from __future__ import annotations

import asyncio
import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from .log_utils import sanitize

SCHEMA_VERSION = 2
CVSS_CACHE_MAX_ENTRIES = 5000
PENDING_MAX_ITEMS_PER_SESSION = 50
PENDING_MAX_ATTEMPTS = 3


class JsonStateStore:
    """三实体状态：基线 + CVSS 缓存 + 按会话的待补发队列。

    持久化唯一落点由 StarTools.get_data_dir() 决定；取不到时降级为纯内存态，
    绝不写到任何其他位置。
    """

    def __init__(
        self,
        plugin_name: str,
        state_file_name: str = "state.json",
        cvss_cache_ttl_days: int = 30,
    ) -> None:
        self.cvss_cache_ttl_days = max(1, int(cvss_cache_ttl_days))
        self._lock = asyncio.Lock()
        self._persistent = True
        self.storage_dir = ""
        self.state_file_path = ""

        try:
            self.storage_dir = str(StarTools.get_data_dir(plugin_name))
            self.state_file_path = os.path.join(self.storage_dir, state_file_name)
        except Exception as e:
            self._persistent = False
            logger.warning(
                f"[CVE漏洞推送] 状态目录不可用，本次运行不落盘（不会写到任何其他位置）: {sanitize(e)}"
            )

        self.catalog_version: str | None = None
        self.etag: str | None = None
        self.baseline_cves: dict[str, str] = {}
        self.cvss_cache: dict[str, dict[str, Any]] = {}
        self.pending_by_session: dict[str, dict[str, Any]] = {}
        self.last_fetch_at_iso: str | None = None
        self.last_push_at_iso: str | None = None

    @property
    def persistent(self) -> bool:
        return self._persistent

    # ------------------------------------------------------------------ 载入

    async def load(self) -> None:
        async with self._lock:
            if not self._persistent:
                return
            try:
                os.makedirs(self.storage_dir, exist_ok=True)
                if not os.path.exists(self.state_file_path):
                    return
                data = await asyncio.to_thread(self._read_json_file)
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 状态加载失败，将使用空状态: {sanitize(e)}")
                return

            if not isinstance(data, dict):
                return

            if data.get("schema_version") != SCHEMA_VERSION:
                self._migrate_from_v1(data)
                try:
                    await asyncio.to_thread(self._backup_v1_file)
                except Exception as e:
                    logger.warning(f"[CVE漏洞推送] v1 状态备份失败: {sanitize(e)}")
                try:
                    await asyncio.to_thread(self._write_json_atomic, self._snapshot())
                    logger.info(
                        f"[CVE漏洞推送] 状态已迁移到 v2：基线 {len(self.baseline_cves)} 条，"
                        f"负缓存条目已清理"
                    )
                except Exception as e:
                    logger.error(f"[CVE漏洞推送] 迁移后写入失败: {sanitize(e)}")
                return

            self._load_v2(data)
            self._prune_cvss_cache()

    def _read_json_file(self) -> Any:
        with open(self.state_file_path, encoding="utf-8") as f:
            return json.load(f)

    def _backup_v1_file(self) -> None:
        if not os.path.exists(self.state_file_path):
            return
        backup_path = os.path.join(self.storage_dir, "state.v1.json.bak")
        shutil.copy2(self.state_file_path, backup_path)

    def _migrate_from_v1(self, data: dict[str, Any]) -> None:
        self.baseline_cves = {}
        pushed = data.get("pushed_at_by_cve")
        if isinstance(pushed, dict):
            for cve_id in pushed:
                if isinstance(cve_id, str) and cve_id.strip():
                    self.baseline_cves[cve_id.strip()] = ""

        self.cvss_cache = {}
        cache = data.get("cvss_cache")
        if isinstance(cache, dict):
            for cve_id, entry in cache.items():
                if not isinstance(cve_id, str) or not isinstance(entry, dict):
                    continue
                payload = entry.get("data") if isinstance(entry.get("data"), dict) else entry
                if not self._cvss_payload_usable(payload):
                    continue
                stored_at = entry.get("stored_at_iso")
                self.cvss_cache[cve_id] = {
                    "stored_at_iso": stored_at
                    if isinstance(stored_at, str) and stored_at
                    else datetime.now(timezone.utc).isoformat(),
                    "data": payload,
                }

        self.pending_by_session = {}
        self.etag = None
        version = data.get("last_catalog_version")
        self.catalog_version = version if isinstance(version, str) and version else None

        last_fetch = data.get("last_fetch_at_iso")
        self.last_fetch_at_iso = last_fetch if isinstance(last_fetch, str) and last_fetch else None
        last_push = data.get("last_push_at_iso")
        self.last_push_at_iso = last_push if isinstance(last_push, str) and last_push else None

    def _load_v2(self, data: dict[str, Any]) -> None:
        version = data.get("catalog_version")
        self.catalog_version = version if isinstance(version, str) and version else None
        etag = data.get("etag")
        self.etag = etag if isinstance(etag, str) and etag else None

        self.baseline_cves = {}
        baseline = data.get("baseline_cves")
        if isinstance(baseline, dict):
            for key, value in baseline.items():
                if isinstance(key, str) and key.strip():
                    self.baseline_cves[key.strip()] = value if isinstance(value, str) else ""

        self.cvss_cache = {}
        cache = data.get("cvss_cache")
        if isinstance(cache, dict):
            for cve_id, entry in cache.items():
                if not isinstance(cve_id, str) or not isinstance(entry, dict):
                    continue
                payload = entry.get("data")
                if not self._cvss_payload_usable(payload):
                    continue
                stored_at = entry.get("stored_at_iso")
                self.cvss_cache[cve_id] = {
                    "stored_at_iso": stored_at if isinstance(stored_at, str) else "",
                    "data": payload,
                }

        self.pending_by_session = {}
        pending = data.get("pending_by_session")
        if isinstance(pending, dict):
            for session, entry in pending.items():
                if not isinstance(session, str) or not isinstance(entry, dict):
                    continue
                deduped: dict[str, dict[str, str]] = {}
                raw_items = entry.get("items")
                if isinstance(raw_items, list):
                    for item in raw_items:
                        if not isinstance(item, dict):
                            continue
                        cve_id = item.get("cve_id")
                        block = item.get("block")
                        if (
                            isinstance(cve_id, str)
                            and cve_id.strip()
                            and isinstance(block, str)
                            and block.strip()
                        ):
                            key = cve_id.strip()
                            deduped[key] = {"cve_id": key, "block": block}
                if not deduped:
                    continue
                attempts = entry.get("attempts")
                self.pending_by_session[session] = {
                    "attempts": attempts if isinstance(attempts, int) and attempts > 0 else 1,
                    "items": list(deduped.values())[-PENDING_MAX_ITEMS_PER_SESSION:],
                }

        last_fetch = data.get("last_fetch_at_iso")
        self.last_fetch_at_iso = last_fetch if isinstance(last_fetch, str) else None
        last_push = data.get("last_push_at_iso")
        self.last_push_at_iso = last_push if isinstance(last_push, str) else None

    # ------------------------------------------------------------------ 保存

    async def save(self) -> None:
        async with self._lock:
            await self._write_snapshot()

    async def _write_snapshot(self) -> None:
        if not self._persistent:
            return
        try:
            await asyncio.to_thread(self._write_json_atomic, self._snapshot())
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 状态保存失败: {sanitize(e)}")

    def _snapshot(self) -> dict[str, Any]:
        """产出一份与内部状态容器互不共享的快照。

        逐层手工浅拷贝（不用 copy.deepcopy，状态可能上万条）：json.dump 在 worker
        线程里只迭代快照自己的容器，所以保存期间其它协程改动活字典不会让 dump 抛出
        "dictionary changed size during iteration"。
        """
        cvss_cache: dict[str, dict[str, Any]] = {}
        for cve_id, entry in self.cvss_cache.items():
            if not isinstance(entry, dict):
                continue
            payload = entry.get("data")
            cvss_cache[cve_id] = {
                "stored_at_iso": entry.get("stored_at_iso"),
                "data": dict(payload) if isinstance(payload, dict) else payload,
            }

        pending_by_session: dict[str, dict[str, Any]] = {}
        for session, entry in self.pending_by_session.items():
            if not isinstance(entry, dict):
                continue
            raw_items = entry.get("items")
            items = (
                [dict(item) for item in raw_items if isinstance(item, dict)]
                if isinstance(raw_items, list)
                else []
            )
            pending_by_session[session] = {
                "attempts": entry.get("attempts"),
                "items": items,
            }

        return {
            "schema_version": SCHEMA_VERSION,
            "catalog_version": self.catalog_version,
            "etag": self.etag,
            "baseline_cves": dict(self.baseline_cves),
            "cvss_cache": cvss_cache,
            "pending_by_session": pending_by_session,
            "last_fetch_at_iso": self.last_fetch_at_iso,
            "last_push_at_iso": self.last_push_at_iso,
        }

    def _write_json_atomic(self, payload: dict[str, Any]) -> None:
        os.makedirs(self.storage_dir, exist_ok=True)
        tmp_path = self.state_file_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp_path, self.state_file_path)

    # ------------------------------------------------------------------ 基线

    def select_new_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for entry in entries:
            cve_id = str(entry.get("cveID") or "").strip()
            if cve_id and cve_id not in self.baseline_cves:
                result.append(entry)
        return result

    def merge_into_baseline(self, entries: list[dict[str, Any]]) -> None:
        for entry in entries:
            cve_id = str(entry.get("cveID") or "").strip()
            if not cve_id:
                continue
            date_added = entry.get("dateAdded")
            self.baseline_cves[cve_id] = date_added.strip() if isinstance(date_added, str) else ""

    def replace_baseline(self, entries: list[dict[str, Any]]) -> None:
        self.baseline_cves = {}
        self.merge_into_baseline(entries)

    # ------------------------------------------------------------- CVSS 缓存

    def get_cvss(self, cve_id: str) -> dict[str, Any] | None:
        entry = self.cvss_cache.get(cve_id)
        if not isinstance(entry, dict):
            return None
        stored_at = entry.get("stored_at_iso")
        if not isinstance(stored_at, str) or not stored_at:
            self.cvss_cache.pop(cve_id, None)
            return None
        try:
            stored_dt = datetime.fromisoformat(stored_at)
        except ValueError:
            self.cvss_cache.pop(cve_id, None)
            return None
        if stored_dt.tzinfo is None:
            stored_dt = stored_dt.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - stored_dt).days >= self.cvss_cache_ttl_days:
            self.cvss_cache.pop(cve_id, None)
            return None
        payload = entry.get("data")
        return payload if isinstance(payload, dict) else None

    def set_cvss(self, cve_id: str, data: dict[str, Any]) -> None:
        """只缓存成功的结果。查询失败不得调用本方法。"""
        if not self._cvss_payload_usable(data):
            return
        self.cvss_cache[cve_id] = {
            "stored_at_iso": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        self._prune_cvss_cache()

    @staticmethod
    def _cvss_payload_usable(payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        score = payload.get("cvss_base_score")
        severity = payload.get("cvss_base_severity")
        return isinstance(score, (int, float)) or (isinstance(severity, str) and bool(severity.strip()))

    def _prune_cvss_cache(self) -> None:
        overflow = len(self.cvss_cache) - CVSS_CACHE_MAX_ENTRIES
        if overflow <= 0:
            return
        ordered = sorted(
            self.cvss_cache.items(), key=lambda kv: kv[1].get("stored_at_iso") or ""
        )
        for cve_id, _ in ordered[:overflow]:
            self.cvss_cache.pop(cve_id, None)

    # ------------------------------------------------------------ 待补发队列

    def get_pending_blocks(self, session: str) -> list[dict[str, str]]:
        entry = self.pending_by_session.get(session)
        if not isinstance(entry, dict):
            return []
        items = entry.get("items")
        if not isinstance(items, list):
            return []
        return [item for item in items if isinstance(item, dict)]

    def get_pending_attempts(self, session: str) -> int:
        entry = self.pending_by_session.get(session)
        if not isinstance(entry, dict):
            return 0
        attempts = entry.get("attempts")
        return attempts if isinstance(attempts, int) and attempts > 0 else 0

    def record_session_failure(self, session: str, blocks: list[dict[str, str]]) -> bool:
        """记录一次适配器报错。返回 False 表示已达上限并放弃补发。"""
        attempts = self.get_pending_attempts(session) + 1
        if attempts >= PENDING_MAX_ATTEMPTS:
            self.pending_by_session.pop(session, None)
            return False

        merged: dict[str, dict[str, str]] = {}
        for item in self.get_pending_blocks(session) + list(blocks):
            cve_id = item.get("cve_id")
            block = item.get("block")
            if isinstance(cve_id, str) and isinstance(block, str):
                merged[cve_id] = {"cve_id": cve_id, "block": block}
        self.pending_by_session[session] = {
            "attempts": attempts,
            "items": list(merged.values())[-PENDING_MAX_ITEMS_PER_SESSION:],
        }
        return True

    def clear_pending(self, session: str) -> None:
        self.pending_by_session.pop(session, None)

    # ------------------------------------------------------------------ 时间戳

    def touch_fetch(self) -> None:
        self.last_fetch_at_iso = datetime.now(timezone.utc).isoformat()

    def touch_push(self) -> None:
        self.last_push_at_iso = datetime.now(timezone.utc).isoformat()
