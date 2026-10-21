from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp
import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import MessageChain

from .cisa_kev_client import CisaKevClient
from .llm_summarizer import LlmSummarizer
from .log_utils import sanitize
from .message_formatter import build_cve_block, build_digest, chunk_blocks
from .nvd_client import NvdClient
from .state_store import PENDING_MAX_ATTEMPTS, JsonStateStore

KEV_FETCH_RETRY_COUNT = 3
KEV_FETCH_RETRY_INTERVAL_SECONDS = 10
NVD_CONCURRENCY = 2
DEFAULT_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@dataclass
class RefreshResult:
    ok: bool = True
    error: str | None = None
    status: str = "unchanged"
    new_count: int = 0
    failed_sessions: int = 0
    abandoned: int = 0
    catalog_version: str | None = None


class CVEWarningService:
    """KEV 增量预警：diff 基线 → 补 CVSS → 摘要 → 合并单条消息 → 按会话补发。"""

    def __init__(self, config: dict[str, Any], context: Any) -> None:
        self.config = config
        self.context = context
        self.plugin_name = "astrbot_plugin_cve_warning"

        self.kev_feed_url = str(config.get("kev_feed_url") or DEFAULT_KEV_FEED_URL).strip()
        self.interval_hours = int(config.get("push_interval_hours", 6) or 6)
        self.interval_seconds = max(60, self.interval_hours * 3600)
        self.max_items_per_message = int(config.get("max_items_per_message", 15) or 15)
        self.http_proxy = str(config.get("http_proxy") or "").strip()
        self.nvd_api_key = str(config.get("nvd_api_key") or "")
        self.enable_ai_summary = bool(config.get("enable_ai_summary", True))
        self.summary_timeout_seconds = int(config.get("summary_timeout_seconds", 60) or 60)
        self.cvss_cache_ttl_days = int(config.get("cvss_cache_ttl_days", 30) or 30)

        self.target_sessions = self._normalize_sessions(config.get("target_sessions", []))
        self.failure_notify_sessions = self._normalize_sessions(
            config.get("failure_notify_sessions", [])
        )

        self._state = JsonStateStore(
            plugin_name=self.plugin_name,
            state_file_name="state.json",
            cvss_cache_ttl_days=self.cvss_cache_ttl_days,
        )
        self._summarizer = LlmSummarizer(context, timeout_seconds=self.summary_timeout_seconds)

        self._session: aiohttp.ClientSession | None = None
        self._kev_client: CisaKevClient | None = None
        self._nvd_client: NvdClient | None = None

        self._running = False
        self._loop_task: asyncio.Task[None] | None = None
        self._refresh_lock = asyncio.Lock()
        self._next_run_at: datetime | None = None
        self.abandoned_total = 0

    # ------------------------------------------------------------- 生命周期

    async def start(self) -> None:
        if not self.kev_feed_url:
            logger.error("[CVE漏洞推送] 未配置 kev_feed_url，服务不启动")
            return
        if not self.target_sessions:
            logger.warning("[CVE漏洞推送] 未配置 target_sessions，将只更新基线不推送")

        self._session = aiohttp.ClientSession()
        self._kev_client = CisaKevClient(
            self._session,
            feed_url=self.kev_feed_url,
            timeout_s=30,
            proxy_url=self.http_proxy,
        )
        self._nvd_client = NvdClient(
            self._session,
            api_key=self.nvd_api_key,
            timeout_s=12,
            proxy_url=self.http_proxy,
        )

        await self._state.load()

        self._running = True
        try:
            await self.refresh_and_push(reason="startup")
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 启动时首次刷新失败（将进入定时重试）: {sanitize(e)}")

        self._loop_task = asyncio.create_task(self._run_loop(), name="cve_warning_loop")
        await self._loop_task

    async def _run_loop(self) -> None:
        while self._running:
            self._next_run_at = datetime.now(timezone.utc) + timedelta(
                seconds=self.interval_seconds
            )
            await asyncio.sleep(self.interval_seconds)
            try:
                await self.refresh_and_push(reason="scheduled")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 定时刷新失败: {sanitize(e)}")

    async def stop(self) -> None:
        self._running = False
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass

    # ----------------------------------------------------------------- 状态

    def get_status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "persistent": self._state.persistent,
            "catalog_version": self._state.catalog_version,
            "baseline_count": len(self._state.baseline_cves),
            "pending": {
                session: self._state.get_pending_attempts(session)
                for session in self._state.pending_by_session
            },
            "abandoned_total": self.abandoned_total,
            "last_fetch_at_iso": self._state.last_fetch_at_iso,
            "last_push_at_iso": self._state.last_push_at_iso,
            "next_run_at": self._next_run_at.isoformat() if self._next_run_at else None,
            "ai_summary_enabled": self.enable_ai_summary,
            "ai_last_outcome": self._summarizer.last_outcome,
        }

    # ------------------------------------------------------------- 主流程

    async def refresh_and_push(self, reason: str) -> RefreshResult:
        if not self._kev_client or not self._nvd_client:
            return RefreshResult(ok=False, error="service_not_ready")

        async with self._refresh_lock:
            result = RefreshResult()
            try:
                return await self._refresh_locked(result)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                result.ok = False
                result.error = f"{type(e).__name__}: {sanitize(e)}"
                logger.error(f"[CVE漏洞推送] 刷新失败: {sanitize(e)}")
                if reason in {"startup", "manual"}:
                    await self._notify_failure(result.error)
                    raise
                return result

    async def _refresh_locked(self, result: RefreshResult) -> RefreshResult:
        catalog, etag = await self._fetch_with_retry()
        self._state.touch_fetch()

        if catalog is None:
            logger.info("[CVE漏洞推送] KEV 目录未修改（304），本轮无操作")
            await self._state.save()
            return result

        version_raw = catalog.get("catalogVersion")
        version = version_raw if isinstance(version_raw, str) and version_raw.strip() else None
        result.catalog_version = version

        if version and version == self._state.catalog_version:
            self._state.etag = etag or self._state.etag
            await self._state.save()
            logger.info(f"[CVE漏洞推送] catalogVersion 未变（{version}），本轮无操作")
            return result

        entries = [e for e in (catalog.get("vulnerabilities") or []) if isinstance(e, dict)]

        if not self._state.baseline_cves:
            self._state.replace_baseline(entries)
            self._finish_cycle(version, etag)
            await self._state.save()
            result.status = "seeded"
            logger.info(
                f"[CVE漏洞推送] 已建立基线，共 {len(self._state.baseline_cves)} 条，"
                f"本轮不推送。此后只推送新增。"
            )
            return result

        if not self.target_sessions:
            self._state.merge_into_baseline(entries)
            self._finish_cycle(version, etag)
            await self._state.save()
            result.status = "no_targets"
            logger.warning("[CVE漏洞推送] 未配置推送会话，仅更新基线")
            return result

        new_entries = self._state.select_new_entries(entries)
        if not new_entries and not self._state.pending_by_session:
            self._finish_cycle(version, etag)
            await self._state.save()
            return result

        result.new_count = len(new_entries)

        new_blocks: list[dict[str, Any]] = []
        if new_entries:
            await self._enrich_cvss(new_entries)
            summaries: dict[str, str] = {}
            if self.enable_ai_summary:
                summaries = await self._summarizer.summarize(new_entries)
            for entry in self._sort_new_entries(new_entries):
                cve_id = str(entry.get("cveID") or "").strip()
                new_blocks.append(
                    build_cve_block(
                        entry,
                        self._state.get_cvss(cve_id),
                        summaries.get(cve_id),
                    )
                )

        sent_any = False
        for session in self.target_sessions:
            blocks = self._merge_blocks(self._state.get_pending_blocks(session), new_blocks)
            if not blocks:
                self._state.clear_pending(session)
                continue
            if await self._send_session(session, blocks):
                self._state.clear_pending(session)
                sent_any = True
                continue

            result.failed_sessions += 1
            if self._state.record_session_failure(session, blocks):
                logger.warning(
                    f"[CVE漏洞推送] 适配器报错 session={session}，已记入待补发队列"
                    f"（attempts={self._state.get_pending_attempts(session)}）"
                )
            else:
                self.abandoned_total += 1
                result.abandoned += 1
                logger.error(
                    f"[CVE漏洞推送] session={session} 连续 {PENDING_MAX_ATTEMPTS} 次适配器报错，"
                    f"放弃补发"
                )

        if sent_any:
            self._state.touch_push()
        if new_entries:
            self._state.merge_into_baseline(new_entries)
        self._finish_cycle(version, etag)
        await self._state.save()
        result.status = "pushed"
        return result

    # --------------------------------------------------------------- 发送

    @staticmethod
    def _merge_blocks(
        pending: list[dict[str, Any]], new_blocks: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """按 cve_id 去重合并：待补发的旧块 + 本轮的新块，同一条以新块覆盖。"""
        merged: dict[str, dict[str, Any]] = {}
        for block in pending:
            cve_id = str(block.get("cve_id") or "").strip()
            if cve_id:
                merged[cve_id] = {"cve_id": cve_id, "block": str(block.get("block") or "")}
        for block in new_blocks:
            cve_id = str(block.get("cve_id") or "").strip()
            if cve_id:
                merged[cve_id] = block
        return list(merged.values())

    async def _send_session(self, session: str, blocks: list[dict[str, Any]]) -> bool:
        if not blocks:
            return True
        today = datetime.now().strftime("%Y-%m-%d")
        chunks = chunk_blocks(blocks, self.max_items_per_message)
        for index, chunk in enumerate(chunks, start=1):
            text = build_digest(chunk, today, index, len(chunks))
            try:
                chain = MessageChain([Comp.Plain(text)])
                if not await self.context.send_message(session, chain):
                    logger.warning(
                        f"[CVE漏洞推送] session={session} 找不到平台实例，消息未发出"
                    )
                    return False
            except Exception as e:
                logger.warning(f"[CVE漏洞推送] 适配器报错 session={session}: {sanitize(e)}")
                return False
        return True

    async def _notify_failure(self, message: str) -> None:
        if not self.failure_notify_sessions:
            return
        text = f"❌ [CVE漏洞推送] 刷新失败：{message}"
        for session in self.failure_notify_sessions:
            try:
                await self.context.send_message(session, MessageChain([Comp.Plain(text)]))
            except Exception as e:
                logger.warning(f"[CVE漏洞推送] 失败通知未送达 session={session}: {sanitize(e)}")

    # --------------------------------------------------------- 内部工具

    async def _fetch_with_retry(self) -> tuple[dict[str, Any] | None, str | None]:
        last_error: Exception | None = None
        for attempt in range(1, KEV_FETCH_RETRY_COUNT + 1):
            try:
                return await self._kev_client.fetch_catalog(etag=self._state.etag)
            except Exception as e:
                last_error = e
                logger.warning(
                    f"[CVE漏洞推送] KEV 拉取失败（第 {attempt}/{KEV_FETCH_RETRY_COUNT} 次）: "
                    f"{sanitize(e)}"
                )
                if attempt < KEV_FETCH_RETRY_COUNT:
                    await asyncio.sleep(KEV_FETCH_RETRY_INTERVAL_SECONDS)
        raise RuntimeError(
            f"KEV 拉取失败: {type(last_error).__name__}: {sanitize(last_error)}"
        )

    async def _enrich_cvss(self, entries: list[dict[str, Any]]) -> None:
        missing: list[str] = []
        for entry in entries:
            cve_id = str(entry.get("cveID") or "").strip()
            if cve_id and self._state.get_cvss(cve_id) is None:
                missing.append(cve_id)
        if not missing:
            return

        semaphore = asyncio.Semaphore(NVD_CONCURRENCY)

        async def worker(cve_id: str) -> None:
            async with semaphore:
                try:
                    data = await self._nvd_client.get_cvss(cve_id)
                except Exception as e:
                    logger.warning(
                        f"[CVE漏洞推送] NVD 查询失败 {cve_id}（不缓存，下轮重试）: {sanitize(e)}"
                    )
                    return
                self._state.set_cvss(cve_id, data)

        await asyncio.gather(*(worker(cve_id) for cve_id in missing))

    def _sort_new_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scored: list[tuple[float, dict[str, Any]]] = []
        unscored: list[dict[str, Any]] = []
        for entry in entries:
            cve_id = str(entry.get("cveID") or "").strip()
            info = self._state.get_cvss(cve_id) or {}
            score = info.get("cvss_base_score")
            if isinstance(score, (int, float)):
                scored.append((float(score), entry))
            else:
                unscored.append(entry)
        scored.sort(key=lambda item: item[0], reverse=True)
        unscored.sort(key=lambda entry: str(entry.get("dateAdded") or ""), reverse=True)
        return [entry for _, entry in scored] + unscored

    def _finish_cycle(self, version: str | None, etag: str | None) -> None:
        if version:
            self._state.catalog_version = version
        if etag:
            self._state.etag = etag

    @staticmethod
    def _normalize_sessions(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
