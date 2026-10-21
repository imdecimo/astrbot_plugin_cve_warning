from __future__ import annotations

import asyncio
from typing import Any

from astrbot.api import logger

from .log_utils import sanitize

SYSTEM_PROMPT = "你是网络安全情报编辑，把英文漏洞描述改写成简洁中文。"
USER_PROMPT = """下面是 CISA KEV 本轮新增的漏洞，请为每条写一句 40-70 字中文摘要，
说明受影响的组件、漏洞性质、攻击者能做什么。
只输出结果，每条一行，格式严格为：<CVE编号>|<摘要>
不要输出标题、编号、解释或其他任何内容。

{items}
"""


class LlmSummarizer:
    def __init__(self, context: Any, timeout_seconds: int = 60) -> None:
        self.context = context
        self.timeout_seconds = max(5, int(timeout_seconds))
        self.last_outcome = "未调用"

    async def summarize(self, entries: list[dict[str, Any]]) -> dict[str, str]:
        if not entries:
            return {}
        provider = await self._get_provider()
        if provider is None:
            self.last_outcome = "降级"
            return {}

        prompt = self._build_prompt(entries)
        try:
            resp = await asyncio.wait_for(
                provider.text_chat(prompt=prompt, system_prompt=SYSTEM_PROMPT),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            self.last_outcome = "降级"
            logger.warning(
                f"[CVE漏洞推送] AI 摘要超时（{self.timeout_seconds}s），本次使用英文原文"
            )
            return {}
        except Exception as e:
            self.last_outcome = "降级"
            logger.warning(f"[CVE漏洞推送] AI 摘要失败，本次使用英文原文: {sanitize(e)}")
            return {}

        text = getattr(resp, "completion_text", None) or ""
        known_ids = {str(e.get("cveID") or "").strip() for e in entries}
        result = self._parse(text, known_ids)
        self.last_outcome = "成功" if result else "降级"
        return result

    async def _get_provider(self) -> Any | None:
        getter = getattr(self.context, "get_using_provider_async", None)
        if getter is None:
            return None
        try:
            provider = await getter()
        except Exception as e:
            logger.warning(f"[CVE漏洞推送] 获取聊天模型失败: {sanitize(e)}")
            return None
        if provider is None or not hasattr(provider, "text_chat"):
            return None
        return provider

    @staticmethod
    def _build_prompt(entries: list[dict[str, Any]]) -> str:
        chunks: list[str] = []
        for entry in entries:
            cve_id = str(entry.get("cveID") or "").strip()
            vendor = str(entry.get("vendorProject") or "").strip()
            product = str(entry.get("product") or "").strip()
            product_line = " / ".join(part for part in (vendor, product) if part) or "未知"
            desc = str(
                entry.get("shortDescription") or entry.get("vulnerabilityName") or ""
            ).strip()
            chunks.append(f"{cve_id}\n产品: {product_line}\n描述: {desc}")
        return USER_PROMPT.format(items="\n\n".join(chunks))

    @staticmethod
    def _parse(text: str, known_ids: set[str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in text.splitlines():
            if "|" not in line:
                continue
            left, right = line.split("|", 1)
            cve_id = left.strip().strip("`*_- ").strip()
            summary = right.strip()
            if cve_id in known_ids and summary:
                result[cve_id] = summary
        return result
