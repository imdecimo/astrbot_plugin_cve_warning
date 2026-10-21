from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from .log_utils import sanitize


class CisaKevClient:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        feed_url: str,
        timeout_s: int = 30,
        proxy_url: str = "",
    ) -> None:
        self.session = session
        self.feed_url = feed_url
        self.timeout_s = int(timeout_s)
        self.proxy_url = str(proxy_url or "").strip() or None

    async def fetch_catalog(self, etag: str | None = None) -> tuple[dict[str, Any] | None, str | None]:
        """拉取 KEV 目录。

        Returns:
            (catalog, etag)。catalog 为 None 表示服务端返回 304（内容未变）。
        """
        headers = {"User-Agent": "astrbot-cve-warning"}
        if etag:
            headers["If-None-Match"] = etag

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout_s)
            async with self.session.get(
                self.feed_url,
                timeout=timeout,
                headers=headers,
                proxy=self.proxy_url,
            ) as resp:
                if resp.status == 304:
                    return None, etag
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                new_etag = resp.headers.get("ETag") or etag
        except asyncio.TimeoutError as e:
            raise RuntimeError(f"KEV 请求超时（{self.timeout_s}s）: {sanitize(e)}") from e
        except aiohttp.ClientResponseError as e:
            raise RuntimeError(f"KEV HTTP 错误: {e.status} {e.message}") from e
        except aiohttp.ClientError as e:
            raise RuntimeError(f"KEV 网络错误: {type(e).__name__} {sanitize(e)}") from e

        if not isinstance(data, dict):
            raise ValueError("KEV feed 返回的 JSON 不是对象")
        return data, new_etag
