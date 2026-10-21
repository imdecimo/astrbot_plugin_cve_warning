from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from .log_utils import sanitize


class NvdClient:
    """只做一件事：查一个 CVE 的 CVSS。失败就抛异常，不做降级。

    网络/HTTP/超时失败统一包装为 RuntimeError，消息已过 sanitize() 并带异常类型名，
    调用方可直接落日志。凭据脱敏在这里兜底，不依赖调用点记得脱敏。
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_key: str = "",
        timeout_s: int = 12,
        user_agent: str = "astrbot-cve-warning",
        proxy_url: str = "",
    ) -> None:
        self.session = session
        self.api_key = api_key or ""
        self.timeout_s = int(timeout_s)
        self.user_agent = user_agent
        self.proxy_url = str(proxy_url or "").strip() or None
        self._base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def get_cvss(self, cve_id: str) -> dict[str, Any]:
        params = {"cveId": cve_id, "resultsPerPage": "1"}
        headers: dict[str, str] = {"User-Agent": self.user_agent}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with self.session.get(
                self._base_url,
                params=params,
                headers=headers,
                timeout=self.timeout_s,
                proxy=self.proxy_url,
            ) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError as e:
            raise RuntimeError(
                f"NVD 请求超时（{self.timeout_s}s）: {type(e).__name__} {sanitize(e)}"
            ) from e
        except aiohttp.ClientResponseError as e:
            raise RuntimeError(sanitize(f"NVD HTTP 错误: {e.status} {e.message}")) from e
        except aiohttp.ClientError as e:
            raise RuntimeError(f"NVD 网络错误: {type(e).__name__} {sanitize(e)}") from e

        return self._parse(data)

    @staticmethod
    def _parse(data: Any) -> dict[str, Any]:
        result: dict[str, Any] = {
            "cvss_base_score": None,
            "cvss_base_severity": None,
            "cvss_vector": None,
        }
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(vulns, list) or not vulns:
            return result

        first = vulns[0] if isinstance(vulns[0], dict) else {}
        cve_obj = first.get("cve") if isinstance(first.get("cve"), dict) else {}
        metrics = cve_obj.get("metrics") if isinstance(cve_obj.get("metrics"), dict) else {}

        entry = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            raw = metrics.get(key)
            if isinstance(raw, list) and raw and isinstance(raw[0], dict):
                entry = raw[0]
                break
        if not isinstance(entry, dict):
            return result

        cvss_data = entry.get("cvssData") if isinstance(entry.get("cvssData"), dict) else {}
        score = cvss_data.get("baseScore", entry.get("baseScore"))
        severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
        vector = cvss_data.get("vectorString") or entry.get("vectorString")

        if isinstance(score, (int, float)):
            result["cvss_base_score"] = float(score)
        if isinstance(severity, str) and severity.strip():
            result["cvss_base_severity"] = severity.strip()
        if isinstance(vector, str) and vector.strip():
            result["cvss_vector"] = vector.strip()
        return result
