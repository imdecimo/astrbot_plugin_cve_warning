from __future__ import annotations

from typing import Any

import aiohttp


class NvdClient:
    """只做一件事：查一个 CVE 的 CVSS。失败就抛异常，不做降级。"""

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

        async with self.session.get(
            self._base_url,
            params=params,
            headers=headers,
            timeout=self.timeout_s,
            proxy=self.proxy_url,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)

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
