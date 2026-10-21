from __future__ import annotations

from typing import Any

DESCRIPTION_MAX_LEN = 120
SUMMARY_MAX_LEN = 200
INDENT = "\u3000"
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
FALLBACK_EMOJI = "⚪"


def severity_bucket(base_severity: Any, base_score: Any) -> str:
    if isinstance(base_severity, str) and base_severity.strip():
        label = base_severity.strip().upper()
        if label in SEVERITY_EMOJI:
            return label
    if isinstance(base_score, (int, float)):
        score = float(base_score)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
    return "UNKNOWN"


def _truncate(text: str, max_len: int) -> str:
    text = (text or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max(0, max_len - 1)] + "…"


def _severity_label(bucket: str, base_score: Any) -> str:
    if isinstance(base_score, (int, float)):
        return f"{bucket} {float(base_score):.1f}"
    return bucket


def build_cve_block(
    entry: dict[str, Any],
    cvss_info: dict[str, Any] | None,
    summary: str | None,
) -> dict[str, Any]:
    cve_id = str(entry.get("cveID") or "").strip()
    if not cve_id:
        raise ValueError("KEV entry 缺少 cveID")

    info = cvss_info or {}
    bucket = severity_bucket(info.get("cvss_base_severity"), info.get("cvss_base_score"))
    emoji = SEVERITY_EMOJI.get(bucket, FALLBACK_EMOJI)
    lines = [f"{emoji} {cve_id} · {_severity_label(bucket, info.get('cvss_base_score'))}"]

    vendor = str(entry.get("vendorProject") or "").strip()
    product = str(entry.get("product") or "").strip()
    product_line = " / ".join(part for part in (vendor, product) if part)
    if product_line:
        lines.append(f"{INDENT}{product_line}")

    # 摘要也要封顶：模型失控返回长段落时单条消息会超过协议端上限，那条消息此后
    # 每轮都发不出去、块文本又已冻结，3 轮后这批 CVE 对该会话永久丢失。
    description = _truncate(str(summary or ""), SUMMARY_MAX_LEN)
    if not description:
        description = _truncate(
            str(entry.get("shortDescription") or entry.get("vulnerabilityName") or ""),
            DESCRIPTION_MAX_LEN,
        )
    if description:
        lines.append(f"{INDENT}{description}")

    tail: list[str] = []
    due_date = str(entry.get("dueDate") or "").strip()
    if due_date:
        tail.append(f"处置到期 {due_date}")
    ransom = str(entry.get("knownRansomwareCampaignUse") or "").strip()
    if ransom:
        tail.append(f"勒索利用：{'是' if ransom.lower() == 'known' else ransom}")
    if tail:
        lines.append(f"{INDENT}{' · '.join(tail)}")

    lines.append(f"{INDENT}https://nvd.nist.gov/vuln/detail/{cve_id}")
    return {"cve_id": cve_id, "block": "\n".join(lines), "is_new": True}


def build_digest(blocks: list[dict[str, Any]], today: str, part: int, total_parts: int) -> str:
    new_count = sum(1 for block in blocks if block.get("is_new"))
    retry_count = len(blocks) - new_count

    header = f"🛡️ CISA KEV 新增预警 · {today}"
    if total_parts > 1:
        header += f"（{part}/{total_parts}）"

    if new_count and retry_count:
        intro = f"新增 {new_count} 条 + 补发 {retry_count} 条，均为已确认在野利用"
    elif retry_count:
        intro = f"补发 {retry_count} 条，均为已确认在野利用"
    else:
        intro = f"新增 {new_count} 条，均为已确认在野利用"

    body = "\n\n".join(str(block.get("block") or "") for block in blocks)
    footer = f"共 {len(blocks)} 条 · 数据源 CISA KEV"
    return f"{header}\n{intro}\n\n{body}\n\n{footer}"


def chunk_blocks(blocks: list[dict[str, Any]], max_items_per_message: int) -> list[list[dict[str, Any]]]:
    size = max(1, int(max_items_per_message))
    return [blocks[i : i + size] for i in range(0, len(blocks), size)] or [[]]
