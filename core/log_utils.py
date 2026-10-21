from __future__ import annotations

import re

_URL_USERINFO_RE = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<userinfo>[^/?#\s]+)@"
)


def sanitize(value: object) -> str:
    """把 URL 里的 userinfo（user:pass@）替换为 ***，避免代理凭据进日志。"""
    text = str(value)
    return _URL_USERINFO_RE.sub(lambda m: f"{m.group('scheme')}***@", text)
