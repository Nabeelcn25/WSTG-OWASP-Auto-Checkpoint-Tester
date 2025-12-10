import re
from collections import defaultdict


ERROR_STATUS_CODES = {400, 401, 403, 404, 405, 413, 415, 422, 429, 500, 501, 502, 503, 504}

ERROR_KEYWORDS = [
    "exception",
    "stack trace",
    "traceback",
    "fatal error",
    "warning:",
    "notice:",
    "at line",
    "undefined index",
    "undefined variable",
    "sqlstate",
    "sql syntax",
    "ora-",
    "odbc",
    "jdbc",
    "nullreferenceexception",
    "server error in '/' application",
    "php notice",
    "php warning",
    "php fatal error",
]


def _looks_like_verbose_error(body: str) -> bool:
    if not body:
        return False
    lower = body.lower()
    for kw in ERROR_KEYWORDS:
        if kw in lower:
            return True
    return False


def _normalize_error_body(body: str, max_len: int = 500) -> str:
    if not body:
        return ""
    cleaned = re.sub(r"\s+", " ", body).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    return cleaned


def _make_error_signature(status: int, body: str) -> str:
    snippet = _normalize_error_body(body, max_len=200)
    snippet = re.sub(r"\d+", "N", snippet)
    return f"{status}:{snippet}"


def check_errh_01(brain, reporter, verifier=None):
    check_id = "WSTG-ERRH-01"

    interactions = getattr(brain, "http_cache", []) or []

    if not interactions:
        reporter.log(
            check_id,
            "PASS",
            "No cached HTTP interactions were available to assess error handling.",
            location="Cache",
        )
        return

    findings_by_sig = {}
    counts_by_sig = defaultdict(int)

    for item in interactions:
        method = getattr(item, "method", None) or item.get("method")
        url = getattr(item, "url", None) or item.get("url")
        status = getattr(item, "status", None) or item.get("status")
        body = getattr(item, "body", None) or item.get("body")

        if not method or not url or status is None:
            continue

        if int(status) not in ERROR_STATUS_CODES:
            continue

        body_text = body or ""
        if not _looks_like_verbose_error(body_text):
            continue

        sig = _make_error_signature(int(status), body_text)
        counts_by_sig[sig] += 1

        if sig not in findings_by_sig:
            snippet = _normalize_error_body(body_text, max_len=300)
            findings_by_sig[sig] = {
                "method": method,
                "url": url,
                "status": int(status),
                "snippet": snippet,
            }

    if not findings_by_sig:
        reporter.log(
            check_id,
            "PASS",
            "Cached error responses did not expose verbose stack traces or detailed internal errors.",
            location="Application",
        )
        return

    sorted_sigs = sorted(counts_by_sig.items(), key=lambda x: x[1], reverse=True)

    max_findings = 2
    emitted = 0

    for sig, count in sorted_sigs:
        meta = findings_by_sig[sig]
        method = meta["method"]
        url = meta["url"]
        status = meta["status"]
        snippet = meta["snippet"]

        message = (
            f"Verbose error detected at {method} {url} (status {status}), "
            f"seen {count} time(s) in cached traffic. "
            "The response body appears to contain detailed error or stack trace information. "
            f"Example snippet (truncated): \"{snippet}\""
        )

        reporter.log(
            check_id,
            "FAIL",
            message,
            location=f"{method} {url}",
        )

        emitted += 1
        if emitted >= max_findings:
            break

    if emitted < len(findings_by_sig):
        reporter.log(
            check_id,
            "INFO",
            f"Additional verbose error patterns were detected but only the first {max_findings} "
            "unique examples are listed here to reduce noise.",
            location="Application",
        )
