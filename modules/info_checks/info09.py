# modules/info_checks/info09.py

import re


def _is_real_body(text: str | None) -> bool:
    if text is None:
        return False
    body = text.strip()
    if not body:
        return False
    if len(body) < 10 and re.fullmatch(r"[+-]?\d+", body):
        return False
    lower = body.lower()
    if any(k in lower for k in ["not found", "404", "error", "forbidden", "access denied"]):
        return False
    return True


def check_info_09(brain, reporter, verifier=None):
    """
    WSTG-INFO-09 (custom): Check for exposed installers.
    FAIL if /install.php or /wp-admin/install.php are present and return a real 200 page.
    """
    check_id = "WSTG-INFO-09"

    paths = ["/install.php", "/wp-admin/install.php"]
    issues = []

    for p in paths:
        resp = brain.targeted_request(p)
        if not resp or resp.status_code != 200:
            continue
        body = getattr(resp, "text", "")
        if not _is_real_body(body):
            continue
        length = len((body or "").strip())
        snippet = (body or "").strip()[:200]
        issues.append((p, length, snippet))

    if not issues:
        reporter.log(
            check_id,
            "PASS",
            "install.php and wp-admin/install.php are not accessible with a real 200 OK page.",
            location="installers",
        )
        return

    for path, length, snippet in issues:
        msg = (
            f"{path} is accessible (HTTP 200, length {length}). This may allow "
            f"reinstallation or exposure of installer logic. First 200 chars: {snippet}"
        )
        reporter.log(
            check_id,
            "FAIL",
            msg,
            location=path,
        )
