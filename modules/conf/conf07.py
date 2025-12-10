import re
from urllib.parse import urlparse


def check_conf_07(brain, reporter, verifier=None):
    check_id = "WSTG-CONF-07"
    parsed = urlparse(brain.target)
    scheme = (parsed.scheme or "").lower()

    curl_cmd = f"curl -s -D- -I -L '{brain.target}' | grep -i strict-transport-security"

    if scheme != "https":
        reporter.log(
            check_id,
            "FAIL",
            f"Target URL is not HTTPS (scheme={scheme}); HSTS header cannot be applied. "
            f"Use an HTTPS URL to configure and test HSTS. Manual check: {curl_cmd}",
            location="hsts",
        )
        return

    if brain.main_response is None:
        reporter.log(
            check_id,
            "FAIL",
            "No main HTTPS response cached; cannot review Strict-Transport-Security header. "
            f"Manual check: {curl_cmd}",
            location="hsts",
        )
        return

    hsts = None
    for k, v in brain.main_response.headers.items():
        if k.lower() == "strict-transport-security":
            hsts = v
            break

    if not hsts:
        reporter.log(
            check_id,
            "FAIL",
            "HTTPS response does not include a Strict-Transport-Security header. "
            "Browsers will not enforce HSTS for this domain. "
            f"Manual check: {curl_cmd}",
            location="hsts",
        )
        return

    header_str = hsts.strip()
    lower = header_str.lower()

    m = re.search(r"max-age\s*=\s*(\d+)", lower)
    maxage = None
    if m:
        try:
            maxage = int(m.group(1))
        except ValueError:
            maxage = None

    includesubdomains = "includesubdomains" in lower
    preload = "preload" in lower

    min_reasonable_maxage = 86400

    if maxage is None:
        reporter.log(
            check_id,
            "FAIL",
            "Strict-Transport-Security header present but missing or malformed "
            f"max-age directive: {header_str}. Manual check: {curl_cmd}",
            location="hsts",
        )
        return

    if maxage < min_reasonable_maxage:
        reporter.log(
            check_id,
            "FAIL",
            "HSTS header present but max-age is very low "
            f"({maxage} seconds): {header_str}. Manual check: {curl_cmd}",
            location="hsts",
        )
        return

    notes = []
    notes.append(f"max-age={maxage}")
    notes.append("includeSubDomains" if includesubdomains else "no includeSubDomains")
    notes.append("preload" if preload else "no preload")

    reporter.log(
        check_id,
        "PASS",
        "Valid Strict-Transport-Security header detected on HTTPS response: "
        f"{header_str}; directives: {', '.join(notes)}. Manual check: {curl_cmd}",
        location="hsts",
    )
