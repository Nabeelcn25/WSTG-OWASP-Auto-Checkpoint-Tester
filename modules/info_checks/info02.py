import re


def check_info_02(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-02"
    server_signatures = set()

    headers = brain.main_response.headers

    if "Server" in headers:
        server_signatures.add(headers["Server"].strip())
    if "X-Powered-By" in headers:
        server_signatures.add(headers["X-Powered-By"].strip())

    if getattr(brain, "whatweb_data", None):
        try:
            last_scan = brain.whatweb_data[-1]
            plugins = last_scan.get("plugins", {})
            if "HTTPServer" in plugins:
                strings = plugins["HTTPServer"].get("string", [])
                os_info = plugins["HTTPServer"].get("os", [])
                for s in strings:
                    server_signatures.add(s.strip())
                for o in os_info:
                    server_signatures.add(f"OS: {o.strip()}")
        except Exception:
            pass

    leaked_versions = []
    for sig in server_signatures:
        if re.search(r"\d", sig):
            leaked_versions.append(sig)

    if leaked_versions:
        proof = ", ".join(sorted(list(set(leaked_versions))))
        reporter.log(
            check_id,
            "FAIL",
            f"Server Version Disclosed: {proof}",
            location="Headers/WhatWeb",
        )
    elif server_signatures:
        proof = ", ".join(sorted(list(server_signatures)))
        reporter.log(
            check_id,
            "PASS",
            f"Server identified (Generic): {proof}",
            location="Headers/WhatWeb",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "Server banner is completely hidden.",
            location="Headers/WhatWeb",
        )
