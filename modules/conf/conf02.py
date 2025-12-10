import re


def check_conf_02(brain, reporter, verifier=None):
    check_id = "WSTG-CONF-02"

    paths = [
        "/wp-content/debug.log",
        "/wp-content/debug.txt",
        "/wp-content/debug.php",
        "/wp-content/wp-debug.log",
        "/debug.log",
        "/error_log",
        "/errors.log",
        "/php_errors.log",
        "/php-error.log",
        "/server.log",
        "/tmp/debug.log",
        "/tmp/wp-errors.log",
        "/tmp/error_log",
        "/temp/debug.log",
        "/temp/temp.log",
        "/temp/error_log",
        "/wp-content/uploads/debug.log",
        "/wp-content/uploads/error_log",
        "/wp-content/uploads/logs/",
        "/wp-content/uploads/log/",
        "/wp-content/error_log",
        "/wp-content/errors.log",
        "/wp-content/cache/",
        "/wp-content/tmp/",
        "/wp-content/temp/",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/xdebug.php",
        "/xdebug_info",
    ]

    findings = []

    def _is_real_body(text: str) -> bool:
        if text is None:
            return False
        body = text.strip()
        if not body:
            return False
        if len(body) <= 5 and re.fullmatch(r"[+-]?\d+", body):
            return False
        return True

    for path in paths:
        resp = brain.targeted_request(path)
        if not resp:
            continue

        status = resp.status_code
        body = resp.text or ""
        content_len = len(resp.content or b"")

        if status != 200:
            continue

        if not _is_real_body(body):
            continue

        lower_body = body.lower()

        if path.endswith("/"):
            if "index of" in lower_body and any(
                ext in lower_body for ext in (".log", ".txt")
            ):
                findings.append(
                    (
                        "FAIL",
                        f"Directory listing exposes potential log files at {path}",
                        "wp_log_dir_listing",
                    )
                )
                continue

        if path.endswith(".php"):
            if "phpinfo()" in body or "php version" in lower_body:
                findings.append(
                    (
                        "FAIL",
                        f"phpinfo() or environment diagnostic page exposed at {path}.",
                        "php_debug_scripts",
                    )
                )
            elif "xdebug" in lower_body:
                findings.append(
                    (
                        "FAIL",
                        f"Xdebug diagnostic script exposed at {path}.",
                        "php_debug_scripts",
                    )
                )
            else:
                findings.append(
                    (
                        "FAIL",
                        f"Debug/test PHP script accessible at {path}.",
                        "php_debug_scripts",
                    )
                )
            continue

        findings.append(
            (
                "FAIL",
                f"Publicly accessible log file found: {path} (size ~{content_len} bytes).",
                "wp_logs",
            )
        )

    if findings:
        for status, msg, loc in findings:
            reporter.log(check_id, status, msg, location=loc)
    else:
        reporter.log(
            check_id,
            "PASS",
            "No publicly accessible debug/error log files or PHP debug scripts "
            "detected on common paths.",
            location="wp_logs",
        )
