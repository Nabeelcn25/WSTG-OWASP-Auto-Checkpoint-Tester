import re
from urllib.parse import urlparse


def _auth_discovery(brain):
    art = brain.artifacts.setdefault("athn", {})
    if art.get("done"):
        return art

    parsed = urlparse(brain.target)
    origin_https = f"https://{parsed.netloc}"

    def get(path: str):
        return brain.targeted_request(path)

    login_present = False

    resp = get("/wp-login.php")
    if resp and resp.status_code == 200:
        body = (resp.text or "")[:20000]
        if (
            'id="loginform"' in body
            or 'name="log"' in body
            or 'name="user_login"' in body
            or re.search(r']+type=["\']password["\']', body, re.IGNORECASE)
        ):
            login_present = True

    admin_public_paths = []

    admin_paths = [
        "/wp-admin/",
        "/wp-admin/edit.php",
        "/wp-admin/edit.php?post_type=page",
        "/wp-admin/post-new.php",
        "/wp-admin/profile.php",
    ]

    for path in admin_paths:
        resp = get(path)
        if not resp or resp.status_code != 200:
            continue
        body = (resp.text or "")[:20000].lower()
        if ('class="wp-admin' in body or 'id="adminmenu"' in body) and 'id="loginform"' not in body:
            admin_public_paths.append(path.split("?", 1)[0])

    art.update(
        dict(
            origin_https=origin_https,
            login_present=login_present,
            admin_public_paths=sorted(set(admin_public_paths)),
            done=True,
        )
    )
    return art


def check_athn_01(brain, reporter, verifier=None):
    check_id = "WSTG-ATHN-01"

    parsed = urlparse(brain.target)
    host = parsed.netloc or parsed.path
    path = parsed.path if parsed.path else "/"
    http_url = f"http://{host}{path}"

    try:
        resp = brain.targeted_request(http_url)
        if not resp:
            raise RuntimeError("no HTTP response")
    except Exception:
        reporter.log(
            check_id,
            "FAIL",
            f"Could not obtain an HTTP response for {http_url}; "
            f"unable to verify HTTP→HTTPS redirection.",
            location="http_https_redirect",
        )
        return

    final_url = str(resp.url).lower()
    if final_url.startswith("https://"):
        reporter.log(
            check_id,
            "PASS",
            f"HTTP access to {http_url} is redirected to HTTPS ({final_url}), "
            f"so credentials should not travel over clear HTTP.",
            location="http_https_redirect",
        )
    else:
        reporter.log(
            check_id,
            "FAIL",
            f"HTTP access to {http_url} is not redirected to HTTPS "
            f"(final URL: {final_url}, status: {resp.status_code}).",
            location="http_https_redirect",
        )


def check_athn_02(brain, reporter, verifier=None):
    check_id = "WSTG-ATHN-02"
    art = _auth_discovery(brain)

    if not art["login_present"]:
        reporter.log(
            check_id,
            "PASS",
            "No standard WordPress login form detected at /wp-login.php; "
            "default credential checks for WordPress are not applicable.",
            location="wp_default_credentials",
        )
        return

    hints = [
        "Verify that any historical 'admin' or installer accounts have strong, "
        "unique passwords or are disabled.",
        "Confirm there are no vendor or panel default credentials in use for "
        "integrated services.",
    ]

    reporter.log(
        check_id,
        "PASS",
        "WordPress login is present at /wp-login.php. This tool does not "
        "attempt default credentials; manual WSTG-ATHN-02 testing should "
        f"confirm defaults are disabled. Examples to review: {hints}",
        location="wp_default_credentials",
    )


def check_athn_04(brain, reporter, verifier=None):
    check_id = "WSTG-ATHN-04"
    art = _auth_discovery(brain)

    origin = art["origin_https"]
    public_paths = art["admin_public_paths"]

    if public_paths:
        curl_cmds = [
            f"curl -s -D- -L '{origin}{p}' | head -n 40"
            for p in public_paths
        ]
        reporter.log(
            check_id,
            "FAIL",
            "One or more WordPress admin endpoints (including /wp-admin/edit.php "
            "and /wp-admin/profile.php) appear accessible without showing the "
            "login form, indicating a possible authentication bypass. "
            f"Affected paths: {public_paths}. Suggested checks: {curl_cmds}",
            location="wp_admin_bypass",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "Core WordPress admin endpoints (/wp-admin/, /wp-admin/edit.php, "
            "/wp-admin/profile.php, etc.) do not appear usable without "
            "authenticating first.",
            location="wp_admin_bypass",
        )


def run_auth_checks(brain, reporter, verifier=None):
    check_athn_01(brain, reporter, verifier)
    check_athn_02(brain, reporter, verifier)
    check_athn_04(brain, reporter, verifier)
