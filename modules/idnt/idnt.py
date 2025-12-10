import json
import re
from urllib.parse import urlparse


def _wp_discovery(brain):
    art = brain.artifacts.setdefault("wp_idnt", {})
    if art.get("done"):
        return art

    parsed = urlparse(brain.target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    def _get(path: str):
        return brain.targeted_request(path)

    wp_login_present = False
    wp_login_url = None

    resp = _get("/wp-login.php")
    if resp and resp.status_code == 200:
        body = (resp.text or "")[:20000]
        if (
            'id="loginform"' in body
            or 'name="log"' in body
            or 'name="user_login"' in body
        ):
            wp_login_present = True
            wp_login_url = "/wp-login.php"

    def _looks_like_reg_form(body: str) -> bool:
        if not body:
            return False
        lower = body.lower()
        if "user registration is currently not allowed" in lower:
            return False
        has_user = re.search(
            r'name["\'](user_login|username|login)["\']', body, re.IGNORECASE
        )
        has_email = re.search(
            r'name["\'](user_email|email)["\']', body, re.IGNORECASE
        )
        has_pass = re.search(
            r'name["\'](pass1|password|user_pass)["\']', body, re.IGNORECASE
        )
        return (has_user and has_email) or (has_email and has_pass) or (has_user and has_pass)

    reg_targets = [
        "/wp-login.php?action=register",
        "/wp-signup.php",
    ]

    wp_registration_enabled = False
    wp_registration_disabled_seen = False
    wp_registration_urls = []

    for path in reg_targets:
        resp = _get(path)
        if not resp or resp.status_code != 200:
            continue
        body = (resp.text or "")[:20000]
        lower = body.lower()

        if "user registration is currently not allowed" in lower:
            wp_registration_disabled_seen = True
            continue

        if _looks_like_reg_form(body):
            wp_registration_enabled = True
            wp_registration_urls.append(path.split("?", 1)[0])

    wp_rest_bulk_enum = False
    wp_rest_bulk_examples = []

    resp = _get("/wp-json/wp/v2/users")
    if resp and resp.status_code == 200:
        try:
            data = json.loads(resp.text)
        except Exception:
            data = None

        if isinstance(data, list) and data and isinstance(data[0], dict):
            usernames = []
            for u in data[:5]:
                for key in ("slug", "name", "username"):
                    if key in u and isinstance(u[key], str):
                        usernames.append(u[key])
                        break
            if usernames:
                wp_rest_bulk_enum = True
                wp_rest_bulk_examples.append(
                    f"/wp-json/wp/v2/users -> {len(data)} users (examples: {usernames})"
                )

    wp_rest_single_enum = False
    wp_rest_single_examples = []

    for ident in ("1", "admin", "01"):
        path = f"/wp-json/wp/v2/users/{ident}"
        resp = _get(path)
        if not resp or resp.status_code != 200:
            continue
        try:
            data = json.loads(resp.text)
        except Exception:
            continue

        if isinstance(data, dict) and any(
            k in data for k in ("slug", "name", "username", "id")
        ):
            val = (
                data.get("slug")
                or data.get("name")
                or data.get("username")
                or data.get("id")
            )
            wp_rest_single_enum = True
            wp_rest_single_examples.append(f"{path} -> {val}")
            break

    art.update(
        dict(
            origin=origin,
            wp_login_present=wp_login_present,
            wp_login_url=wp_login_url,
            wp_registration_enabled=wp_registration_enabled,
            wp_registration_disabled_seen=wp_registration_disabled_seen,
            wp_registration_urls=sorted(set(wp_registration_urls)),
            wp_rest_bulk_enum=wp_rest_bulk_enum,
            wp_rest_bulk_examples=wp_rest_bulk_examples,
            wp_rest_single_enum=wp_rest_single_enum,
            wp_rest_single_examples=wp_rest_single_examples,
            done=True,
        )
    )
    return art


def check_idnt_01(brain, reporter, verifier=None):
    check_id = "WSTG-IDNT-01"
    art = _wp_discovery(brain)

    login_url = art.get("wp_login_url") or "not detected"
    reg_urls = art.get("wp_registration_urls") or []

    if art["wp_registration_enabled"]:
        reporter.log(
            check_id,
            "PASS",
            "WordPress login and registration discovered: "
            f"login={login_url}, registration={reg_urls}. "
            "Manual review of the registration flow is required.",
            location="wp_registration",
        )
    elif art["wp_registration_disabled_seen"]:
        reporter.log(
            check_id,
            "PASS",
            "WordPress login and registration endpoints discovered but "
            "registration is disabled: "
            f"login={login_url}, registration_targets={reg_urls}.",
            location="wp_registration",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "WordPress login discovery result: "
            f"login={login_url}; no core registration page found at "
            "/wp-login.php?action=register or /wp-signup.php.",
            location="wp_registration",
        )


def check_idnt_02(brain, reporter, verifier=None):
    check_id = "WSTG-IDNT-02"
    art = _wp_discovery(brain)
    origin = art["origin"]

    if not art["wp_registration_enabled"]:
        reporter.log(
            check_id,
            "PASS",
            "No active WordPress registration form detected; "
            "Test User Registration Process is not applicable.",
            location="wp_registration",
        )
        return

    curl_cmds = [
        f"curl -s -D- -L '{origin}{p}' | less"
        for p in art["wp_registration_urls"]
    ]

    reporter.log(
        check_id,
        "PASS",
        "WordPress registration is enabled. Login URL: "
        f"{art.get('wp_login_url') or 'not detected'}. "
        "Automated registration testing is not permitted; manual "
        "WSTG-IDNT-02 testing is required on "
        f"{art['wp_registration_urls']}. Suggested manual checks: {curl_cmds}",
        location="wp_registration",
    )


def check_idnt_04(brain, reporter, verifier=None):
    check_id = "WSTG-IDNT-04"
    art = _wp_discovery(brain)
    origin = art["origin"]

    any_issue = False

    if art["wp_rest_bulk_enum"]:
        curl_cmd = f"curl -s '{origin}/wp-json/wp/v2/users' | jq '.'"
        reporter.log(
            check_id,
            "FAIL",
            "WordPress REST API exposes a list of users at "
            "/wp-json/wp/v2/users, enabling bulk account enumeration: "
            f"{art['wp_rest_bulk_examples']}. Manual check: {curl_cmd}",
            location="wp_rest_bulk",
        )
        any_issue = True

    if art["wp_rest_single_enum"]:
        examples = art["wp_rest_single_examples"]
        curl_cmd = f"curl -s '{origin}/wp-json/wp/v2/users/1' | jq '.'"
        reporter.log(
            check_id,
            "FAIL",
            "WordPress REST API exposes individual users at "
            "/wp-json/wp/v2/users/{id-or-slug}, enabling targeted "
            f"enumeration: {examples}. Manual check: {curl_cmd}",
            location="wp_rest_single",
        )
        any_issue = True

    if not any_issue:
        reporter.log(
            check_id,
            "PASS",
            "No WordPress REST user enumeration detected: "
            "/wp-json/wp/v2/users and /wp-json/wp/v2/users/{1,admin,01} "
            "do not return user data without authentication.",
            location="wp_enum",
        )


def check_idnt_05(brain, reporter, verifier=None):
    check_id = "WSTG-IDNT-05"
    art = _wp_discovery(brain)
    origin = art["origin"]

    if not art["wp_rest_bulk_enum"] and not art["wp_rest_single_enum"]:
        reporter.log(
            check_id,
            "PASS",
            "No usernames are exposed via the WordPress REST API; weak or "
            "unenforced username policy cannot be evaluated automatically "
            "and is not applicable for REST in this context.",
            location="wp_username_policy",
        )
        return

    enum_sources = []
    if art["wp_rest_bulk_enum"]:
        enum_sources.append("/wp-json/wp/v2/users")
    if art["wp_rest_single_enum"]:
        enum_sources.append("/wp-json/wp/v2/users/{1,admin,01}")

    curl_cmd = f"curl -s '{origin}/wp-json/wp/v2/users' | jq '.'"

    reporter.log(
        check_id,
        "FAIL",
        "Usernames are exposed via the WordPress REST API "
        f"({enum_sources}). Review username predictability and "
        "application error messages (e.g. login/password reset) for "
        "enumeration risk. Suggested manual check: "
        f"{curl_cmd}",
        location="wp_username_policy",
    )


def run_idnt_checks(brain, reporter, verifier=None):
    check_idnt_01(brain, reporter, verifier)
    check_idnt_02(brain, reporter, verifier)
    check_idnt_04(brain, reporter, verifier)
    check_idnt_05(brain, reporter, verifier)
