import re
from urllib.parse import urlparse


def check_conf_05(brain, reporter, verifier=None):
    check_id = "WSTG-CONF-05"
    html = brain.html_source or ""

    technologies = {t.lower() for t in brain.artifacts.get("technologies", [])}
    stack_hints = set(brain.artifacts.get("technologies", []))

    gen_tags = re.findall(
        r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )
    for g in gen_tags:
        val = g.strip()
        if not val:
            continue
        stack_hints.add(f"generator: {val}")
        technologies.add(val.lower())

    if brain.main_response is not None:
        server = brain.main_response.headers.get("Server")
        xpb = brain.main_response.headers.get("X-Powered-By")
        if server:
            stack_hints.add(f"Server: {server}")
            technologies.add(server.lower())
        if xpb:
            stack_hints.add(f"X-Powered-By: {xpb}")
            technologies.add(xpb.lower())

    adminish_keywords = (
        "admin",
        "administrator",
        "backend",
        "manage",
        "management",
        "console",
        "dashboard",
        "wp-admin",
        "wp-login",
        "login",
        "logon",
        "auth",
    )

    homepage_candidates = set()
    default_candidates = set()

    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)
    for href in hrefs:
        url = href.strip()
        if not url:
            continue
        if url.startswith("http://") or url.startswith("https://"):
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != brain.domain:
                continue
            path = parsed.path or "/"
        else:
            parsed = urlparse(url)
            path = parsed.path or "/"
        lower_path = path.lower()
        if any(k in lower_path for k in adminish_keywords):
            if not path.startswith("/"):
                path = "/" + path
            base = path.split("?", 1)[0]
            homepage_candidates.add(base)

    forms = re.findall(
        r'<form[^>]+action=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )
    for action in forms:
        url = action.strip()
        if not url:
            continue
        if url.startswith("http://") or url.startswith("https://"):
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != brain.domain:
                continue
            path = parsed.path or "/"
        else:
            parsed = urlparse(url)
            path = parsed.path or "/"
        lower_path = path.lower()
        if any(k in lower_path for k in adminish_keywords):
            if not path.startswith("/"):
                path = "/" + path
            base = path.split("?", 1)[0]
            homepage_candidates.add(base)

    js_targets = re.findall(
        r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
        html,
        flags=re.IGNORECASE,
    )
    for target in js_targets:
        path = target.strip()
        if not path:
            continue
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            if parsed.netloc and parsed.netloc != brain.domain:
                continue
            path = parsed.path or "/"
        lower_path = path.lower()
        if any(k in lower_path for k in adminish_keywords):
            if not path.startswith("/"):
                path = "/" + path
            base = path.split("?", 1)[0]
            homepage_candidates.add(base)

    for f in brain.artifacts.get("forms", []):
        action = (f.get("action") or "").strip()
        if not action:
            continue
        parsed = urlparse(action)
        path = parsed.path or "/"
        lower_path = path.lower()
        if any(k in lower_path for k in adminish_keywords):
            if not path.startswith("/"):
                path = "/" + path
            base = path.split("?", 1)[0]
            homepage_candidates.add(base)

    for c in brain.artifacts.get("comments", []):
        text = (c.get("content") or "").strip()
        if not text:
            continue
        for k in adminish_keywords:
            m = re.search(
                rf"(\/[A-Za-z0-9_\-\/]*{re.escape(k)}[A-Za-z0-9_\-\/]*)",
                text,
                re.IGNORECASE,
            )
            if m:
                path = m.group(1)
                if not path.startswith("/"):
                    path = "/" + path
                path = path.split("?", 1)[0]
                homepage_candidates.add(path)

    default_candidates.update(
        [
            "/admin",
            "/admin/",
            "/administrator",
            "/administrator/",
            "/admin/login",
            "/admin/login.php",
            "/admin.php",
            "/login.php",
            "/logon.php",
            "/backend/",
            "/dashboard/",
            "/manage/",
            "/controlpanel/",
            "/console/",
            "/phpinfo",
            "/phpinfo.php",
            "/phpmyadmin/",
            "/phpMyAdmin/",
            "/mysqladmin/",
            "/MySQLadmin",
            "/MySQLAdmin",
            "/dbadmin",
            "/xmlrpc.php",
        ]
    )

    if any("wordpress" in t for t in technologies):
        default_candidates.update(
            [
                "/wp-admin/",
                "/wp-admin/about.php",
                "/wp-admin/admin-ajax.php",
                "/wp-admin/admin-db.php",
                "/wp-admin/admin-footer.php",
                "/wp-admin/admin-functions.php",
                "/wp-admin/admin-header.php",
                "/wp-login.php",
            ]
        )

    if any("joomla" in t for t in technologies):
        default_candidates.update(
            [
                "/administrator/index.php",
                "/administrator/index.php?option=com_login",
                "/administrator/index.php?option=com_content",
                "/administrator/index.php?option=com_users",
                "/administrator/index.php?option=com_menus",
                "/administrator/index.php?option=com_installer",
                "/administrator/index.php?option=com_config",
            ]
        )

    if any("tomcat" in t for t in technologies):
        default_candidates.update(
            [
                "/manager/html",
                "/host-manager/html",
                "/manager/text",
            ]
        )

    if any("apache" in t for t in technologies):
        default_candidates.add("/server-status")

    if any("nginx" in t for t in technologies):
        default_candidates.add("/nginx_status")

    ordered_candidates = list(sorted(homepage_candidates)) + [
        p for p in sorted(default_candidates) if p not in homepage_candidates
    ]

    seen_canon = set()
    unique_candidates = []
    for p in ordered_candidates:
        canon = p.rstrip("/") or "/"
        if canon in seen_canon:
            continue
        seen_canon.add(canon)
        unique_candidates.append(p)

    unique_candidates = unique_candidates[:50]
    findings = []

    for path in unique_candidates:
        resp = brain.targeted_request(path)
        if not resp:
            continue
        status = resp.status_code
        if status not in (200, 401, 403):
            continue

        body = (resp.text or "")[:8000]
        lower_body = body.lower()
        desc = None
        location = "admin_interface"

        if path.startswith("/wp-admin"):
            desc = f"WordPress admin interface reachable at {path} (HTTP {status})."
            location = "wp_admin"
        elif "phpmyadmin" in path.lower():
            desc = f"phpMyAdmin interface reachable at {path} (HTTP {status})."
            location = "phpmyadmin"
        elif "dbadmin" in path.lower() or "mysqladmin" in path.lower():
            desc = f"Database admin interface reachable at {path} (HTTP {status})."
            location = "db_admin"
        elif "manager/html" in path or "host-manager/html" in path:
            desc = f"Tomcat manager interface reachable at {path} (HTTP {status})."
            location = "tomcat_manager"
        elif any(k in path.lower() for k in adminish_keywords):
            if any(x in path.lower() for x in ("login", "logon", "signin")):
                desc = f"Login endpoint discovered at {path} (HTTP {status})."
                location = "login"
            else:
                desc = f"Possible admin interface at {path} (HTTP {status})."
        if not desc and path.endswith(".php"):
            if "phpinfo()" in body or "php version" in lower_body:
                desc = f"phpinfo() environment page exposed at {path} (HTTP {status})."
                location = "phpinfo"

        if desc:
            findings.append((desc, status, location))

    if stack_hints:
        reporter.log(
            check_id,
            "PASS",
            f"Detected platform/CMS hints from architecture: {sorted(stack_hints)}",
            location="stack",
        )

    if findings:
        reported = set()
        for msg, status, loc in findings:
            key = (loc, msg)
            if key in reported:
                continue
            reported.add(key)
            reporter.log(check_id, "FAIL", msg, location=loc)
    else:
        reporter.log(
            check_id,
            "PASS",
            "No obvious admin, login, or management interfaces discovered from "
            "cached '/' content or common default paths.",
            location="admin_interface",
        )

