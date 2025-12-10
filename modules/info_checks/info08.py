import re
import json
from urllib.parse import urlparse


def check_info_08(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-08"

    html = getattr(brain, "html_source", "") or ""
    whatweb_data = getattr(brain, "whatweb_data", []) or []
    tech_artifacts = set(brain.artifacts.get("technologies", set()) or [])
    discovery_files = getattr(brain, "discovery_files", {}) or {}
    js_files = getattr(brain, "js_files", {}) or getattr(brain, "jsfiles", {}) or {}

    if not html and not whatweb_data and not tech_artifacts and not js_files:
        reporter.log(
            check_id,
            "PASS",
            "No sufficient data collected to fingerprint the web application framework.",
            location="Summary",
        )
        return

    candidates = {}

    # Build WhatWeb plugin name set for correlation
    ww_names = set()
    if whatweb_data:
        last_scan = whatweb_data[-1]
        for plugin in last_scan.get("plugins", {}).keys():
            if plugin in ["Country", "IP", "Title", "RedirectLocation"]:
                continue
            ww_names.add(plugin.strip().lower())

    def add_hit(name: str, source: str, detail: str):
        key = name.strip().lower()
        if not key:
            return
        correlated = key in ww_names
        if correlated and "correlated with WhatWeb" not in detail:
            detail = f"{detail} (correlated with WhatWeb plugin)"
        entry = candidates.setdefault(
            key,
            {"label": name.strip(), "hits": []},
        )
        entry["hits"].append(f"{source}: {detail}")

    # 1. Raw WhatWeb output (full JSON as informational proof)
    if whatweb_data:
        raw_ww = json.dumps(whatweb_data, indent=2)[:8000]
        reporter.log(
            check_id,
            "PASS",
            f"WhatWeb raw fingerprint data (truncated to 8k chars): {raw_ww}",
            location="WhatWeb",
        )
        last_scan = whatweb_data[-1]
        for plugin, info in last_scan.get("plugins", {}).items():
            if plugin in ["Country", "IP", "Title", "RedirectLocation"]:
                continue
            add_hit(plugin, "WhatWeb", "plugin detected")

    # 2. META generator tags
    for m in re.findall(
        r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\\']+)["\']',
        html,
        flags=re.IGNORECASE,
    ):
        val = m.strip()
        if not val:
            continue
        add_hit(val, "META generator", "generator meta tag")
        tech_artifacts.add(val)

    # 3. HTML heuristics for frameworks / CMS
    lower_html = html.lower()

    if "wp-content/" in lower_html or "wordpress" in lower_html:
        add_hit("WordPress", "HTML body", "wp-content/ or wordpress markers")
    if "drupal.settings" in lower_html or "/sites/all/modules/" in lower_html:
        add_hit("Drupal", "HTML body", "drupal.settings or sites/all/modules")
    if "joomla" in lower_html and 'content="joomla' in lower_html:
        add_hit("Joomla", "HTML body", "Joomla markers")
    if 'content="laravel' in lower_html or "x-powered-by: laravel" in lower_html:
        add_hit("Laravel", "HTML body", "Laravel markers")
    if "asp.net" in lower_html or "__viewstate" in lower_html:
        add_hit("ASP.NET", "HTML body", "__VIEWSTATE/ASP.NET markers")
    if "ng-version" in lower_html:
        add_hit("Angular", "HTML body", "ng-version attribute")
    if "data-reactroot" in lower_html or "react-dom" in lower_html:
        add_hit("React", "HTML body", "data-reactroot or react-dom")

    # 3a. WordPress theme and plugin slugs in HTML
    for m in re.findall(r"wp-content/themes/([a-zA-Z0-9_\-]+)/", lower_html):
        add_hit(f"WordPress theme: {m}", "HTML body", f"wp-content/themes/{m}/")
    for m in re.findall(r"wp-content/plugins/([a-zA-Z0-9_\-]+)/", lower_html):
        add_hit(f"WordPress plugin: {m}", "HTML body", f"wp-content/plugins/{m}/")

    # 4. Discovery files
    for name, content in discovery_files.items():
        lname = (content or "").lower()
        if "wp-content/" in lname or "wordpress" in lname:
            add_hit("WordPress", name, "wp-content or wordpress markers")
        if "drupal.settings" in lname:
            add_hit("Drupal", name, "drupal.settings in discovery file")

    # 5. JS paths and hosts: libraries, WP, and extra tools
    for url, body in js_files.items():
        parsed = urlparse(url)
        path = parsed.path or ""
        lower_path = path.lower()
        host = parsed.netloc.lower()

        if "jquery" in lower_path:
            add_hit("jQuery", path, "jquery file name")
        if "angular" in lower_path:
            add_hit("AngularJS", path, "angular file name")
        if "vue" in lower_path and "vue.js" in lower_path:
            add_hit("Vue.js", path, "vue.js file name")
        if "react" in lower_path and "react-dom" in lower_path:
            add_hit("React", path, "react-dom file name")
        if "wp-includes/" in lower_path or "wp-content/" in lower_path:
            add_hit("WordPress", path, "wp-includes/wp-content in JS path")

        for m in re.findall(r"wp-content/themes/([a-zA-Z0-9_\-]+)/", lower_path):
            add_hit(f"WordPress theme: {m}", path, f"wp-content/themes/{m}/")
        for m in re.findall(r"wp-content/plugins/([a-zA-Z0-9_\-]+)/", lower_path):
            add_hit(f"WordPress plugin: {m}", path, f"wp-content/plugins/{m}/")

        if "googletagmanager.com" in host:
            add_hit("Google Tag Manager", url, "gtm.js script")
        if "google-analytics.com" in host or "gtag/js" in url.lower():
            add_hit("Google Analytics / gtag", url, "analytics/gtag script")
        if "recaptcha" in host or "www.google.com/recaptcha" in url.lower():
            add_hit("Google reCAPTCHA", url, "reCAPTCHA script")
        if "js.stripe.com" in host or "stripe.com" in host:
            add_hit("Stripe", url, "Stripe JS library")
        if "paypal.com" in host or "paypalobjects.com" in host:
            add_hit("PayPal", url, "PayPal checkout JS")
        if "hotjar.com" in host:
            add_hit("Hotjar", url, "Hotjar tracking script")
        if "cloudflare" in host:
            add_hit("Cloudflare", url, "Cloudflare-related script")

    # 6. Generic technologies from artifacts
    for t in tech_artifacts:
        add_hit(t, "Technologies", "detected by WhatWeb or headers/html")

    if not candidates:
        reporter.log(
            check_id,
            "PASS",
            "No clear framework, CMS, plugin, theme, or third-party tool fingerprints could be derived from collected data.",
            location="Summary",
        )
        return

    summaries = []
    for key, data in sorted(candidates.items()):
        label = data["label"]
        hits = data["hits"][:5]
        summaries.append(f"{label} (evidence: {hits})")

    msg = (
        "Possible web application frameworks, CMSs, themes, plugins, libraries, and "
        "third-party tools identified: "
        f"{'; '.join(summaries)}. This is informational and should guide "
        "subsequent technology-specific testing."
    )
    reporter.log(check_id, "PASS", msg, location="Summary")
