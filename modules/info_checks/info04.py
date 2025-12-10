import os
import json
import re
from urllib.parse import urlparse


def check_info_04(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-04"

    if not brain.html_source:
        reporter.log(
            check_id,
            "PASS",
            "No main HTML source available; skipping application enumeration.",
            location="root",
        )
        return

    html = brain.html_source

    rel_urls = re.findall(
        r'\s(?:href|src)=["\'](/[^"\']*)["\']',
        html,
        flags=re.IGNORECASE,
    )

    all_paths = set()
    for u in rel_urls:
        parsed = urlparse(u)
        path = parsed.path or "/"
        all_paths.add(path)

    ignore_roots = {
        "",
        "/",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/security.txt",
        "/humans.txt",
    }

    static_roots = {
        "css",
        "js",
        "img",
        "image",
        "images",
        "static",
        "assets",
        "fonts",
        "media",
        "vendor",
        "node_modules",
        "dist",
        "build",
        "wp-content",
        "wp-includes",
        "themes",
        "plugins",
        "_next",
        "_nuxt",
    }

    candidate_roots = set()
    for path in all_paths:
        if path in ignore_roots:
            continue
        parts = path.strip("/").split("/")
        if not parts:
            continue
        root = parts[0]
        if root in static_roots:
            continue
        candidate_roots.add(f"/{root}/")

    root_fp = _fingerprint_html(html)
    potential_apps = []
    same_theme_sections = []

    for base in sorted(candidate_roots):
        r = brain.targeted_request(base)
        if not r or r.status_code >= 400 or not r.text:
            continue

        fp = _fingerprint_html(r.text)
        root_theme = root_fp.get("wp_theme")
        sub_theme = fp.get("wp_theme")
        css_overlap = _jaccard(root_fp["css"], fp["css"])
        js_overlap = _jaccard(root_fp["js"], fp["js"])

        record = {
            "path": base,
            "root_theme": root_theme,
            "sub_theme": sub_theme,
            "css_overlap": round(css_overlap, 2),
            "js_overlap": round(js_overlap, 2),
        }

        if (root_theme and sub_theme and root_theme != sub_theme) or (
            css_overlap < 0.4 and js_overlap < 0.4
        ):
            potential_apps.append(record)
        else:
            same_theme_sections.append(record)

    if potential_apps:
        msg = "POTENTIAL CHECKING NEEDED – paths that may be separate applications: "
        msg += ", ".join(
            f"{p['path']} (root_theme={p['root_theme']}, "
            f"sub_theme={p['sub_theme']}, "
            f"css_overlap={p['css_overlap']}, "
            f"js_overlap={p['js_overlap']})"
            for p in potential_apps
        )
        reporter.log(
            check_id,
            "PASS",
            msg,
            location="path_fingerprint",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "No strong evidence of separate applications by path; "
            "root sections share theme/assets.",
            location="path_fingerprint",
        )

    if same_theme_sections:
        msg = (
            "Sections likely part of the same application "
            "(same theme / high asset overlap): "
        )
        msg += ", ".join(
            f"{s['path']} (theme={s['sub_theme']}, "
            f"css_overlap={s['css_overlap']}, "
            f"js_overlap={s['js_overlap']})"
            for s in same_theme_sections
        )
        reporter.log(
            check_id,
            "PASS",
            msg,
            location="path_fingerprint",
        )

    out_dir = getattr(reporter, "out_dir", ".")
    try:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "root_paths.json")
        with open(out_path, "w") as f:
            json.dump(sorted(all_paths), f, indent=2)
        reporter.log(
            check_id,
            "PASS",
            f"All paths referenced from '/' saved to {out_path}",
            location="root_paths.json",
        )
    except Exception as e:
        reporter.log(
            check_id,
            "PASS",
            f"Could not write root_paths.json: {e}",
            location="root_paths.json",
        )


def _fingerprint_html(html: str):
    m = re.search(r"wp-content/themes/([^/]+)/", html, flags=re.IGNORECASE)
    wp_theme = m.group(1) if m else None

    css = set(
        re.findall(
            r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']',
            html,
            flags=re.IGNORECASE,
        )
    )

    js = set(
        re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            html,
            flags=re.IGNORECASE,
        )
    )

    return {
        "wp_theme": wp_theme,
        "css": css,
        "js": js,
    }


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    if union == 0:
        return 0.0
    return inter / union
