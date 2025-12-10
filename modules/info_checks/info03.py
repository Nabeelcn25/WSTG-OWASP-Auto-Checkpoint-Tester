import random
import re
from urllib.parse import urlparse


def check_info_03(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-03"

    target_files = [
        "robots.txt",
        "sitemap.xml",
        "sitemap_index.xml",
        "security.txt",
        ".well-known/security.txt",
        "humans.txt",
    ]

    found_files = {}

    for filename in target_files:
        content = brain.get_standard_file(filename)
        if content:
            found_files[filename] = content

    if not found_files:
        reporter.log(
            check_id,
            "PASS",
            "No standard metadata files found.",
            location="Discovery",
        )
        return

    reporter.log(
        check_id,
        "PASS",
        f"Metafiles found: {', '.join(found_files.keys())}",
        location="Discovery",
    )

    meta_art = brain.artifacts.setdefault("metafiles", {})
    for name, content in found_files.items():
        meta_art[name] = {
            "length": len(content),
            "snippet": (content[:200] + "...") if len(content) > 200 else content,
        }

    if "robots.txt" in found_files:
        _analyze_robots(brain, reporter, check_id, found_files["robots.txt"])

    sitemap_keys = [k for k in found_files if "sitemap" in k]
    for sitemap_name in sitemap_keys:
        content = found_files[sitemap_name]
        _analyze_sitemap_content(brain, reporter, check_id, content, sitemap_name)

        child_sitemaps = re.findall(
            r"<loc>(.*?sitemap.*?\.xml)</loc>", content
        )
        if child_sitemaps:
            reporter.log(
                check_id,
                "PASS",
                f"Sitemap index '{sitemap_name}' references "
                f"{len(child_sitemaps)} child sitemaps.",
                location=sitemap_name,
            )
            child_url = child_sitemaps[0]
            parsed = urlparse(child_url)
            r_child = brain.targeted_request(parsed.path or "/")
            if r_child and r_child.status_code == 200 and r_child.text:
                _analyze_sitemap_content(
                    brain,
                    reporter,
                    check_id,
                    r_child.text,
                    f"{sitemap_name} -> child",
                )

    if brain.html_source:
        _analyze_meta_tags(brain, reporter, check_id, brain.html_source)

    if "security.txt" in found_files or ".well-known/security.txt" in found_files:
        sec_name = (
            "security.txt"
            if "security.txt" in found_files
            else ".well-known/security.txt"
        )
        _analyze_security_txt(
            reporter, check_id, found_files[sec_name], sec_name
        )

    if "humans.txt" in found_files:
        _analyze_humans_txt(reporter, check_id, found_files["humans.txt"])


def _is_real_access(r):
    if not r:
        return False
    status = r.status_code
    body = (r.text or "").strip()
    body_short = re.sub(r"\s+", "", body)

    if status != 200:
        return False
    if re.fullmatch(r"[+-]?\d+", body_short):
        return False
    if len(body_short) < 10:
        return False

    denied_keywords = ["forbidden", "access denied", "not allowed", "unauthorized"]
    if any(k in body.lower() for k in denied_keywords):
        return False

    return True


def _analyze_robots(brain, reporter, check_id, content):
    sensitive_keywords = [
        "admin",
        "login",
        "config",
        "backup",
        "db",
        "database",
        "staging",
        "private",
        "logs",
        "dashboard",
        "internal",
    ]

    accessible_leaks = []

    for line in content.splitlines():
        clean_line = line.split("#", 1)[0].strip()
        if clean_line.lower().startswith("disallow:"):
            parts = clean_line.split(":", 1)
            if len(parts) > 1:
                path = parts[1].strip()
                if path and path != "/" and any(
                    k in path.lower() for k in sensitive_keywords
                ):
                    r = brain.targeted_request(path)
                    if _is_real_access(r):
                        accessible_leaks.append(
                            f"{path} (200 OK, len={len((r.text or '').strip())})"
                        )

    if accessible_leaks:
        proof = ", ".join(accessible_leaks[:3])
        if len(accessible_leaks) > 3:
            proof += f" ... and {len(accessible_leaks) - 3} more"
        reporter.log(
            check_id,
            "FAIL",
            "robots.txt lists sensitive paths that appear publicly accessible: "
            f"{proof}",
            location="robots.txt",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "robots.txt analyzed; no clearly accessible sensitive paths found.",
            location="robots.txt",
        )

    robots_comments = [l.strip() for l in content.splitlines() if "#" in l]
    if robots_comments:
        reporter.log(
            check_id,
            "PASS",
            f"Manual review – robots.txt comments: {robots_comments}",
            location="robots.txt",
        )


def _analyze_sitemap_content(brain, reporter, check_id, content, source_name):
    xml_comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)

    ignore_signatures = [
        "generated by",
        "yoast",
        "wordpress seo",
        "sitemap",
        "google",
        "bing",
        "seo",
        "w3 total cache",
        "served from",
        "performance optimized by",
        "cached",
        "http://",
        "https://",
    ]

    dev_leak_signatures = [
        "todo",
        "fixme",
        "hack",
        "edit",
        "remove",
        "internal",
        "staging",
        "debug",
        "test",
    ]

    manual_review_comments = []

    for comment in xml_comments:
        stripped = comment.strip()
        lower = stripped.lower()

        if any(sig in lower for sig in ignore_signatures):
            continue

        manual_review_comments.append(stripped)

        if any(sig in lower for sig in dev_leak_signatures):
            reporter.log(
                check_id,
                "FAIL",
                f"Developer / debug comment in sitemap ({source_name}): "
                f"'{stripped}'",
                location=source_name,
            )

    if manual_review_comments:
        reporter.log(
            check_id,
            "PASS",
            "Manual review – sitemap comments in "
            f"{source_name}: {manual_review_comments}",
            location=source_name,
        )

    lower_body = content.lower()
    if any(
        token in lower_body
        for token in [
            "admin-sitemap",
            "users-sitemap",
            "internal-sitemap",
            "private-sitemap",
        ]
    ):
        reporter.log(
            check_id,
            "FAIL",
            f"Sitemap structure in {source_name} exposes admin/users/internal "
            "sitemap files.",
            location=source_name,
        )

    if "admin" in lower_body or "login" in lower_body or "internal" in lower_body:
        reporter.log(
            check_id,
            "FAIL",
            f"Sitemap {source_name} references admin/login/internal URLs.",
            location=source_name,
        )

    urls = re.findall(r"<loc>(.*?)</loc>", content)
    page_urls = [u for u in urls if ".xml" not in u]

    if page_urls:
        sample_size = min(2, len(page_urls))
        samples = random.sample(page_urls, sample_size)

        ok = 0
        for url in samples:
            parsed = urlparse(url)
            if parsed.netloc and brain.domain not in parsed.netloc:
                continue
            r = brain.targeted_request(parsed.path or "/")
            if _is_real_access(r):
                ok += 1

        if ok < sample_size:
            reporter.log(
                check_id,
                "PASS",
                f"Sitemap {source_name}: only {ok}/{sample_size} sampled URLs "
                "responded with real 200 pages.",
                location=source_name,
            )
        else:
            reporter.log(
                check_id,
                "PASS",
                f"Sitemap {source_name}: sampled URLs are reachable "
                f"({ok}/{sample_size} active).",
                location=source_name,
            )


def _analyze_meta_tags(brain, reporter, check_id, html):
    robots_meta = re.findall(
        r'<meta\s+[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )

    if robots_meta:
        reporter.log(
            check_id,
            "PASS",
            f"Found META robots directives: {robots_meta}",
            location="META robots",
        )

    interesting_meta = re.findall(
        r'<meta\s+[^>]*(property|name)=["\']'
        r"(og:[^\"']+|twitter:[^\"']+|application-name|apple-mobile-web-app-title)"
        r'["\'][^>]*>',
        html,
        flags=re.IGNORECASE,
    )

    if interesting_meta:
        reporter.log(
            check_id,
            "PASS",
            "Misc META tags of interest present (OG/Twitter/app-name). "
            f"Count: {len(interesting_meta)}",
            location="META misc",
        )


def _analyze_security_txt(reporter, check_id, content, source_name):
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    contacts = [l for l in lines if l.lower().startswith("contact:")]
    policy = [l for l in lines if l.lower().startswith("policy:")]

    reporter.log(
        check_id,
        "PASS",
        f"{source_name} present. Contacts: {contacts}, Policy: {policy}",
        location=source_name,
    )


def _analyze_humans_txt(reporter, check_id, content):
    snippet = " ".join(content.splitlines())[:200]
    reporter.log(
        check_id,
        "PASS",
        f"humans.txt present (first 200 chars): {snippet}",
        location="humans.txt",
    )
