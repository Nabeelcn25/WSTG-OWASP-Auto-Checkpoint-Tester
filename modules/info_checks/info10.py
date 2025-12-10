import re
from urllib.parse import urlparse
from xml.etree import ElementTree as ET


def check_info_10(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-10"

    reporter.log(
        check_id,
        "PASS",
        "For maximum accuracy, run all other checks before INFO-10 so the application map and caches are fully populated.",
        location="Run order",
    )

    html = getattr(brain, "html_source", "") or ""
    techs = set(brain.artifacts.get("technologies", set()) or [])
    whatweb_data = getattr(brain, "whatweb_data", []) or []
    discovery_files = getattr(brain, "discovery_files", {}) or {}
    mapper_tree = brain.mapper.generate_tree()
    response_cache = getattr(brain, "response_cache", {}) or {}
    raw_endpoints = list(getattr(brain, "raw_artifacts", {}).get("endpoints", []))
    raw_params = list(getattr(brain, "raw_artifacts", {}).get("parameters", []))

    lower_html = html.lower()
    wp_hits = []

    if any("wordpress" in t.lower() for t in techs):
        wp_hits.append("technologies: WordPress in technology list")
    if whatweb_data:
        last_scan = whatweb_data[-1]
        for plugin in last_scan.get("plugins", {}).keys():
            if "wordpress" in plugin.lower():
                wp_hits.append("WhatWeb plugin: WordPress")

    if "wp-content/" in lower_html or "wp-includes/" in lower_html:
        wp_hits.append("HTML body: wp-content/wp-includes markers")

    for e in raw_endpoints:
        path = e.get("path", "") if isinstance(e, dict) else str(e)
        lp = path.lower()
        if "wp-admin" in lp:
            wp_hits.append(f"Endpoint: {path} (wp-admin)")
        if "wp-login.php" in lp:
            wp_hits.append(f"Endpoint: {path} (wp-login.php)")
        if lp.startswith("/wp-json/wp/v2/"):
            wp_hits.append(f"Endpoint: {path} (WordPress REST)")

    wp_hits = list(dict.fromkeys(wp_hits))

    if len(wp_hits) >= 2:
        msg = (
            "Strong evidence of a real WordPress installation based on multiple indicators: "
            f"{wp_hits[:5]}."
        )
    elif len(wp_hits) == 1:
        msg = (
            "Single indicator suggests possible WordPress usage: "
            f"{wp_hits[0]}. Additional manual verification is recommended."
        )
    else:
        msg = "No clear evidence of a WordPress installation was found in cached data."

    reporter.log(
        check_id,
        "PASS",
        msg,
        location="WordPress",
    )

    api_roots = {}
    api_patterns = [
        "/wp-json",
        "/api/",
        "/v1/",
        "/v2/",
        "/rest/",
        "/graphql",
        "/odata",
    ]

    for e in raw_endpoints:
        path = e.get("path", "") if isinstance(e, dict) else str(e)
        lp = path.lower()
        for pat in api_patterns:
            if pat in lp:
                idx = lp.find(pat)
                root_path = lp[idx:]
                parts = [p for p in root_path.split("/") if p]
                if len(parts) >= 2:
                    root_key = "/" + "/".join(parts[:2])
                else:
                    root_key = "/" + parts[0]
                api_roots.setdefault(root_key, set()).add(lp)
                break

    if not api_roots:
        reporter.log(
            check_id,
            "PASS",
            "No obvious API entry points (such as /wp-json, /api, /graphql) were detected from cached endpoints.",
            location="API",
        )
    else:
        summaries = []
        for root, paths in sorted(api_roots.items()):
            resources = set()
            for p in paths:
                parts = [x for x in p.split("/") if x]
                if len(parts) >= 2:
                    resources.add(parts[-1])
            summaries.append(
                f"{root} (seen paths: {sorted(list(paths))[:5]}; "
                f"example resources: {sorted(list(resources))[:5]})"
            )
        reporter.log(
            check_id,
            "PASS",
            "API entry points inferred from cached endpoints: "
            f"{'; '.join(summaries)}. These are based on URL structure only; "
            "manual testing is required to confirm methods, auth, and allowed actions.",
            location="API",
        )

    sitemap_content = None
    sitemap_name = None
    for candidate in ["sitemap.xml", "sitemap_index.xml"]:
        if candidate in discovery_files:
            sitemap_content = discovery_files[candidate]
            sitemap_name = candidate
            break

    if not sitemap_content:
        reporter.log(
            check_id,
            "PASS",
            "No sitemap.xml or sitemap_index.xml was cached; cannot correlate sitemap entries with accessibility.",
            location="Sitemap",
        )
    else:
        confirmed = []
        unknown = []
        try:
            root = ET.fromstring(sitemap_content)
        except Exception:
            reporter.log(
                check_id,
                "PASS",
                f"{sitemap_name} is present but could not be parsed as valid XML; sitemap mapping is skipped.",
                location="Sitemap",
            )
        else:
            loc_elems = root.findall(".//{*}loc")
            for loc in loc_elems:
                url = (loc.text or "").strip()
                if not url:
                    continue
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != brain.domain:
                    continue
                path = parsed.path or "/"
                full_url = url if url in response_cache else brain.target.rstrip("/") + path
                r = response_cache.get(full_url)
                if r and r.status_code == 200 and r.text and len(r.text.strip()) > 0:
                    confirmed.append(path)
                else:
                    unknown.append(path)

            msg = (
                f"Sitemap '{sitemap_name}' contains {len(loc_elems)} URLs; "
                f"{len(confirmed)} were seen with 200 OK in cached responses "
                f"(examples: {confirmed[:5]}), "
                f"{len(unknown)} were not confirmed from cached traffic "
                f"(examples: {unknown[:5]})."
            )
            reporter.log(
                check_id,
                "PASS",
                msg,
                location="Sitemap",
            )

    root_tree = mapper_tree.get("root", {})
    top_levels = [k for k in root_tree.keys() if not k.startswith("_")]
    top_levels = sorted(top_levels)[:10]

    if not top_levels:
        reporter.log(
            check_id,
            "PASS",
            "No application paths were recorded in the mapper; application map is empty or very limited.",
            location="App map",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "Top-level application sections discovered from cached paths: "
            f"{top_levels}. See app_map.json for the full tree.",
            location="App map",
        )
