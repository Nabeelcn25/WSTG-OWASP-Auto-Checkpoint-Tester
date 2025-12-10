import re
from urllib.parse import urlparse


def check_info_07(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-07"

    reporter.log(
        check_id,
        "PASS",
        "For maximum coverage of execution paths, run all other checks before INFO-07 so more URLs are present in the mapper.",
        location="Run order",
    )

    tree = brain.mapper.generate_tree()
    root = tree.get("root", {})
    paths = []

    def collect_paths(node, prefix=""):
        for name, child in node.items():
            if name == "_meta":
                continue
            new_prefix = f"{prefix}/{name}".replace("//", "/")
            meta = child.get("_meta")
            if meta:
                paths.append((new_prefix, meta.get("status"), meta.get("type")))
            collect_paths(child, new_prefix)

    collect_paths(root, "")

    if not paths:
        reporter.log(
            check_id,
            "PASS",
            "No paths were recorded in the mapper; execution path mapping is not available. "
            "Use an intercepting proxy such as Burp Suite or OWASP ZAP to explore flows manually.",
            location="Execution paths",
        )
        return

    name_keywords = {
        "auth": ["login", "logon", "signin", "sign-in", "sign_in", "logout", "log-out"],
        "registration": ["register", "signup", "sign-up", "sign_up"],
        "account": ["account", "profile", "settings"],
        "shop": ["cart", "checkout", "order", "shop", "product"],
        "content": ["blog", "post", "article", "news"],
        "admin": ["admin", "dashboard", "manage", "cpanel"],
    }

    buckets = {k: [] for k in name_keywords}
    for path, status, ctype in paths:
        lp = path.lower()
        for key, kws in name_keywords.items():
            if any(k in lp for k in kws):
                buckets[key].append((path, status, ctype))

    flows = []

    if buckets["auth"]:
        home = "/"
        auth_paths = [p for p, s, t in buckets["auth"] if s in (200, 302)]
        account_paths = [p for p, s, t in buckets["account"] if s in (200, 302)]
        if auth_paths and account_paths:
            flows.append(
                f"Authentication flow example: {home} -> {auth_paths[0]} -> {account_paths[0]}"
            )

    if buckets["registration"]:
        home = "/"
        reg_paths = [p for p, s, t in buckets["registration"] if s in (200, 302)]
        if reg_paths:
            flows.append(
                f"Registration flow example: {home} -> {reg_paths[0]} (additional steps not auto-mapped)"
            )

    if buckets["shop"]:
        shop_paths = [p for p, s, t in buckets["shop"] if "cart" in p.lower() or "shop" in p.lower()]
        checkout_paths = [p for p, s, t in buckets["shop"] if "checkout" in p.lower() or "order" in p.lower()]
        if shop_paths and checkout_paths:
            flows.append(
                f"E-commerce flow example: {shop_paths[0]} -> {checkout_paths[0]}"
            )

    if not flows:
        reporter.log(
            check_id,
            "PASS",
            "Execution paths inferred from cached URLs are limited; no clear multi-step flows could be derived automatically. "
            "These heuristics are approximate only and should be validated and expanded using an intercepting proxy such as Burp Suite or OWASP ZAP.",
            location="Execution paths",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "Example execution paths inferred from cached URLs (heuristic only): "
            f"{'; '.join(flows)}. These paths are approximate and should be confirmed, refined, "
            "and extended using an intercepting proxy such as Burp Suite or OWASP ZAP.",
            location="Execution paths",
        )

    examples = [p for p, s, t in paths[:10]]
    reporter.log(
        check_id,
        "PASS",
        "Total cached paths in mapper: "
        f"{len(paths)} (example paths: {examples}). See app_map.json for full details. "
        "Use these as starting points for manual exploration in Burp Suite or OWASP ZAP.",
        location="Execution paths",
    )
