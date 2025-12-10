import re
from urllib.parse import urljoin


def check_info_05(brain, reporter, verifier=None):
    check_id = "WSTG-INFO-05"

    html = getattr(brain, "html_source", None)
    jsfiles = getattr(brain, "js_files", {}) or getattr(brain, "jsfiles", {}) or {}

    if not html and not jsfiles:
        reporter.log(
            check_id,
            "PASS",
            "No main HTML or front-end JavaScript captured; skipping page content leakage review.",
            location="Content",
        )
        return

    secrets = list(brain.artifacts.get("secrets", []))
    raw_comments = list(brain.artifacts.get("comments", []))
    raw_params = list(getattr(brain, "raw_artifacts", {}).get("parameters", []))
    raw_endpoints = list(getattr(brain, "raw_artifacts", {}).get("endpoints", []))

    any_issue = False

    sensitive_fragments = [
        "api",
        "key",
        "auth",
        "token",
        "secret",
        "pass",
        "pwd",
        "bearer",
        "client",
        "id",
    ]
    high_entropy = re.compile(r"[A-Za-z0-9+/]{20,}")

    secret_examples = []

    for s in secrets:
        if isinstance(s, dict):
            val = str(s.get("value", "")).strip()
            src = s.get("source", "unknown")
        else:
            val = str(s).strip()
            src = "unknown"

        if not val:
            continue

        lower = val.lower()
        present = {frag for frag in sensitive_fragments if frag in lower}

        if len(present) >= 2 or high_entropy.search(val):
            secret_examples.append(f"{val[:80]} (from {src})")
            if len(secret_examples) >= 5:
                break

    if secret_examples:
        msg = (
            "Potential secret-like values were detected in front-end sources "
            f"(examples: {secret_examples}). Manual verification is required to "
            "confirm whether these are real credentials or harmless test data."
        )
        reporter.log(check_id, "FAIL", msg, location="Secrets")
        any_issue = True
    else:
        reporter.log(
            check_id,
            "PASS",
            "No obvious API key or auth token-like values were detected in cached HTML/JS content.",
            location="Secrets",
        )

    sensitive_keywords = [
        "password",
        "passwd",
        "pwd",
        "api key",
        "apikey",
        "access key",
        "auth token",
        "bearer",
        "secret",
        "token",
        "client id",
        "client secret",
        "debug",
        "trace",
        "todo",
        "fixme",
        "sql ",
        "select ",
        "insert ",
        "update ",
        "delete ",
        "drop ",
        "internal",
        "staging",
        "admin",
        "localhost",
    ]

    internal_ip_pattern = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
    )

    leaky_comments = []

    for c in raw_comments:
        if isinstance(c, dict):
            text = (c.get("content") or "").strip()
            src = c.get("source", "unknown")
        else:
            text = str(c).strip()
            src = "unknown"

        if not text:
            continue
        lower = text.lower()

        if any(k in lower for k in sensitive_keywords) or internal_ip_pattern.search(text):
            leaky_comments.append(f"{text[:160]} (from {src})")
            if len(leaky_comments) >= 5:
                break

    if leaky_comments:
        msg = (
            "HTML/JS comments include potentially sensitive information or internal "
            f"details (examples: {leaky_comments}). Review and remove such comments "
            "from production builds if they are not required."
        )
        reporter.log(check_id, "FAIL", msg, location="Comments")
        any_issue = True

    if raw_comments:
        reporter.log(
            check_id,
            "PASS",
            f"Collected {len(raw_comments)} HTML/JS comments from page and script sources for manual review.",
            location="Comments",
        )

    sourcemap_urls = set()
    debug_named_js = set()

    for url, body in jsfiles.items():
        lower_url = (url or "").lower()

        if lower_url.endswith(".map") or ".js.map" in lower_url:
            sourcemap_urls.add(url)

        if any(tag in lower_url for tag in ("-debug.", ".debug.", "-dev.", ".dev.", "-test.", ".test.")):
            debug_named_js.add(url)

        if not body:
            continue

        m = re.search(r"sourceMappingURL=([^\s*]+)", body)
        if m:
            sm = m.group(1).strip().strip("\"'")
            if sm:
                try:
                    full = urljoin(url, sm)
                except Exception:
                    full = sm
                sourcemap_urls.add(full)

    if sourcemap_urls:
        examples = list(sorted(sourcemap_urls))[:5]
        msg = (
            "Front-end source map files appear to be exposed "
            f"(examples: {examples}). These can reveal original source code and "
            "should be reviewed before being left accessible in production."
        )
        reporter.log(check_id, "FAIL", msg, location="JS debug")
        any_issue = True

    if debug_named_js:
        examples = list(sorted(debug_named_js))[:5]
        reporter.log(
            check_id,
            "PASS",
            "JavaScript files with debug/dev-style names were identified "
            f"(examples: {examples}). Verify that these builds do not leak "
            "internal information or debug functionality.",
            location="JS debug",
        )

    core_regex = re.compile(
        r"(?i)(auth|token|secret|key|pass|pwd|session|sess|csrf|debug|admin|role|priv|env|api)"
    )

    def normalize_param(name: str) -> str:
        n = name.strip()
        n = re.sub(r"^x[_-]+", "", n, flags=re.IGNORECASE)
        n = re.sub(r"[_-]?(id|key|token|flag|mode)$", "", n, flags=re.IGNORECASE)
        return n.lower()

    sensitive_params = []
    for p in raw_params:
        pname = str(p.get("name", "")) if isinstance(p, dict) else str(p)
        if core_regex.search(pname):
            sensitive_params.append(p)

    clusters = {}
    for p in sensitive_params:
        pname = str(p.get("name", "")) if isinstance(p, dict) else str(p)
        core = normalize_param(pname)
        clusters.setdefault(core, []).append(p)

    endpoint_text = " ".join(
        str(e.get("path", "")) if isinstance(e, dict) else str(e)
        for e in raw_endpoints
    ).lower()
    comments_text = " ".join(
        ((c.get("content") or "") if isinstance(c, dict) else str(c))
        for c in raw_comments
    ).lower()

    sensitive_cluster_summaries = []

    for core, items in clusters.items():
        if not core:
            continue

        evidence = []
        if core in endpoint_text:
            evidence.append("endpoints")
        if core in comments_text:
            evidence.append("comments")

        if not evidence:
            continue

        names = sorted({str(p.get("name", "")) for p in items if isinstance(p, dict)})[:5]
        sources = sorted({str(p.get("source", "unknown")) for p in items if isinstance(p, dict)})[:5]

        summary = {
            "core": core,
            "names": names,
            "sources": sources,
            "evidence": evidence,
        }
        sensitive_cluster_summaries.append(summary)

    if sensitive_cluster_summaries:
        any_issue = True
        parts = []
        for s in sensitive_cluster_summaries[:5]:
            parts.append(
                f"core '{s['core']}': params {s['names']} "
                f"(from {s['sources']}, seen in {', '.join(s['evidence'])})"
            )
        msg = (
            "Cached parameter and endpoint names suggest potentially sensitive controls "
            "exposed in front-end context. Examples: "
            f"{'; '.join(parts)}. Review whether these can be abused or should be renamed or hidden."
        )
        reporter.log(check_id, "FAIL", msg, location="Param names")
    elif raw_params:
        reporter.log(
            check_id,
            "PASS",
            "Collected parameter names from cached HTML/JS and headers; no strong "
            "clusters of sensitive-looking names were detected beyond generic usage.",
            location="Param names",
        )

    if not any_issue:
        reporter.log(
            check_id,
            "PASS",
            "No obvious information leakage was detected in cached HTML/JS content, "
            "secret-like patterns, comments, debug artifacts, or parameter clusters.",
            location="Summary",
        )
