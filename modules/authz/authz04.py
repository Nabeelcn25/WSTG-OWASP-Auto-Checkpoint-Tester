import re
from urllib.parse import urlparse


def check_athz_04(brain, reporter, verifier=None):
    check_id = "WSTG-ATHZ-04"
    html = brain.html_source or ""
    parsed = urlparse(brain.target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    def to_path(u: str) -> str:
        u = (u or "").strip()
        if not u:
            return ""
        if u.startswith("http://") or u.startswith("https://"):
            p = urlparse(u)
            if p.netloc and p.netloc != brain.domain:
                return ""
            return p.path or "/"
        p = urlparse(u)
        path = p.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return path

    paths = set()

    for attr in ("src", "href"):
        for m in re.findall(rf'{attr}=["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
            path = to_path(m)
            if path:
                paths.add(path)

    for m in re.findall(r"url\((['\"]?)([^\"')]+)\1\)", html, flags=re.IGNORECASE):
        path = to_path(m[1])
        if path:
            paths.add(path)

    candidate_dirs = set()

    for p in paths:
        if "/" not in p:
            continue
        base = p.rsplit("/", 1)[0]
        if not base:
            continue
        if not base.endswith("/"):
            base += "/"
        candidate_dirs.add(base)

        tmp = base.rstrip("/")
        if "/" in tmp:
            parent = tmp.rsplit("/", 1)[0]
            if parent:
                candidate_dirs.add(parent + "/")

        m = re.search(r"(/wp-content/uploads/\d{4}/\d{2})/", p)
        if m:
            candidate_dirs.add(m.group(1) + "/")
        m2 = re.search(r"(/(?:\d{4})/(?:0[1-9]|1[0-2]))/", p)
        if m2:
            candidate_dirs.add(m2.group(1) + "/")

    candidate_dirs = sorted(candidate_dirs)[:40]
    findings = []

    for d in candidate_dirs:
        resp = brain.targeted_request(d)
        if not resp or resp.status_code != 200:
            continue
        body = (resp.text or "")[:8000].lower()
        if (
            "index of /" in body
            or "<title>index of" in body
            or "parent directory" in body
        ):
            findings.append(d)

    if findings:
        curl_cmds = [
            f"curl -s -D- -L '{origin}{d}' | head -n 40" for d in findings
        ]
        reporter.log(
            check_id,
            "FAIL",
            "Directory indexing appears enabled on paths that are referenced "
            f"from the main page: {findings}. Suggested manual checks: {curl_cmds}",
            location="dir_listing",
        )
    else:
        reporter.log(
            check_id,
            "PASS",
            "No evidence of directory indexing on asset or upload directories "
            "referenced from the main page.",
            location="dir_listing",
        )
