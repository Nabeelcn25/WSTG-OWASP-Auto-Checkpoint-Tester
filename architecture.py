#!/usr/bin/env python3

import os
import re
import json
import subprocess
import time

import requests
import urllib3

from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"
COLOR_BOLD = "\033[1m"


class CodeAnalyzer:
    def __init__(self):
        self.sensitive_keywords = [
            "admin", "login", "signin", "register", "signup", "dashboard",
            "dash", "config", "auth", "token", "secret", "user", "account",
            "internal", "backup", "db_pass", "staging", "prod",
        ]
        self.patterns = {
            "fuzzy_secret": (
                r"(?i)(api[_\-]?key|auth[_\-]?token|access[_\-]?token|"
                r"secret[_\-]?key|aws[_\-]?key|bearer[_\-]?token)[\"']?\s*[:=]\s*[\"']"
                r"([a-zA-Z0-9_\-]{20,})[\"']"
            ),
            "comments": {
                "html": r"<!--[\s\S]*?-->",
                "js_single": r"\/\/.*",
                "js_multi": r"\/\*[\s\S]*?\*\/",
                "hash": r"(^|\s)#.*",
                "docstring": r"\"{3}[\s\S]*?\"{3}",
            },
            "endpoint": r"[\"'](\\/[a-zA-Z0-9_\\-\\/\\.]+)[\"']",
            "form_param": r"name=[\"']?([a-zA-Z0-9_\-\[\]]+)[\"']?",
            "url_string_param": r"[?&]([a-zA-Z0-9_\\-\\[\\]]+)=",
            "json_param": r"[\"']([a-zA-Z0-9_\\-]+)[\"']\s*:\s*",
        }

    def analyze_text(self, text: str, source_url: str = ""):
        findings = {
            "secrets": [],
            "endpoints": [],
            "comments": [],
            "parameters": [],
            "source": source_url,
        }

        for match in re.finditer(self.patterns["fuzzy_secret"], text):
            findings["secrets"].append(
                {
                    "value": f"{match.group(1)}: {match.group(2)}",
                    "source": source_url,
                }
            )

        for c_type, pattern in self.patterns["comments"].items():
            if not pattern:
                continue
            for match in re.finditer(pattern, text, re.DOTALL):
                clean = match.group(0).strip()
                if len(clean) > 4:
                    findings["comments"].append(
                        {
                            "type": c_type,
                            "content": clean,
                            "source": source_url,
                        }
                    )

        for match in re.finditer(self.patterns["endpoint"], text):
            findings["endpoints"].append(
                {
                    "path": match.group(1),
                    "source": source_url,
                }
            )

        for match in re.finditer(self.patterns["form_param"], text):
            findings["parameters"].append(
                {
                    "kind": "FORM",
                    "name": match.group(1),
                    "source": source_url,
                }
            )

        for match in re.finditer(self.patterns["url_string_param"], text):
            findings["parameters"].append(
                {
                    "kind": "URL",
                    "name": match.group(1),
                    "source": source_url,
                }
            )

        for match in re.finditer(self.patterns["json_param"], text):
            findings["parameters"].append(
                {
                    "kind": "JSON",
                    "name": match.group(1),
                    "source": source_url,
                }
            )

        return findings


class AppMapper:
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
        self.nodes = {}

    def add_node(self, url: str, status: int, content_type: str, size: int):
        if self.base_domain not in url:
            return
        parsed = urlparse(url)
        path = parsed.path if parsed.path else "/"
        self.nodes[path] = {
            "status": status,
            "type": content_type.split(";")[0] if content_type else "unknown",
            "size": size,
            "params": list(parse_qs(parsed.query).keys()),
        }

    def generate_tree(self):
        tree = {"root": {}}
        for path, data in self.nodes.items():
            parts = [p for p in path.strip("/").split("/") if p]
            current = tree["root"]
            for part in parts:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current["_meta"] = data
        return tree


class AI_Verifier:
    def __init__(self):
        self.provider = None
        self.api_key = None
        self.enabled = False
        self._load_config()

    def _load_config(self):
        if os.path.exists(".api_keys"):
            with open(".api_keys", "r") as f:
                for line in f:
                    if "=" in line and not line.strip().startswith("#"):
                        prov, key = line.strip().split("=", 1)
                        self.provider = prov.lower()
                        self.api_key = key.strip()
                        self.enabled = True
                        return
        # fallback: disabled
        self.provider = None
        self.api_key = None
        self.enabled = False

    def verify_secret(self, snippet: str) -> str:
        if not self.enabled:
            return "SKIPPED"
        prompt = (
            f"Analyze code snippet: '{snippet}'. "
            f"Is it a SECURITY RISK (hardcoded secret) or HARMLESS? "
            f"Reply SENSITIVE or HARMLESS."
        )
        try:
            if self.provider == "openai":
                resp = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": "gpt-4-turbo",
                        "messages": [{"role": "user", "content": prompt}],
                    },
                    timeout=15,
                )
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception:
            return "AI_ERROR"
        return "UNKNOWN"


class TargetBrain:
    def __init__(self, target_url: str, verbose: bool = False):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.domain = urlparse(self.target).netloc

        self.verbose = verbose
        self.rate_delay = 0.5

        self.analyzer = CodeAnalyzer()
        self.mapper = AppMapper(self.domain)

        self.artifacts = {
            "secrets": [],
            "endpoints": set(),
            "comments": [],
            "technologies": set(),
            "parameters": set(),
        }
        self.raw_artifacts = {
            "endpoints": [],
            "parameters": [],
        }

        self.discovery_files = {}
        self.whatweb_data = []
        self.main_response = None
        self.html_source = ""
        self.js_files = {}

        self.response_cache = {}
        self.http_errors = []

        self.request_log = set()

    def initialize(self):
        print(f"{COLOR_GREEN}[+]{COLOR_RESET} Brain Initialized for: {self.target}")
        self._run_external_tools()

        common_files = [
            "robots.txt",
            "sitemap.xml",
            "security.txt",
            ".well-known/security.txt",
        ]
        for f in common_files:
            self.get_standard_file(f)

        self._fetch_main()

        if self.html_source:
            self._analyze(self.html_source, "Main HTML")
        self._harvest_js()

        self._augment_technologies()
        if self.artifacts.get("technologies"):
            techs = ", ".join(sorted(self.artifacts["technologies"]))
            print(f"[*] Detected technologies: {techs}")

        self._prefetch_auth_endpoints()

    def get_standard_file(self, filename: str):
        if filename in self.discovery_files:
            return self.discovery_files[filename]

        r = self.targeted_request(filename)
        if r and r.status_code == 200 and len(r.content) > 0:
            self.discovery_files[filename] = r.text
            self._analyze(r.text, filename)
            return r.text
        return None

    def _run_external_tools(self):
        try:
            cmd = ["whatweb", "-a", "1", "--log-json", "-", self.target]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            if res.stdout.strip():
                try:
                    self.whatweb_data = json.loads(res.stdout)
                    last_scan = self.whatweb_data[-1]
                    for plugin, info in last_scan.get("plugins", {}).items():
                        if plugin not in ["Country", "IP", "Title", "RedirectLocation"]:
                            self.artifacts["technologies"].add(plugin)
                except Exception:
                    pass
        except Exception:
            pass

    def _fetch_main(self):
        try:
            r = self.targeted_request(self.target)
            if r:
                self.main_response = r
                self.html_source = r.text
        except Exception:
            pass

    def _harvest_js(self):
        if not self.html_source:
            return
        soup = BeautifulSoup(self.html_source, "html.parser")
        scripts = [
            urljoin(self.target, s.get("src"))
            for s in soup.find_all("script")
            if s.get("src")
        ]
        internal = [s for s in scripts if self.domain in s]
        for js in internal[:5]:
            try:
                r = self.targeted_request(js)
                if r and r.status_code == 200:
                    self.js_files[js] = r.text
                    self._analyze(r.text, js)
            except Exception:
                pass

    def _augment_technologies(self):
        html = self.html_source or ""
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")

        for meta in soup.find_all("meta", attrs={"name": "generator"}):
            val = (meta.get("content") or "").strip()
            if val:
                self.artifacts["technologies"].add(val)

        lower = html.lower()
        if "wp-content/" in lower or "wordpress" in lower:
            self.artifacts["technologies"].add("wordpress")

        if self.main_response is not None:
            server = self.main_response.headers.get("Server", "")
            xpb = self.main_response.headers.get("X-Powered-By", "")
            if server:
                self.artifacts["technologies"].add(server.lower())
            if xpb:
                self.artifacts["technologies"].add(xpb.lower())
            if "wordpress" in server.lower() or "wordpress" in xpb.lower():
                self.artifacts["technologies"].add("wordpress")

    def _prefetch_auth_endpoints(self):
        candidates = set()
        html = self.html_source or ""
        if html:
            soup = BeautifulSoup(html, "html.parser")
            auth_keywords = [
                "login", "logon", "signin", "sign-in", "sign_in",
                "register", "signup", "sign-up", "sign_up",
                "auth", "account", "user", "wp-login", "wp-signup",
            ]

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href:
                    continue
                url = urljoin(self.target, href)
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != self.domain:
                    continue
                path = parsed.path or "/"
                lower_path = path.lower()
                if any(k in lower_path for k in auth_keywords):
                    candidates.add(path)

            for form in soup.find_all("form", action=True):
                action = form["action"].strip()
                if not action:
                    continue
                url = urljoin(self.target, action)
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != self.domain:
                    continue
                path = parsed.path or "/"
                lower_path = path.lower()
                if any(k in lower_path for k in auth_keywords):
                    candidates.add(path)

        default_auth = {
            "/login",
            "/login/",
            "/user/login",
            "/users/login",
            "/account/login",
            "/signin",
            "/signin/",
            "/register",
            "/register/",
            "/signup",
            "/signup/",
        }

        candidates.update(default_auth)

        techs = {t.lower() for t in self.artifacts.get("technologies", [])}
        if any("wordpress" in t for t in techs):
            candidates.update(
                {
                    "/wp-login.php",
                    "/wp-login.php?action=register",
                    "/wp-signup.php",
                    "/wp-json/wp/v2/users",
                    "/wp-json/wp/v2/users/1",
                    "/wp-json/wp/v2/users/admin",
                    "/wp-json/wp/v2/users/01",
                    "/wp-admin/",
                }
            )

        norm = set()
        for p in candidates:
            parsed = urlparse(urljoin(self.target, p))
            if parsed.netloc and parsed.netloc != self.domain:
                continue
            path = parsed.path or "/"
            if not path.startswith("/"):
                path = "/" + path
            norm.add(path)

        for path in list(sorted(norm))[:40]:
            self.targeted_request(path)

    def _track(self, r: requests.Response | None):
        if not r:
            return

        self.mapper.add_node(
            r.url,
            r.status_code,
            r.headers.get("Content-Type"),
            len(r.content),
        )

        for h in r.headers:
            if h.lower() in ["server", "x-powered-by", "via"]:
                self.artifacts["parameters"].add(f"HEADER: {h}")

        if r.status_code >= 400:
            parsed = urlparse(r.url)
            entry = {
                "url": r.url,
                "path": parsed.path or "/",
                "status": r.status_code,
                "reason": getattr(r, "reason", ""),
                "content_type": r.headers.get("Content-Type"),
                "length": len(r.content),
                "snippet": (r.text or "")[:200],
            }
            self.http_errors.append(entry)

    def _analyze(self, text: str, source: str):
        res = self.analyzer.analyze_text(text, source)
        self.artifacts["secrets"].extend(res["secrets"])
        self.artifacts["comments"].extend(res["comments"])

        for e in res["endpoints"]:
            self.raw_artifacts["endpoints"].append(e)
            self.artifacts["endpoints"].add(e["path"])

        for p in res["parameters"]:
            self.raw_artifacts["parameters"].append(p)
            kind = p.get("kind", "GEN")
            name = p.get("name", "")
            self.artifacts["parameters"].add(f"{kind}: {name}")

    def targeted_request(self, path_or_url: str):
        full_url = urljoin(self.target, path_or_url)

        self.request_log.add(full_url)

        if full_url in self.response_cache:
            r = self.response_cache[full_url]
            if self.verbose:
                status = r.status_code if r is not None else "ERR"
                print(f"[CACHE] {status} {full_url}")
            return r

        if self.verbose:
            print(f"[REQ] GET {full_url}")
        if self.rate_delay:
            time.sleep(self.rate_delay)

        try:
            r = requests.get(full_url, timeout=5, verify=False)
            if self.verbose:
                print(f"[RESP] {r.status_code} {full_url}")
                for k, v in r.headers.items():
                    print(f"    {k}: {v}")
            self._track(r)
            self.response_cache[full_url] = r
            return r
        except Exception as e:
            if self.verbose:
                print(f"[ERR] {full_url} -> {e}")
            return None


class Reporter:
    def __init__(self, out_dir: str, verbose: bool = False):
        self.verbose = verbose
        self.evidences: dict[str, dict] = {}
        self.out_dir = out_dir

        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)

    def _ensure_entry(self, check_id: str):
        if check_id not in self.evidences:
            self.evidences[check_id] = {
                "status": "PASS",
                "status_color": "green",
                "proofs": [],
            }

    def log(self, check_id: str, status: str, proof: str,
            location: str = "General", ai_verdict: str | None = None):
        self._ensure_entry(check_id)

        if status == "FAIL":
            self.evidences[check_id]["status"] = "FAIL"
            self.evidences[check_id]["status_color"] = "red"

        self.evidences[check_id]["proofs"].append(
            {"proof": proof, "location": location}
        )

        is_fail = status == "FAIL" or ai_verdict == "SENSITIVE"

        if self.verbose:
            if is_fail:
                icon = f"{COLOR_RED}[!]{COLOR_RESET}"
                status_str = f"{COLOR_RED}FAIL{COLOR_RESET}"
            else:
                icon = f"{COLOR_GREEN}[+]{COLOR_RESET}"
                status_str = f"{COLOR_GREEN}PASS{COLOR_RESET}"
            print(f" {icon} {check_id} {status_str}: {proof}")
        elif is_fail:
            icon = f"{COLOR_RED}[!]{COLOR_RESET}"
            print(f" {icon} {check_id}: {proof}")

    def _owasp_sort_key(self, check_id: str):
        category_order = [
            "WSTG-INFO",
            "WSTG-CONF",
            "WSTG-IDNT",
            "WSTG-ATHN",
            "WSTG-ATHZ",
            "WSTG-INPV",
            "WSTG-ERRH",
        ]

        cat_index = len(category_order)
        for i, prefix in enumerate(category_order):
            if check_id.startswith(prefix):
                cat_index = i
                break

        m = re.search(r"(\d+)$", check_id)
        num = int(m.group(1)) if m else 0

        return (cat_index, num, check_id)

    def generate_report(self, brain: "TargetBrain"):
        evidences_path = os.path.join(self.out_dir, "evidences.json")
        app_map_path = os.path.join(self.out_dir, "app_map.json")
        params_path = os.path.join(self.out_dir, "parameters.json")
        errors_path = os.path.join(self.out_dir, "http_errors.json")
        urls_path = os.path.join(self.out_dir, "requested_urls.json")

        with open(evidences_path, "w") as f:
            json.dump(self.evidences, f, indent=2)
        with open(app_map_path, "w") as f:
            json.dump(brain.mapper.generate_tree(), f, indent=2)
        with open(params_path, "w") as f:
            json.dump(sorted(list(brain.artifacts["parameters"])), f, indent=2)

        if getattr(brain, "http_errors", None):
            with open(errors_path, "w") as f:
                json.dump(brain.http_errors, f, indent=2)

        if getattr(brain, "request_log", None):
            with open(urls_path, "w") as f:
                json.dump(sorted(list(brain.request_log)), f, indent=2)

        print(f"\n{COLOR_GREEN}[+]{COLOR_RESET} Reports saved to folder: {self.out_dir}")

        total_checks = len(self.evidences)
        failed = sum(1 for v in self.evidences.values() if v["status"] == "FAIL")
        passed = total_checks - failed

        print(f"\n{COLOR_BOLD}=== Scan Summary ==={COLOR_RESET}")
        print(f"Total checks: {total_checks}")
        print(f"{COLOR_GREEN}Passed:      {passed}{COLOR_RESET}")
        print(f"{COLOR_RED}Failed:      {failed}{COLOR_RESET}\n")

        if self.evidences:
            header = "Check ID                 Status   Proofs   First proof snippet"
            print(f"{COLOR_BOLD}{header}{COLOR_RESET}")
            print("-" * len(header))
            for check_id, data in sorted(
                self.evidences.items(),
                key=lambda kv: self._owasp_sort_key(kv[0]),
            ):
                status = data["status"]
                proofs = data.get("proofs", [])
                count = len(proofs)
                first_snippet = ""
                if proofs:
                    ptxt = proofs[0].get("proof", "")
                    first_snippet = (ptxt[:60] + "...") if len(ptxt) > 60 else ptxt

                if status == "FAIL":
                    status_col = f"{COLOR_RED}{status}{COLOR_RESET}"
                else:
                    status_col = f"{COLOR_GREEN}{status}{COLOR_RESET}"

                print(f"{check_id:<22} {status_col:<7} {count:<7} {first_snippet}")
        else:
            print("No checks were recorded.")
