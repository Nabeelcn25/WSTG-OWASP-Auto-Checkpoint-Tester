
# OWASP WSTG Scanner -- WordPress Security Testing Framework

## Legal / Ethical Notice

This tool is provided strictly for lawful security testing and
educational purposes.\
Only run it against systems and applications that you own, manage, or
have **explicit written permission** to test from the rightful owner.

Unauthorized scanning or exploitation of systems that you do not control
may violate laws, regulations, and contracts, and can result in criminal
or civil penalties.\
By using this tool, you accept full responsibility for complying with
all applicable laws and for obtaining proper authorization before
performing any tests.

------------------------------------------------------------------------

## Overview

A lightweight, modular Python scanner implementing selected OWASP Web
Security Testing Guide (WSTG) checkpoints, with a strong focus on
**WordPress** targets.\
The tool performs automated reconnaissance, configuration checks, and
produces clear guidance for deeper manual testing.

## Features

-   **WordPress-focused checks:** login/registration, REST user
    enumeration, admin interfaces, debug logs, XML-RPC, phpMyAdmin.
-   **OWASP WSTG coverage:** INFO-02/03/04, IDNT-01/02/04/05,
    ATHN-01/02/04, ATHZ-04, CONF-02/05/07, INPV-01/13, ERRH-01.
-   **Smart HTTP caching:** each URL is requested once; all checks reuse
    the cached response.
-   **Colorized console output** for PASS / FAIL.
-   **JSON reports** including evidences, app map, parameters, HTTP
    errors, requested URLs.
-   **Verbose mode** (`-v`) for full request/response logging.

## Requirements

**Python:** 3.10+\
**Packages:**

    requests>=2.31.0  
    beautifulsoup4>=4.12.0  
    urllib3>=2.0.0

Optional: - `whatweb` CLI for extra fingerprinting

## Installation

``` bash
git https://github.com/Nabeelcn25/WSTG-OWASP-Auto-Checkpoint-Tester.git
cd owasp-wstg scanner
pip3 install -r requirements.txt
```

## Usage

### Basic scan

``` bash
python3 main.py http://target.local
```

### Verbose scan

``` bash
python3 main.py http://target.local -v
```

### Run only selected INFO checks

``` bash
python3 main.py http://target.local -f info02 info03
```

### HTTPS target

``` bash
python3 main.py https://secureu.local:8443 -v
```

## Output Files

A folder named after the domain (e.g., `secureu.local:8000/`) is
created.

-   **evidences.json** -- proofs per WSTG check\
-   **app_map.json** -- hierarchical path map\
-   **parameters.json** -- discovered parameter names\
-   **http_errors.json** -- 4xx/5xx leaks\
-   **requested_urls.json** -- all requested URLs

## Architecture

### TargetBrain

Handles URL normalization, discovery (robots, sitemap), fingerprinting,
caching, prefetching, and internal mapping.

### CodeAnalyzer

Regex-based extractor for: - secrets\
- comments\
- endpoint-like strings\
- parameters

### AppMapper

Builds a tree of paths and metadata: - status\
- content type\
- size\
- parameters

### Reporter

Writes JSON reports and colorized terminal summaries.

### AI_Verifier (optional)

Classifies possible secrets using API keys from `.api_keys`.

## Implemented WSTG Checkpoints

### Information Gathering

-   **INFO-02:** Server fingerprinting\
-   **INFO-03:** Metadata files\
-   **INFO-04:** Multiple application detection

### Identification / Enumeration (WordPress)

-   **IDNT-01:** Registration page\
-   **IDNT-02:** Registration process\
-   **IDNT-04:** REST user enumeration\
-   **IDNT-05:** Username policy

### Authentication

-   **ATHN-01:** HTTP → HTTPS redirection\
-   **ATHN-02:** WordPress login presence\
-   **ATHN-04:** WordPress admin protection

### Authorization

-   **ATHZ-04:** Directory listing

### Configuration / Deployment

-   **CONF-02:** Logs and debug scripts\
-   **CONF-05:** Admin interfaces\
-   **CONF-07:** HSTS

### Input Validation & Error Handling

-   **INPV-01:** Reflected input discovery\
-   **INPV-13:** Client-side validation discovery\
-   **ERRH-01:** Error handling leaks

## Suggested Manual Workflow

After scanning: - Review **evidences.json**, focus on **FAIL** items.\
- Test suggested `curl` reproductions.\
- Use **parameters.json** for Burp/ffuf/sqlmap fuzzing.\
- Manually check: - registration flow\
- username policy\
- admin panels\
- exposed logs/debug pages\
- directory listings

## Roadmap

-   Expand parameter extraction\
-   WP plugin/theme enumeration\
-   Add more WSTG categories\
-   Async HTTP\
-   HTML/Markdown summary reports
