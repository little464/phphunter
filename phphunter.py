#!/usr/bin/env python3
# ============================================================
# PHPHunter v2.1
# Portable launcher-safe version
# ============================================================

import re
import sys
import argparse
import subprocess
from urllib.parse import urlparse, parse_qs, urljoin
from concurrent.futures import ThreadPoolExecutor

try:
    from curl_cffi import requests as cfreq
except ImportError:
    print("[!] curl_cffi missing. Install with:")
    print("    python3 -m pip install curl_cffi")
    sys.exit(1)

IMPERSONATE = "chrome"
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}
COOKIES = {}

TEST_MAP = {
    "id":"SQLi","id1":"SQLi","id2":"SQLi","pid":"SQLi","uid":"SQLi","cid":"SQLi","aid":"SQLi","tid":"SQLi","rid":"SQLi","sid":"SQLi",
    "cat":"SQLi","category":"SQLi","cat_id":"SQLi","category_id":"SQLi","page":"SQLi","page_id":"SQLi","p":"SQLi","post":"SQLi",
    "item":"SQLi","item_id":"SQLi","product":"SQLi","product_id":"SQLi","news":"SQLi","blog":"SQLi","article":"SQLi","user":"SQLi",
    "user_id":"SQLi","no":"SQLi","num":"SQLi","view":"SQLi","edit":"SQLi","delete":"SQLi","order":"SQLi","sort":"SQLi","sort_by":"SQLi",
    "limit":"SQLi","offset":"SQLi",
    "file":"LFI/RFI","path":"LFI/RFI","dir":"LFI/RFI","folder":"LFI/RFI","include":"LFI/RFI","load":"LFI/RFI","read":"LFI/RFI",
    "doc":"LFI/RFI","template":"LFI/RFI","lang":"LFI/RFI","module":"LFI/RFI","controller":"LFI/RFI","comp":"LFI/RFI","component":"LFI/RFI",
    "redirect":"OpenRedirect/SSRF","url":"OpenRedirect/SSRF","next":"OpenRedirect/SSRF","return":"OpenRedirect/SSRF","goto":"OpenRedirect/SSRF",
    "link":"OpenRedirect/SSRF","target":"OpenRedirect/SSRF","rurl":"OpenRedirect/SSRF","dest":"OpenRedirect/SSRF","destination":"OpenRedirect/SSRF",
    "callback":"OpenRedirect/SSRF",
    "q":"XSS","search":"XSS","query":"XSS","s":"XSS","name":"XSS","msg":"XSS","message":"XSS","text":"XSS","comment":"XSS","content":"XSS",
    "title":"XSS","keyword":"XSS",
    "cmd":"CmdInjection","exec":"CmdInjection","command":"CmdInjection","ping":"CmdInjection","host":"CmdInjection","ip":"CmdInjection",
}

SQLI_HINTS = ["id","page","cat","view","item","product","post","user","news"]
LFI_HINTS = ["file","path","dir","include","load","read","template","lang"]
REDIR_HINTS = ["redirect","url","next","return","goto","link","target"]
XSS_HINTS = ["q","search","query","name","msg","text","comment","keyword"]
CMDI_HINTS = ["cmd","exec","command","ping","host","ip"]

BRUTE_PARAMS = [
    "id","page","file","dir","cat","category","view","item","product","user","user_id","uid","pid","cid","aid","news","blog",
    "article","post","q","search","query","name","msg","redirect","url","next","return","path","read","load","include","template",
    "lang","cmd","exec","download","doc","p","edit","delete","action","type","sort","order","limit","offset","status","year",
    "month","module","option","task","menu","menu_id","ref","from","to","show","get","op","fn",
]

visited = set()
found_php = []
results = []

def req(url, timeout=12):
    try:
        r = cfreq.get(
            url, headers=HEADERS, impersonate=IMPERSONATE, timeout=timeout,
            verify=False, allow_redirects=True,
            cookies=COOKIES if COOKIES else None
        )
        return r.status_code, r.text
    except Exception:
        return None, ""

def is_same_domain(url, base_domain):
    try:
        return urlparse(url).netloc.endswith(base_domain)
    except Exception:
        return False

def crawl(start_url, depth=2):
    base_domain = urlparse(start_url).netloc
    to_visit = [(start_url, 0)]

    print(f"\n{'='*55}")
    print(f"[*] MODULE 1: PHP URLs crawl kar rahe hain (depth={depth})...")
    print(f"{'='*55}")

    while to_visit:
        url, d = to_visit.pop(0)
        if url in visited or d > depth:
            continue
        visited.add(url)

        code, html = req(url)
        if code is None or not html:
            continue

        links = re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I)
        links += re.findall(r"href='([^'#+]+)'", html, re.I)

        for link in links:
            full = urljoin(url, link).split("#")[0].strip()
            if not full.startswith("http"):
                continue
            if not is_same_domain(full, base_domain):
                continue
            if full not in visited:
                to_visit.append((full, d + 1))

        php_links = [
            l for l in set(links)
            if ".php" in l.lower() and is_same_domain(urljoin(url, l), base_domain)
        ]
        for pl in php_links:
            full_pl = urljoin(url, pl).split("#")[0]
            if full_pl not in [f[0] for f in found_php]:
                found_php.append((full_pl, url))
                print(f"  [+] PHP URL: {full_pl}")

    print(f"\n[+] Total {len(found_php)} PHP URLs mile, {len(visited)} pages crawl hue")
    if not found_php:
        found_php.append((start_url, "direct"))

def extract_params_from_url(url):
    try:
        return list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []

def extract_params_from_js(page_url, html):
    params = set()
    js_links = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
    for js in js_links[:10]:
        js_url = urljoin(page_url, js)
        code, content = req(js_url)
        if code is None or not content:
            continue
        found = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', content)
        found += re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,25})["\']\s*[:=]', content)
        for p in found:
            if p.lower() not in ("true","false","null","function","return","var","this","window","document","const"):
                params.add(p)
    return params

def brute_force_params(base_url):
    code, base_text = req(base_url)
    if code is None:
        return []
    base_len = len(base_text)

    def test(param):
        c, t = req(base_url + ("&" if "?" in base_url else "?") + param + "=test123")
        if c is None:
            return None
        if c != code or abs(len(t) - base_len) > 50:
            return param
        return None

    found = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        for res in ex.map(test, BRUTE_PARAMS):
            if res:
                found.append(res)
    return found

def get_tests(param):
    p = param.lower()
    tests = set()
    if p in TEST_MAP:
        tests.add(TEST_MAP[p])
    else:
        if any(h in p for h in SQLI_HINTS): tests.add("SQLi")
        if any(h in p for h in LFI_HINTS): tests.add("LFI/RFI")
        if any(h in p for h in REDIR_HINTS): tests.add("OpenRedirect/SSRF")
        if any(h in p for h in XSS_HINTS): tests.add("XSS")
        if any(h in p for h in CMDI_HINTS): tests.add("CmdInjection")
        if not tests:
            tests.add("XSS + Fuzzing (unknown param)")
    return sorted(tests)

def how_to_test(test_type):
    guides = {
        "SQLi": "    - Manual: test only on systems you own or are authorized to assess.\n    - sqlmap: sqlmap -u \"URL\" -p PARAM --batch --level=3 --risk=2",
        "XSS": "    - Test only with authorization; verify whether input is reflected/encoded.",
        "LFI/RFI": "    - Test only with authorization; use harmless, controlled files.",
        "OpenRedirect/SSRF": "    - Test only with authorization and controlled endpoints.",
        "CmdInjection": "    - Test only with authorization and non-destructive validation.",
        "XSS + Fuzzing (unknown param)": "    - First understand the parameter's behavior; fuzz only authorized targets.",
    }
    return guides.get(test_type, "")

def run_sqlmap(sqli_urls):
    print(f"\n{'='*55}")
    print("[*] MODULE 4: SQLmap AUTO-RUN mode")
    print(f"{'='*55}")

    for full, p in sqli_urls:
        print(f"\n[*] sqlmap running on: {full}")
        print(f"{'-'*55}")
        try:
            subprocess.run([
                "sqlmap", "-u", full, "-p", p,
                "--batch", "--level=3", "--risk=2", "--dbs",
                "--threads=5", "--random-agent"
            ])
        except FileNotFoundError:
            print("[!] sqlmap install nahi hai. Chalao: sudo apt install sqlmap")
            return

def main():
    banner = r"""
   ____  ____  _    _   _ _
  |  _ \|  _ \| |  | | | | |
  | |_) | | | | |  | | | | |
  |  __/| |_| | |__| |_| |
  |_|    |____/|_____\___/|
   PHP Hunter v2.1 [Crawl + Params + Vuln Advisor + Auto SQLmap]
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="PHPHunter v2.1 - PHP URL/parameter reconnaissance helper"
    )
    parser.add_argument("target", nargs="?", default=None)
    parser.add_argument("-u", "--url", default=None)
    parser.add_argument("-d", "--depth", type=int, default=2)
    parser.add_argument("-o", "--output")
    parser.add_argument("--no-crawl", action="store_true")
    parser.add_argument("--no-js", action="store_true")
    parser.add_argument("--auto-sqlmap", action="store_true")
    args = parser.parse_args()

    target = args.url if args.url else args.target
    if not target:
        print("[!] URL do bhai! Example: hunt https://example.com")
        sys.exit(1)

    start_url = target.rstrip("/")

    if args.no_crawl:
        found_php.append((start_url, "direct"))
    else:
        crawl(start_url, args.depth)

    print(f"\n{'='*55}")
    print("[*] MODULE 2+3: Params nikal rahe hain + Test advice bana rahe hain...")
    print(f"{'='*55}")

    for target_url, source in found_php:
        clean_url = target_url.split("?")[0]
        params = extract_params_from_url(target_url)

        code, html = req(clean_url)
        if code is None:
            print(f"  [!] Skip (unreachable): {clean_url}")
            continue

        print(f"\n  [*] Testing: {clean_url} (Status: {code})")

        if not args.no_js and html:
            js_params = extract_params_from_js(clean_url, html)
            params = list(dict.fromkeys(params + sorted(js_params)))

        if not params:
            print("    [*] Koi param nahi mila, brute-force kar rahe hain...")
            bf_params = brute_force_params(clean_url)
            params = list(dict.fromkeys(params + bf_params))

        if not params:
            print("    [-] Koi active param nahi mila is URL pe")
            continue

        print(f"    [+] {len(params)} params: {', '.join(params)}")
        url_entry = {"url": clean_url, "params": []}

        for p in params:
            url_entry["params"].append({"param": p, "tests": get_tests(p)})
        results.append(url_entry)

    print(f"\n\n{'='*55}")
    print("[+] FINAL REPORT: Kis URL pe KON SA test karna hai")
    print(f"{'='*55}\n")

    report_lines = []
    sqli_urls = []

    for entry in results:
        print(f"[*] URL: {entry['url']}")
        report_lines.append(f"\n[*] URL: {entry['url']}")
        for pe in entry["params"]:
            tests_str = ", ".join(pe["tests"])
            print(f"    Param: ?{pe['param']}=  ==> TEST KARO: {tests_str}")
            report_lines.append(f"    Param: ?{pe['param']}=  ==> {tests_str}")

            for t in pe["tests"]:
                guide = how_to_test(t)
                if guide:
                    print(guide)
                    report_lines.append(guide)

            if "SQLi" in pe["tests"]:
                sqli_urls.append((f"{entry['url']}?{pe['param']}=1", pe["param"]))
        print()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"[*] Report saved: {args.output}")

    if sqli_urls:
        print(f"{'='*55}")
        print(f"[+] SQLMAP READY COMMANDS ({len(sqli_urls)} candidates):")
        print(f"{'='*55}")
        for full, p in sqli_urls:
            print(f'  sqlmap -u "{full}" -p {p} --batch --level=3 --risk=2 --dbs')
    else:
        print("\n[-] Koi SQLi candidate nahi mila is scan me.")

    if sqli_urls and args.auto_sqlmap:
        run_sqlmap(sqli_urls)

    print("\n[+] Scan complete! Happy hunting bhai \\m//")

if __name__ == "__main__":
    main()

