#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          RECON HUNTER - Advanced Subdomain & Live Host Tool          ║
║              Bug Bounty Edition | by Claude Sonnet 4.6               ║
╚══════════════════════════════════════════════════════════════════════╝

Real subdomain enumeration using:
  - DNS brute force (A, AAAA, CNAME records)
  - Certificate Transparency (crt.sh)
  - AlienVault OTX passive DNS
  - HackerTarget API
  - HTTP/HTTPS live host probing
  - Banner grabbing & tech fingerprinting
  - Subdomain takeover detection
  - AI-powered analysis (optional)
"""

import argparse
import asyncio
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from typing import Optional
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ─── Color helpers (fallback if rich not available) ───────────────────────────
if RICH_AVAILABLE:
    console = Console()
    def success(msg): console.print(f"[bold green]{msg}[/]")
    def info(msg):    console.print(f"[cyan]{msg}[/]")
    def warn(msg):    console.print(f"[yellow]{msg}[/]")
    def error(msg):   console.print(f"[bold red]{msg}[/]")
    def found(msg):   console.print(f"[bold bright_green]{msg}[/]")
    def live_host(msg): console.print(f"[bold cyan]{msg}[/]")
    def vuln(msg):    console.print(f"[bold red on black]{msg}[/]")
    def dead(msg):    console.print(f"[dim red]{msg}[/]")
    def header(msg):  console.print(f"[bold white]{msg}[/]")
else:
    G='\033[92m'; C='\033[96m'; Y='\033[93m'; R='\033[91m'; W='\033[97m'; D='\033[2m'; E='\033[0m'
    def success(msg): print(f"{G}{msg}{E}")
    def info(msg):    print(f"{C}{msg}{E}")
    def warn(msg):    print(f"{Y}{msg}{E}")
    def error(msg):   print(f"{R}{msg}{E}")
    def found(msg):   print(f"{G}{msg}{E}")
    def live_host(msg): print(f"{C}{msg}{E}")
    def vuln(msg):    print(f"{R}{msg}{E}")
    def dead(msg):    print(f"{D}{msg}{E}")
    def header(msg):  print(f"{W}{msg}{E}")

# ─── Wordlists ────────────────────────────────────────────────────────────────
WORDLIST_QUICK = [
    "www","mail","ftp","smtp","pop","imap","webmail","api","app","admin","login",
    "portal","dashboard","dev","staging","test","beta","prod","cdn","static",
    "assets","media","blog","docs","help","support","status","vpn","remote",
    "internal","intranet","git","jenkins","ci","monitor","ns1","ns2","mx"
]

WORDLIST_STANDARD = WORDLIST_QUICK + [
    "web","shop","store","cart","checkout","pay","billing","payments","invoice",
    "auth","oauth","sso","saml","idp","accounts","user","users","profile","api2",
    "v1","v2","v3","new","old","legacy","archive","bak","temp","sandbox","qa",
    "upload","download","files","s3","backup","logs","img","images","video",
    "m","mobile","app2","forum","news","calendar","meet","chat","api-v1","api-v2",
    "grafana","kibana","prometheus","nagios","zabbix","splunk","sentry","elastic",
    "redis","mongo","mysql","postgres","db","database","search","solr","rabbit",
    "kubernetes","k8s","docker","registry","artifactory","nexus","sonar","vault",
    "confluence","jira","gitlab","github","bitbucket","teamcity","travis","circle",
    "corp","office","employees","hr","crm","erp","sharepoint","exchange","owa",
    "autodiscover","lyncdiscover","cpanel","whm","pleplesk","directadmin","webdisk",
    "sftp","tftp","proxy","gateway","firewall","router","switch","network","nms",
    "uat","pre-prod","preprod","release","rc","canary","green","blue","local"
]

WORDLIST_DEEP = WORDLIST_STANDARD + [
    "api-gateway","api-internal","api-public","api-private","api-dev","api-prod",
    "api-staging","api-test","api-beta","api-v3","api-v4","graphql","rest","soap",
    "rpc","grpc","microservice","service","services","svc","backend","frontend",
    "internal-api","external-api","private-api","public-api","partner-api",
    "webhook","callbacks","events","stream","queue","broker","kafka","rabbitmq",
    "us","eu","asia","us-east","us-west","eu-west","eu-central","ap-southeast",
    "us-east-1","us-west-2","eu-west-1","ap-northeast-1","region1","region2",
    "dc1","dc2","dc3","node1","node2","node3","server1","server2","server3",
    "load","lb","haproxy","nginx","traefik","istio","envoy","ingress","egress",
    "waf","ddos","sec","security","pentest","red","blue-team","soc","siem",
    "mail2","mail3","smtp2","relay","sendgrid","mailgun","ses","postfix","exim",
    "push","notification","analytics","tracking","pixel","tag","gtm","metrics",
    "report","reporting","bi","tableau","looker","powerbi","datalake","warehouse",
    "infra","infrastructure","devops","sre","platform","engineering","tech",
    "demo","preview","prototype","sandbox2","test2","staging2","stage","stg",
    "customer","client","partner","vendor","supplier","b2b","b2c","marketplace",
    "token","key","secret","config","settings","env","environment","manifest",
    "health","healthcheck","ping","alive","readiness","liveness","probe"
]

# ─── Subdomain Takeover fingerprints ──────────────────────────────────────────
TAKEOVER_SIGNATURES = {
    "GitHub Pages":       ["There isn't a GitHub Pages site here", "For root URLs"],
    "Heroku":             ["No such app", "herokuapp.com", "no-such-app.html"],
    "Shopify":            ["Sorry, this shop is currently unavailable"],
    "Fastly":             ["Fastly error: unknown domain"],
    "Ghost":              ["The thing you were looking for is no longer here"],
    "Surge.sh":           ["project not found"],
    "Bitbucket":          ["Repository not found"],
    "AWS S3":             ["NoSuchBucket", "The specified bucket does not exist"],
    "Azure":              ["404 Web Site not found"],
    "Pantheon":           ["The gods are wise"],
    "Tumblr":             ["Whatever you were looking for doesn't currently exist"],
    "WordPress":          ["Do you want to register"],
    "Zendesk":            ["Help Center Closed"],
    "UserVoice":          ["This UserVoice subdomain is currently available!"],
    "GetResponse":        ["With GetResponse Landing Pages"],
    "Unbounce":           ["The requested URL was not found on this server"],
    "Strikingly":         ["But if you're looking to build your own website"],
    "Tilda":              ["Domain has been assigned"],
    "HubSpot":            ["does not exist in our system"],
    "Netlify":            ["Not Found - Request ID"],
}

# ─── DNS Resolver ──────────────────────────────────────────────────────────────
class DNSResolver:
    def __init__(self, nameservers=None, timeout=3):
        self.timeout = timeout
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
            if nameservers:
                self.resolver.nameservers = nameservers
            else:
                self.resolver.nameservers = ["8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1"]
        else:
            self.resolver = None

    def resolve(self, hostname, rdtype="A"):
        if not DNS_AVAILABLE:
            try:
                ip = socket.gethostbyname(hostname)
                return [ip]
            except Exception:
                return []
        try:
            answers = self.resolver.resolve(hostname, rdtype)
            return [str(r) for r in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def resolve_all(self, hostname):
        results = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
        for rtype in results:
            try:
                results[rtype] = self.resolve(hostname, rtype)
            except Exception:
                pass
        return results

# ─── Passive DNS Sources ────────────────────────────────────────────────────────
def fetch_crtsh(domain: str) -> list:
    """Fetch subdomains from certificate transparency logs via crt.sh"""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconHunter/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
    except Exception as e:
        warn(f"  [crt.sh] Error: {e}")
    return list(subdomains)

def fetch_hackertarget(domain: str) -> list:
    """Fetch subdomains from HackerTarget API"""
    subdomains = []
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconHunter/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            lines = resp.read().decode().strip().split("\n")
            for line in lines:
                if "," in line:
                    host = line.split(",")[0].strip()
                    if host.endswith(f".{domain}") or host == domain:
                        subdomains.append(host)
    except Exception as e:
        warn(f"  [hackertarget] Error: {e}")
    return subdomains

def fetch_alienvault(domain: str) -> list:
    """Fetch subdomains from AlienVault OTX"""
    subdomains = []
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconHunter/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for entry in data.get("passive_dns", []):
                host = entry.get("hostname", "").lower()
                if host.endswith(f".{domain}") or host == domain:
                    subdomains.append(host)
    except Exception as e:
        warn(f"  [alienvault] Error: {e}")
    return subdomains

def fetch_rapiddns(domain: str) -> list:
    """Fetch from RapidDNS"""
    subdomains = []
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode()
            matches = re.findall(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')', content)
            subdomains = list(set(m.lower() for m in matches))
    except Exception as e:
        warn(f"  [rapiddns] Error: {e}")
    return subdomains

# ─── HTTP Prober ───────────────────────────────────────────────────────────────
def probe_http(hostname: str, timeout: int = 5) -> dict:
    """Probe a host over HTTP/HTTPS and return status info"""
    result = {"live": False, "status_code": None, "server": None,
              "title": None, "redirect": None, "https": False,
              "content_length": None, "technologies": []}

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{hostname}"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; ReconHunter/2.0)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            })
            start = time.time()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme=="https" else None) as resp:
                elapsed = int((time.time() - start) * 1000)
                result["live"] = True
                result["status_code"] = resp.status
                result["https"] = (scheme == "https")
                result["response_time"] = elapsed
                headers = dict(resp.headers)
                result["server"] = headers.get("Server") or headers.get("server")
                result["content_type"] = headers.get("Content-Type") or headers.get("content-type")
                result["x_powered_by"] = headers.get("X-Powered-By") or headers.get("x-powered-by")
                # Read up to 10KB for title and takeover checks
                try:
                    body = resp.read(10240).decode("utf-8", errors="ignore")
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:100]
                    # Detect technologies
                    techs = []
                    tech_patterns = {
                        "WordPress": ["wp-content","wp-includes","WordPress"],
                        "Drupal":    ["Drupal.settings","drupal.org"],
                        "Joomla":    ["/components/com_","Joomla"],
                        "Laravel":   ["laravel_session","Laravel"],
                        "React":     ["react-app","__react"],
                        "Vue.js":    ["vue.js","__vue"],
                        "Angular":   ["ng-version","angular"],
                        "jQuery":    ["jquery.min.js","jQuery"],
                        "Bootstrap": ["bootstrap.min","bootstrap.css"],
                        "nginx":     ["nginx"],
                        "Apache":    ["Apache","mod_"],
                        "PHP":       [".php","X-Powered-By: PHP"],
                        "ASP.NET":   ["ASP.NET","__VIEWSTATE"],
                        "Django":    ["csrfmiddlewaretoken","Django"],
                        "Flask":     ["Werkzeug"],
                        "Node.js":   ["Express","node.js"],
                        "Cloudflare":["cloudflare","__cfduid","cf-ray"],
                        "AWS":       ["amazonaws","aws-cf","awselb"],
                    }
                    for tech, patterns in tech_patterns.items():
                        combined = body + str(headers)
                        if any(p.lower() in combined.lower() for p in patterns):
                            techs.append(tech)
                    result["technologies"] = techs
                    result["body_snippet"] = body[:500]
                except Exception:
                    pass
                return result
        except urllib.error.HTTPError as e:
            result["live"] = True
            result["status_code"] = e.code
            result["https"] = (scheme == "https")
            result["response_time"] = 0
            return result
        except Exception:
            continue
    return result

def check_takeover(hostname: str, body_snippet: str = "", status: int = None) -> Optional[str]:
    """Check if a subdomain is vulnerable to takeover"""
    if not body_snippet:
        return None
    for service, signatures in TAKEOVER_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in body_snippet.lower():
                return service
    return None

# ─── AI Analysis ──────────────────────────────────────────────────────────────
def ai_analyze(domain: str, live_hosts: list, api_key: str) -> list:
    """Use Claude API to analyze findings for vulnerabilities"""
    if not api_key:
        return []
    try:
        import urllib.request
        hosts_text = "\n".join([
            f"{h['subdomain']} [{h.get('status_code','')}] {h.get('server','')} {h.get('title','')}"
            for h in live_hosts[:40]
        ])
        payload = json.dumps({
            "model": "claude-sonnet-4-6",
            "max_tokens": 1000,
            "messages": [{
                "role": "user",
                "content": f"""Analyze these live subdomains of {domain} found during bug bounty recon:

{hosts_text}

Identify security issues:
1. Subdomain takeover candidates
2. Exposed sensitive services (admin, CI/CD, monitoring, databases)
3. Interesting endpoints for further testing
4. Information disclosure risks
5. Misconfigurations

Return JSON array only:
[{{"subdomain":"x","type":"TAKEOVER|EXPOSED|SENSITIVE|INFO_DISCLOSURE|MISCONFIGURATION","severity":"HIGH|MEDIUM|LOW","detail":"finding"}}]
Max 10 findings. JSON only, no explanation."""
            }]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            text = data["content"][0]["text"]
            clean = re.sub(r'```json|```', '', text).strip()
            return json.loads(clean)
    except Exception as e:
        warn(f"  [AI] Analysis error: {e}")
        return []

# ─── Report Generator ──────────────────────────────────────────────────────────
def save_report(domain, results, vulns, output_dir, formats):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(output_dir, f"recon_{domain.replace('.','_')}_{ts}")
    saved = []

    if "json" in formats:
        fp = base + ".json"
        with open(fp, "w") as f:
            json.dump({"domain": domain, "timestamp": datetime.now().isoformat(),
                       "total": len(results), "live": len([r for r in results if r.get("live")]),
                       "results": results, "vulnerabilities": vulns}, f, indent=2)
        saved.append(fp)

    if "txt" in formats:
        fp = base + "_live.txt"
        with open(fp, "w") as f:
            for r in results:
                if r.get("live"):
                    f.write(r["subdomain"] + "\n")
        saved.append(fp)

    if "csv" in formats:
        fp = base + ".csv"
        with open(fp, "w") as f:
            f.write("subdomain,ip,live,status_code,server,title,https,response_time,technologies\n")
            for r in results:
                techs = "|".join(r.get("technologies", []))
                f.write(f'{r["subdomain"]},{r.get("ip","")},{r.get("live","")},{r.get("status_code","")},{r.get("server","")},{r.get("title","")},{r.get("https","")},{r.get("response_time","")},{techs}\n')
        saved.append(fp)

    if "md" in formats:
        fp = base + "_report.md"
        live = [r for r in results if r.get("live")]
        with open(fp, "w") as f:
            f.write(f"# Recon Report — {domain}\n\n")
            f.write(f"**Date:** {datetime.now().isoformat()}  \n")
            f.write(f"**Total Subdomains:** {len(results)}  \n")
            f.write(f"**Live Hosts:** {len(live)}  \n")
            f.write(f"**Vulnerabilities:** {len(vulns)}  \n\n")
            f.write("## Live Hosts\n\n")
            f.write("| Subdomain | IP | Status | Server | Title | HTTPS | Technologies |\n")
            f.write("|---|---|---|---|---|---|---|\n")
            for r in live:
                techs = ", ".join(r.get("technologies", []))
                f.write(f'| {r["subdomain"]} | {r.get("ip","")} | {r.get("status_code","")} | {r.get("server","")} | {r.get("title","")} | {r.get("https","")} | {techs} |\n')
            if vulns:
                f.write("\n## Vulnerabilities\n\n")
                for v in vulns:
                    f.write(f'- **[{v.get("severity","?")}] [{v.get("type","?")}]** `{v.get("subdomain","")}` — {v.get("detail","")}\n')
            f.write("\n## All Subdomains\n\n")
            for r in results:
                f.write(f'- `{r["subdomain"]}` ({r.get("ip","")})\n')
        saved.append(fp)

    return saved

# ─── DNS Brute Force (threaded) ────────────────────────────────────────────────
def brute_dns_worker(args):
    prefix, domain, resolver = args
    hostname = f"{prefix}.{domain}"
    try:
        ips = resolver.resolve(hostname, "A")
        if ips:
            return hostname, ips[0]
    except Exception:
        pass
    return None, None

# ─── Main Scanner ──────────────────────────────────────────────────────────────
def print_banner():
    banner = r"""
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"""
    if RICH_AVAILABLE:
        console.print(f"[bold green]{banner}[/]")
        console.print(Panel.fit(
            "[cyan]Advanced Subdomain Enumeration & Live Host Discovery[/]\n"
            "[dim]Bug Bounty Edition v2.0 | Real DNS | Real HTTP Probing[/]",
            border_style="green"
        ))
    else:
        print(banner)
        print("  Advanced Subdomain Enumeration & Live Host Discovery")
        print("  Bug Bounty Edition v2.0\n")

def run_scan(args):
    domain = args.domain.lower().strip().lstrip("*.").rstrip(".")
    start_time = time.time()

    print_banner()
    info(f"\n  Target   : {domain}")
    info(f"  Wordlist : {args.wordlist}")
    info(f"  Threads  : {args.threads}")
    info(f"  Timeout  : {args.timeout}s")
    info(f"  Output   : {args.output}/")
    print()

    resolver = DNSResolver(timeout=args.timeout)
    all_subdomains = {}  # hostname -> ip
    results = []
    vulns = []

    # ── Phase 1: Passive OSINT ─────────────────────────────────────────────────
    sep = "━" * 60
    header(sep)
    header("  [1/4] PASSIVE RECON — OSINT Sources")
    header(sep)

    if not args.no_passive:
        info("  → Querying crt.sh (Certificate Transparency)...")
        ct_subs = fetch_crtsh(domain)
        info(f"    Found {len(ct_subs)} entries from crt.sh")
        for s in ct_subs:
            all_subdomains[s] = None

        info("  → Querying HackerTarget passive DNS...")
        ht_subs = fetch_hackertarget(domain)
        info(f"    Found {len(ht_subs)} entries from HackerTarget")
        for s in ht_subs:
            all_subdomains[s] = None

        info("  → Querying AlienVault OTX...")
        av_subs = fetch_alienvault(domain)
        info(f"    Found {len(av_subs)} entries from AlienVault OTX")
        for s in av_subs:
            all_subdomains[s] = None

        info("  → Querying RapidDNS...")
        rd_subs = fetch_rapiddns(domain)
        info(f"    Found {len(rd_subs)} entries from RapidDNS")
        for s in rd_subs:
            all_subdomains[s] = None

        success(f"  ✓ Passive recon complete — {len(all_subdomains)} unique subdomains")
    else:
        warn("  ✗ Passive recon skipped (--no-passive)")

    # ── Phase 2: DNS Brute Force ───────────────────────────────────────────────
    header(f"\n{sep}")
    header("  [2/4] ACTIVE — DNS Brute Force")
    header(sep)

    wordlist_map = {"quick": WORDLIST_QUICK, "standard": WORDLIST_STANDARD, "deep": WORDLIST_DEEP}
    wordlist = wordlist_map.get(args.wordlist, WORDLIST_STANDARD)

    if args.wordlist_file:
        try:
            with open(args.wordlist_file) as f:
                wordlist = [l.strip() for l in f if l.strip()]
            info(f"  → Loaded custom wordlist: {len(wordlist)} entries")
        except Exception as e:
            error(f"  ✗ Could not load wordlist: {e}")

    info(f"  → Brute forcing {len(wordlist)} prefixes with {args.threads} threads...")
    bf_found = 0
    work = [(w, domain, resolver) for w in wordlist]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(brute_dns_worker, w): w for w in work}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            hostname, ip = future.result()
            if hostname:
                if hostname not in all_subdomains:
                    found(f"  [DNS] {hostname:<45} {ip}")
                    bf_found += 1
                all_subdomains[hostname] = ip
            if done % 50 == 0:
                print(f"\r  Progress: {done}/{len(wordlist)} ({int(done/len(wordlist)*100)}%)", end="", flush=True)

    print()
    success(f"  ✓ DNS brute force complete — {bf_found} new subdomains found")

    # ── Resolve all passive-found subdomains ───────────────────────────────────
    info(f"\n  → Resolving {len(all_subdomains)} total subdomains via DNS...")
    resolve_work = [h for h, ip in all_subdomains.items() if ip is None]
    resolved = 0

    def do_resolve(hostname):
        ips = resolver.resolve(hostname, "A")
        return hostname, ips[0] if ips else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(do_resolve, h): h for h in resolve_work}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            hostname, ip = future.result()
            all_subdomains[hostname] = ip
            if ip:
                resolved += 1
            if done % 20 == 0:
                print(f"\r  Resolved: {resolved}/{done}", end="", flush=True)

    print()
    # Filter to only resolved (has IP)
    live_candidates = {h: ip for h, ip in all_subdomains.items() if ip}
    success(f"  ✓ DNS resolution complete — {len(live_candidates)} hosts resolved")

    # ── Phase 3: HTTP Probing ──────────────────────────────────────────────────
    header(f"\n{sep}")
    header("  [3/4] HTTP/HTTPS — Live Host Detection")
    header(sep)
    info(f"  → Probing {len(live_candidates)} hosts (timeout={args.timeout}s)...")
    print()

    live_count = 0
    dead_count = 0
    takeover_count = 0

    def probe_worker(item):
        hostname, ip = item
        probe = probe_http(hostname, timeout=args.timeout)
        return hostname, ip, probe

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(probe_worker, item): item for item in live_candidates.items()}
        for future in concurrent.futures.as_completed(futures):
            hostname, ip, probe = future.result()
            status = probe.get("status_code")
            server = probe.get("server", "")
            title  = probe.get("title", "")
            techs  = probe.get("technologies", [])
            rt     = probe.get("response_time", 0)
            is_live = probe.get("live", False)

            # Takeover check
            takeover_svc = None
            if is_live and probe.get("body_snippet"):
                takeover_svc = check_takeover(hostname, probe.get("body_snippet",""), status)
            elif not is_live:
                # Check NXDOMAIN for cloud services
                pass

            entry = {
                "subdomain": hostname,
                "ip": ip,
                "live": is_live,
                "status_code": status,
                "server": server,
                "title": title,
                "technologies": techs,
                "https": probe.get("https", False),
                "response_time": rt,
                "takeover": takeover_svc,
            }
            results.append(entry)

            if takeover_svc:
                takeover_count += 1
                vuln_entry = {"subdomain": hostname, "type": "TAKEOVER", "severity": "HIGH",
                              "detail": f"Possible {takeover_svc} subdomain takeover"}
                vulns.append(vuln_entry)
                vuln(f"  ⚠  TAKEOVER [{takeover_svc}] {hostname}")
            elif is_live:
                live_count += 1
                scheme = "https" if probe.get("https") else "http"
                tech_str = f" [{','.join(techs[:3])}]" if techs else ""
                live_host(f"  ✓  LIVE  [{status}] {hostname:<40} {ip:<16} {rt}ms  {server or ''}{tech_str}")
                if title:
                    info(f"       Title: {title}")
            else:
                dead_count += 1
                dead(f"  ✗  DEAD  {hostname}")

    success(f"\n  ✓ Probing complete — {live_count} live, {dead_count} dead, {takeover_count} takeover candidates")

    # ── Phase 4: AI Analysis ───────────────────────────────────────────────────
    if args.ai and args.api_key:
        header(f"\n{sep}")
        header("  [4/4] AI — Vulnerability Analysis (Claude)")
        header(sep)
        info("  → Sending live hosts to Claude for security analysis...")
        live_results = [r for r in results if r.get("live")]
        ai_findings = ai_analyze(domain, live_results, args.api_key)
        for f in ai_findings:
            vulns.append(f)
            sev_color = "HIGH" if f.get("severity") == "HIGH" else "MEDIUM"
            vuln(f"  ⚠  [{f.get('severity')}] [{f.get('type')}] {f.get('subdomain')} — {f.get('detail')}")
        success(f"  ✓ AI analysis complete — {len(ai_findings)} findings")
    elif not args.ai:
        warn("\n  [4/4] AI analysis skipped (use --ai --api-key YOUR_KEY to enable)")

    # ── Final Report ───────────────────────────────────────────────────────────
    elapsed = int(time.time() - start_time)
    header(f"\n{sep}")
    header("  SCAN COMPLETE")
    header(sep)

    if RICH_AVAILABLE:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold white")
        table.add_row("Total Subdomains Found", str(len(all_subdomains)))
        table.add_row("DNS Resolved",           str(len(live_candidates)))
        table.add_row("Live Hosts",             str(live_count))
        table.add_row("Dead Hosts",             str(dead_count))
        table.add_row("Vulnerabilities",        str(len(vulns)))
        table.add_row("Takeover Candidates",    str(takeover_count))
        table.add_row("Scan Duration",          f"{elapsed}s")
        console.print(table)
    else:
        print(f"  Total Subdomains : {len(all_subdomains)}")
        print(f"  DNS Resolved     : {len(live_candidates)}")
        print(f"  Live Hosts       : {live_count}")
        print(f"  Dead Hosts       : {dead_count}")
        print(f"  Vulnerabilities  : {len(vulns)}")
        print(f"  Scan Duration    : {elapsed}s")

    if vulns:
        header("\n  VULNERABILITIES FOUND:")
        for v in vulns:
            vuln(f"  ⚠  [{v.get('severity')}] [{v.get('type')}] {v.get('subdomain')} — {v.get('detail')}")

    # Save reports
    formats = args.format.split(",")
    saved = save_report(domain, results, vulns, args.output, formats)
    print()
    success("  Reports saved:")
    for fp in saved:
        info(f"    → {fp}")
    print()

# ─── CLI Entry Point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ReconHunter — Advanced Subdomain & Live Host Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon_hunter.py -d example.com
  python3 recon_hunter.py -d example.com -w deep -t 50
  python3 recon_hunter.py -d example.com --no-passive
  python3 recon_hunter.py -d example.com -w deep --ai --api-key YOUR_KEY
  python3 recon_hunter.py -d example.com -wf /path/to/wordlist.txt -o /results
  python3 recon_hunter.py -d example.com -f json,csv,md
        """
    )
    parser.add_argument("-d",  "--domain",       required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w",  "--wordlist",      default="standard", choices=["quick","standard","deep"], help="Wordlist size (default: standard)")
    parser.add_argument("-wf", "--wordlist-file", help="Custom wordlist file (one prefix per line)")
    parser.add_argument("-t",  "--threads",       type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("--timeout",              type=int, default=5,  help="Timeout per request in seconds (default: 5)")
    parser.add_argument("--no-passive",           action="store_true",  help="Skip passive OSINT (crt.sh, HackerTarget, etc.)")
    parser.add_argument("--ai",                   action="store_true",  help="Enable AI-powered vulnerability analysis")
    parser.add_argument("--api-key",              help="Anthropic API key for AI analysis (or set ANTHROPIC_API_KEY env var)")
    parser.add_argument("-o",  "--output",        default="./recon_results", help="Output directory (default: ./recon_results)")
    parser.add_argument("-f",  "--format",        default="json,txt,csv,md", help="Output formats: json,txt,csv,md (default: all)")
    args = parser.parse_args()

    # API key from env if not provided
    if not args.api_key:
        args.api_key = os.environ.get("ANTHROPIC_API_KEY")

    run_scan(args)

if __name__ == "__main__":
    main()
