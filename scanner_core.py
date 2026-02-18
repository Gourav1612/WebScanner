import os
import time
import json
import ssl
import socket
import hashlib
import re
import requests
import threading
import queue
import concurrent.futures
import subprocess
import platform
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

# Optional libraries
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import tldextract
except Exception:
    tldextract = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    import whois
except Exception:
    whois = None

# --------------- Configuration & Defaults ---------------

CHECKS_CSV_DEFAULT = "checks.csv"

REQUEST_TIMEOUT = 10
DEFAULT_RATE_DELAY = 0.12
DEFAULT_THREADS = 10
MAX_THREADS = 100

# Expanded Port List (Top 50 Nmap)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888, 9000, 27017, 6379, 11211, 5432
]

SECURITY_HEADER_LIST = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy",
]

DEFAULT_CHECKS = [
    ("/", "Root page", "Info", "GET"),
    ("/robots.txt", "robots.txt presence", "Info", "GET"),
    ("/sitemap.xml", "sitemap.xml presence", "Info", "GET"),
    ("/admin/", "Common admin directory", "Low", "GET"),
    ("/.git/", "Exposed .git directory", "High", "GET"),
    ("/.git/config", "Git configuration exposure", "High", "GET"),
    ("/.env", ".env exposure", "High", "GET"),
    ("/phpinfo.php", "phpinfo.php exposure", "High", "GET"),
    ("/.htaccess", "Apache .htaccess exposure", "Medium", "GET"),
    ("/server-status", "Apache server-status", "Medium", "GET"),
    ("/wp-login.php", "WordPress login page", "Low", "GET"),
    ("/backup.zip", "Backup file", "High", "GET"),
    ("/config.php", "Config file", "Medium", "GET"),
    ("/config/settings.json", "Settings file", "Medium", "GET"),
]

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "__cfduid", "cf-cache-status", "cf-request-id"], "content": ["cloudflare"]},
    "AWS WAF": {"headers": ["x-amzn-requestid", "x-amz-id-2", "awselb"], "content": ["aws waf"]},
    "Akamai": {"headers": ["x-akamai-transformed", "akamai-ghs", "edge-control"], "content": ["akamai"]},
    "Imperva": {"headers": ["x-cdn", "visid_incap", "incap_ses"], "cookies": ["incap_ses"]},
    "F5 BIG-IP": {"headers": ["x-cnection", "x-wa-info"], "cookies": ["bigip"]},
    "Google Cloud Armor": {"headers": ["via"], "content": ["google cloud armor"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "content": ["sucuri"]},
    "Barracuda": {"headers": ["x-barracuda"], "cookies": ["barra_counter_session"]},
    "ModSecurity": {"headers": ["x-mod-security"], "content": ["mod_security", "ModSecurity"]},
    "Palo Alto Networks": {"headers": ["x-pan-auth"], "content": ["palo alto"]},
    "Fortinet": {"headers": ["fortiwafsid"], "cookies": ["fortiwafsid"]},
    "Citrix NetScaler": {"headers": ["ns_af"], "cookies": ["ns_af"]},
} # Expanded WAF list

FINGERPRINT_RULES = [
    ("WordPress", re.compile(r"wp-(?:content|includes)|wp-json", re.I)),
    ("Joomla", re.compile(r"Joomla", re.I)),
    ("Drupal", re.compile(r"Drupal.settings", re.I)),
    ("php", re.compile(r"\.php", re.I)),
    ("ASP.NET", re.compile(r"ASP.NET", re.I)),
    ("nginx", re.compile(r"nginx", re.I)),
    ("Apache", re.compile(r"Apache", re.I)),
    ("IIS", re.compile(r"Microsoft-IIS", re.I)),
]

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --", "' UNION SELECT 1,2,3 --",
    "1' ORDER BY 1--", "1' GROUP BY 1--", "') OR ('1'='1", "admin' --"
]

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --------------- Utility helpers ---------------

def now_iso():
    return datetime.utcnow().strftime("%H:%M:%S")

def safe_normalize_url(url: str) -> str:
    if not url: return ""
    url = url.strip()
    parsed = urlparse(url, "http")
    if not parsed.netloc and parsed.path:
        return "http://" + parsed.path
    if parsed.scheme == "":
        return "http://" + url
    return parsed.geturl()

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except:
        return "Unknown"

def get_whois_info(host):
    if not whois: return None
    try:
        w = whois.whois(host)
        res = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "org": w.org
        }
        return res
    except:
        return None

def parse_links_and_forms(html: str, base_url: str):
    if not BeautifulSoup: return None
    try:
        soup = BeautifulSoup(html, "html.parser")
        links = soup.find_all("a")
        forms = soup.find_all("form")
        return {
            "links_count": len(links),
            "forms_count": len(forms)
        }
    except:
        return None

def fingerprint(headers: dict, html: str, favicon_hash: str = None):
    findings = []
    server = headers.get("Server", "")
    xp = headers.get("X-Powered-By", "")
    if server:
        findings.append(("Server", server))
    if xp:
        findings.append(("X-Powered-By", xp))
    text = (html or "") + " " + server + " " + xp
    for name, rx in FINGERPRINT_RULES:
        if rx.search(text):
            findings.append(("Tech", name))
    if favicon_hash:
        findings.append(("Favicon-MD5", favicon_hash))
    return findings

def icmp_ping(host):
    param = '-n' if platform.system().lower()=='windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def fetch_url(url: str, headers_only=False, verify=True, timeout=REQUEST_TIMEOUT):
    res = {"url": url, "status": None, "headers": {}, "elapsed_ms": None, "text_snippet": "", "error": None}
    start = time.time()
    try:
        method = requests.head if headers_only else requests.get
        try:
            r = method(url, timeout=timeout, allow_redirects=True, verify=verify)
            # If head failed or returned 405, try get
            if headers_only and (r.status_code == 405 or r.status_code >= 400):
                 r = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify)
        except:
             r = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify)
             
        res["elapsed_ms"] = int((time.time() - start) * 1000)
        res["status"] = r.status_code
        res["headers"] = dict(r.headers)
        try:
            res["text_snippet"] = (r.text or "")[:10000]
        except:
            pass
    except Exception as e:
        res["error"] = str(e)
    return res

def tcp_scan_port(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return True
    except:
        return False

def get_tls_cert(host: str, port: int = 443, timeout=5):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.getpeercert(binary_form=True) # Binary for parsing if needed, but we just check presence
    except Exception as e:
        return False, str(e)

def compute_favicon_md5(base_url: str):
    try:
        fav = urljoin(base_url, "/favicon.ico")
        r = requests.get(fav, timeout=REQUEST_TIMEOUT, verify=False)
        if r.status_code == 200:
            return hashlib.md5(r.content).hexdigest()
    except:
        pass
    return None

# ----------------- Advanced Checks -----------------

def check_waf(url, timeout=5):
    results = []
    try:
        # Passive
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        headers = str(resp.headers).lower()
        cookies = str(resp.cookies.get_dict()).lower()
        
        for name, sigs in WAF_SIGNATURES.items():
            for h in sigs.get("headers", []):
                if h in headers: results.append(f"{name} (Header: {h})")
            for c in sigs.get("cookies", []):
                if c in cookies: results.append(f"{name} (Cookie: {c})")

        # Active
        active_url = f"{url}?id=<script>alert(1)</script>&cmd=cat%20/etc/passwd"
        active_resp = requests.get(active_url, timeout=timeout, verify=False)
        if active_resp.status_code in [403, 406, 501, 999]:
            results.append(f"WAF Blocking Triggered (Status: {active_resp.status_code})")
            
        return list(set(results))
    except Exception as e:
        return []

def check_sqli(url, timeout=5):
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings
    
    params = parse_qs(parsed.query)
    base_resp = requests.get(url, timeout=timeout, verify=False)
    base_len = len(base_resp.text)
    
    for param in params:
        for payload in SQLI_PAYLOADS:
            # Construct malicious query
            q = params.copy()
            q[param] = [payload]
            new_query = urlencode(q, doseq=True)
            target = parsed._replace(query=new_query).geturl()
            
            try:
                r = requests.get(target, timeout=timeout, verify=False)
                # Simple heuristics: Status 500 or significant size change
                if r.status_code == 500:
                    findings.append(f"Potential SQLi (500 Error) on param '{param}' with payload: {payload}")
                    break
                if abs(len(r.text) - base_len) > base_len * 0.5 and r.status_code == 200:
                     # This is very noisy, so we tag it as low confidence or just info
                     pass 
                if "syntax error" in r.text.lower() or "mysql" in r.text.lower() or "ora-" in r.text.lower():
                    findings.append(f"SQL Error leaked on param '{param}' with payload: {payload}")
                    break
            except:
                pass
    return findings

def check_infrastructure(target_ip, url):
    info = {"hosting": "Unknown", "load_balancer": "Not detected"}
    
    # 1. Hosting Provider (via IP API)
    try:
        r = requests.get(f"http://ip-api.com/json/{target_ip}?fields=isp,org,hosting", timeout=5)
        if r.status_code == 200:
            data = r.json()
            info["hosting"] = f"{data.get('isp', 'Unknown')} ({data.get('org', '')})"
    except:
        pass

    # 2. Load Balancer (Headers & Cookies)
    try:
        r = requests.get(url, timeout=5, verify=False)
        headers = str(r.headers).lower()
        cookies = str(r.cookies.get_dict()).lower()
        
        lbs = []
        if "via" in headers: lbs.append("Generic HTTP Proxy/LB")
        if "x-amz-cf-id" in headers: lbs.append("AWS CloudFront")
        if "awselb" in headers or "awsalb" in cookies: lbs.append("AWS ELB")
        if "cf-ray" in headers: lbs.append("Cloudflare")
        if "gcloud" in headers: lbs.append("Google Cloud LB")
        if "x-azure-ref" in headers: lbs.append("Azure LB")
        
        if lbs:
            info["load_balancer"] = ", ".join(list(set(lbs)))
    except:
        pass
        
    return info

# ----------------- Scanner Class -----------------

class Scanner:
    def __init__(self, target, config=None, callback=None):
        self.target = safe_normalize_url(target)
        self.config = config or {}
        self.callback = callback
        self.stop_event = threading.Event()
        
        self.threads = self.config.get("threads", DEFAULT_THREADS)
        self.rate = self.config.get("rate_delay", DEFAULT_RATE_DELAY)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.headers_only = self.config.get("headers_only", False)
        self.checks = self.config.get("checks", DEFAULT_CHECKS)

    def stop(self):
        self.stop_event.set()

    def report(self, severity, rtype, detail, meta=None):
        if self.callback:
            self.callback({
                "time": now_iso(),
                "severity": severity,
                "type": rtype,
                "detail": detail,
                "meta": meta or {}
            })

    def run(self):
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.hostname
        
        # 1. DNS Resolution (Resolve IP first)
        target_ip = host
        if dns:
            try:
                ans = dns.resolver.resolve(host, "A")
                ips = [r.to_text() for r in ans]
                if ips:
                    target_ip = ips[0]
                self.report("Info", "DNS Resolution", f"IPs: {', '.join(ips)}")
            except:
                self.report("Low", "DNS", "Could not resolve DNS")

        # 2. Host Discovery (Ping IP)
        self.report("Info", "Host Discovery", f"Pinging {target_ip}...")
        is_live = icmp_ping(target_ip)
        if is_live:
            self.report("Info", "Host Discovery", f"Host {target_ip} is responding to ping")
        else:
            self.report("Low", "Host Discovery", f"Host {target_ip} did not respond to ping (might be blocked)")

        # 2a. Infrastructure Detection
        self.report("Info", "Infrastructure Check", "Detecting Hosting & Load Balancer...")
        infra = check_infrastructure(target_ip, self.target)
        self.report("Info", "Hosting Provider", infra["hosting"])
        if infra["load_balancer"] != "Not detected":
            self.report("Medium", "Load Balancer", infra["load_balancer"])
        else:
            self.report("Info", "Load Balancer", "No Load Balancer detected")

        # 2b. WHOIS Check
        if whois:
            self.report("Info", "WHOIS", f"Fetching registration info for {host}...")
            wdata = get_whois_info(host)
            if wdata:
                self.report("Info", "WHOIS Registrar", wdata["registrar"])
                self.report("Info", "Domain Created", wdata["creation_date"])
                if wdata.get("org"):
                    self.report("Info", "Organization", wdata["org"])

        # 3. WAF Check
        self.report("Info", "WAF Check", "Analyzing WAF presence...")
        waf_hits = check_waf(self.target)
        if waf_hits:
            for hit in waf_hits: self.report("Medium", "WAF Detected", hit)
        else:
            self.report("Info", "WAF", "No common WAF signatures detected")
            
        # 4. Port Scan (Threaded)
        self.report("Info", "Port Scan", f"Scanning {len(COMMON_PORTS)} common ports...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(tcp_scan_port, host, p): p for p in COMMON_PORTS}
            for future in concurrent.futures.as_completed(future_to_port):
                if self.stop_event.is_set(): break
                p = future_to_port[future]
                if future.result():
                    self.report("Info", "Open Port", f"Port {p} is open")
        
        # 5. SQLi Check
        self.report("Info", "Security Check", "Checking for SQL Injection vulnerabilities...")
        sqli_hits = check_sqli(self.target)
        for sqli in sqli_hits:
            self.report("High", "SQL Injection", sqli)

        # 6. Web Checks (Content, Headers, Files)
        tasks = []
        tasks.append(("fetch_root", {"url": base}))
        tasks.append(("favicon", {"base": base}))
        tasks.append(("tls", {"host": host}))
        
        for path, desc, sev, method in self.checks:
            tasks.append(("path", {"url": urljoin(base, path), "desc": desc, "sev": sev, "method": method}))

        q = queue.Queue()
        for t in tasks: q.put(t)
            
        workers = []
        for _ in range(max(1, self.threads)):
            w = threading.Thread(target=self._worker_loop, args=(q,), daemon=True)
            w.start()
            workers.append(w)
            
        q.join()
        self.report("Info", "Scan Complete", "All checks finished.")

    def _worker_loop(self, q):
        while not q.empty() and not self.stop_event.is_set():
            try:
                task, payload = q.get_nowait()
            except queue.Empty:
                break
            
            try:
                if task == "fetch_root":
                    info = fetch_url(payload["url"], headers_only=self.headers_only, verify=self.verify_ssl)
                    if info.get("error"):
                        self.report("High", "Fetch error", info.get("error"))
                    else:
                        # Fingerprinting
                        fav_hash = compute_favicon_md5(payload["url"])
                        hits = fingerprint(info["headers"], info["text_snippet"], fav_hash)
                        for tag, val in hits:
                            self.report("Info", f"Fingerprint ({tag})", val)
                        
                        # HTML Analysis
                        html_data = parse_links_and_forms(info["text_snippet"], payload["url"])
                        if html_data:
                            self.report("Info", "Links Found", f"{html_data['links_count']} internal/external links")
                            self.report("Info", "Forms Found", f"{html_data['forms_count']} input forms detected")

                        for h in SECURITY_HEADER_LIST:
                            if h not in info["headers"]:
                                self.report("Medium", "Missing Header", h)
                
                elif task == "tls":
                    ok, cert = get_tls_cert(payload["host"])
                    if ok: self.report("Info", "TLS", "Certificate is present and valid")
                    else: self.report("Low", "TLS", "No valid certificate found or connection failed")

                elif task == "favicon":
                    h = compute_favicon_md5(payload["base"])
                    if h: self.report("Info", "Favicon", f"MD5: {h}")

                elif task == "path":
                    try:
                        r = requests.request(payload["method"], payload["url"], timeout=REQUEST_TIMEOUT, verify=self.verify_ssl)
                        if r.status_code < 400:
                            self.report(payload["sev"], payload["desc"], f"Found (HTTP {r.status_code}) - {payload['url']}")
                    except:
                        pass
            except Exception as e:
                pass
            finally:
                q.task_done()
            time.sleep(self.rate)
