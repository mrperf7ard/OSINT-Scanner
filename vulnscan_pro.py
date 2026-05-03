#!/usr/bin/env python3
"""
VulnScan Pro — Windows Vulnerability Assessment Framework
Author: VulnScan Pro
Version: 2.5.0

HOW TO RUN:
  python vulnscan_pro.py

HOW TO COMPILE TO EXE:
  pip install pyinstaller
  pyinstaller --onefile --windowed --name="VulnScanPro" vulnscan_pro.py

DEPENDENCIES (install first):
  pip install requests dnspython
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import socket
import ssl
import json
import time
import datetime
import os
import re
import csv
import hashlib
import urllib.parse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Optional imports (graceful fallback if missing) ──────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# THEME CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
DARK = {
    "bg":        "#0d0e0f",
    "surface":   "#13151a",
    "surface2":  "#181b22",
    "border":    "#2a2f42",
    "text":      "#e2e4ec",
    "muted":     "#8892ab",
    "faint":     "#4a5168",
    "primary":   "#4f98a3",
    "success":   "#6daa45",
    "warning":   "#e8af34",
    "error":     "#dd4c5f",
    "critical":  "#ff6b35",
    "mono":      "Consolas",
    "font":      "Segoe UI",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff6b35",
    "HIGH":     "#dd4c5f",
    "MEDIUM":   "#e8af34",
    "LOW":      "#6daa45",
    "INFO":     "#4f98a3",
}

# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINE  (pure Python, no heavy deps)
# ─────────────────────────────────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","vpn","remote","api","dev","staging",
    "test","beta","admin","portal","dashboard","login","auth","sso","app","apps",
    "web","cdn","media","static","assets","img","images","ns1","ns2","mx","smtp2",
    "exchange","owa","webmail","cpanel","whm","plesk","mysql","db","database",
    "git","gitlab","github","jira","confluence","jenkins","ci","cd","deploy",
    "monitor","nagios","grafana","kibana","elastic","redis","kafka","rabbitmq",
    "shop","store","blog","forum","support","help","docs","api2","mobile","m",
    "secure","ssl","cloud","s3","backup","old","new","stage","uat","prod",
    "internal","intranet","private","corp","office","remote2","vpn2","fw","firewall",
]

COMMON_PORTS = [
    (21,"FTP"),(22,"SSH"),(23,"Telnet"),(25,"SMTP"),(53,"DNS"),
    (80,"HTTP"),(110,"POP3"),(143,"IMAP"),(443,"HTTPS"),(445,"SMB"),
    (465,"SMTPS"),(587,"SMTP-TLS"),(993,"IMAPS"),(995,"POP3S"),
    (1433,"MSSQL"),(1521,"Oracle"),(3306,"MySQL"),(3389,"RDP"),
    (5432,"PostgreSQL"),(5900,"VNC"),(6379,"Redis"),(8080,"HTTP-Alt"),
    (8443,"HTTPS-Alt"),(8888,"HTTP-Dev"),(9200,"Elasticsearch"),
    (27017,"MongoDB"),(11211,"Memcached"),
]

RISKY_PORTS = {21,23,3389,5900,6379,9200,27017,11211,445}

CVE_SIGNATURES = [
    ("Apache/2.4.49", "CVE-2021-41773", "CRITICAL", "Path traversal / RCE in Apache 2.4.49"),
    ("Apache/2.4.50", "CVE-2021-42013", "CRITICAL", "Path traversal / RCE in Apache 2.4.50"),
    ("OpenSSH_7.",    "CVE-2023-38408", "HIGH",     "OpenSSH agent remote code execution"),
    ("nginx/1.18",    "CVE-2021-23017", "HIGH",     "nginx resolver 1-byte memory overwrite"),
    ("Microsoft-IIS/7","CVE-2017-7269","CRITICAL",  "IIS 7.x WebDAV buffer overflow (RCE)"),
    ("ProFTPD/1.3.5", "CVE-2019-12815","CRITICAL",  "ProFTPD arbitrary file copy"),
    ("vsftpd 2.3.4",  "CVE-2011-2523", "CRITICAL",  "vsftpd 2.3.4 backdoor"),
    ("PHP/5.",         "CVE-2019-11043","CRITICAL",  "PHP-FPM RCE in Nginx configurations"),
    ("Exim 4.",        "CVE-2019-10149","CRITICAL",  "Exim remote code execution (The Return of the WIZard)"),
    ("Dovecot/2.2",    "CVE-2019-11494","HIGH",      "Dovecot partial MIME parsing DoS"),
]

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

# ─────────────────────────────────────────────────────────────────────────────
# SCAN FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def enumerate_subdomains(domain, log_fn, found_fn):
    log_fn(f"[SUBDOMAIN] Starting enumeration for {domain}", "info")
    discovered = []

    # 1. DNS brute-force
    log_fn(f"[SUBDOMAIN] Brute-forcing {len(COMMON_SUBDOMAINS)} common subdomains...", "info")
    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        ip = resolve_domain(fqdn)
        if ip:
            return (fqdn, ip)
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(check_sub, s): s for s in COMMON_SUBDOMAINS}
        for f in as_completed(futs):
            res = f.result()
            if res:
                discovered.append(res)
                found_fn("subdomain", res[0], res[1], "INFO", "Active subdomain resolved")

    # 2. crt.sh certificate transparency
    if REQUESTS_OK:
        try:
            log_fn(f"[SUBDOMAIN] Querying crt.sh certificate transparency logs...", "info")
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15, headers={"User-Agent": "VulnScanPro/2.5"}
            )
            if r.status_code == 200:
                data = r.json()
                seen = set(d[0] for d in discovered)
                for entry in data:
                    names = entry.get("name_value", "")
                    for n in names.split("\n"):
                        n = n.strip().lstrip("*.")
                        if n.endswith(domain) and n not in seen:
                            seen.add(n)
                            ip = resolve_domain(n)
                            if ip:
                                discovered.append((n, ip))
                                found_fn("subdomain", n, ip, "INFO", "Found via CT logs (crt.sh)")
                log_fn(f"[SUBDOMAIN] crt.sh returned {len(data)} certificate entries", "success")
        except Exception as e:
            log_fn(f"[SUBDOMAIN] crt.sh query failed: {e}", "warn")

    log_fn(f"[SUBDOMAIN] Found {len(discovered)} active subdomains", "success")
    return discovered


def scan_ports(host, ip, log_fn, found_fn, ports=None):
    if ports is None:
        ports = COMMON_PORTS
    log_fn(f"[PORTSCAN] Scanning {host} ({ip}) — {len(ports)} ports...", "info")
    open_ports = []

    def check_port(port_info):
        port, svc = port_info
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return (port, svc)
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(check_port, p): p for p in ports}
        for f in as_completed(futs):
            res = f.result()
            if res:
                port, svc = res
                open_ports.append(res)
                sev = "HIGH" if port in RISKY_PORTS else "LOW"
                msg = f"Open port {port}/{svc}"
                if port in RISKY_PORTS:
                    msg += f" ⚠ RISKY — {svc} should not be internet-facing"
                found_fn("port", host, f"{port}/{svc}", sev, msg)

    log_fn(f"[PORTSCAN] {host}: {len(open_ports)} open ports found", "success" if open_ports else "info")
    return open_ports


def check_ssl(host, log_fn, found_fn):
    log_fn(f"[SSL] Checking TLS/SSL for {host}...", "info")
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as ssock:
            ssock.settimeout(5)
            ssock.connect((host, 443))
            cert = ssock.getpeercert()
            proto = ssock.version()

            # Expiry check
            exp_str = cert.get("notAfter", "")
            if exp_str:
                exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                if days_left < 0:
                    sev, msg = "CRITICAL", f"SSL certificate EXPIRED {abs(days_left)} days ago"
                    findings.append(msg)
                    found_fn("ssl", host, "Certificate Expired", sev, msg)
                elif days_left < 14:
                    sev, msg = "HIGH", f"SSL certificate expires in {days_left} days"
                    findings.append(msg)
                    found_fn("ssl", host, "Cert Expiring Soon", sev, msg)
                elif days_left < 30:
                    sev, msg = "MEDIUM", f"SSL certificate expires in {days_left} days"
                    findings.append(msg)
                    found_fn("ssl", host, "Cert Expiring", sev, msg)
                else:
                    log_fn(f"[SSL] {host}: Certificate valid for {days_left} days", "success")

            # Weak protocol
            if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                msg = f"Weak TLS version in use: {proto}"
                findings.append(msg)
                found_fn("ssl", host, f"Weak TLS: {proto}", "HIGH", msg)
            else:
                log_fn(f"[SSL] {host}: TLS version {proto} ✓", "success")

            # Subject Alt Names
            san = cert.get("subjectAltName", [])
            log_fn(f"[SSL] {host}: {len(san)} SAN entries in certificate", "info")

    except ssl.SSLCertVerificationError as e:
        msg = f"SSL verification failed: {e}"
        found_fn("ssl", host, "SSL Cert Invalid", "HIGH", msg)
    except ConnectionRefusedError:
        log_fn(f"[SSL] {host}: Port 443 not open", "warn")
    except Exception as e:
        log_fn(f"[SSL] {host}: {e}", "warn")

    return findings


def check_dns(domain, log_fn, found_fn):
    log_fn(f"[DNS] Checking DNS configuration for {domain}...", "info")
    if not DNS_OK:
        log_fn("[DNS] dnspython not installed. Running basic DNS checks only.", "warn")
        # Basic fallback
        try:
            txt_records = socket.getaddrinfo(domain, None)
            log_fn(f"[DNS] Basic A record resolved: {txt_records[0][4][0]}", "success")
        except:
            pass
        return

    # SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = False
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_found = True
                if "+all" in txt:
                    found_fn("dns", domain, "SPF +all (Open Relay)", "CRITICAL",
                             "SPF record uses +all — allows ANY IP to send email as your domain")
                elif "~all" in txt:
                    found_fn("dns", domain, "SPF ~all (SoftFail)", "MEDIUM",
                             "SPF uses ~all (softfail) — consider -all for strict enforcement")
                else:
                    log_fn(f"[DNS] {domain}: SPF record OK ({txt[:60]})", "success")
        if not spf_found:
            found_fn("dns", domain, "Missing SPF Record", "HIGH",
                     "No SPF record found — email spoofing is possible")
    except Exception as e:
        log_fn(f"[DNS] SPF check error: {e}", "warn")

    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if "p=none" in txt:
                found_fn("dns", domain, "DMARC p=none (Monitor Only)", "MEDIUM",
                         "DMARC policy is monitor-only. Set p=quarantine or p=reject")
            elif "p=quarantine" in txt:
                log_fn(f"[DNS] {domain}: DMARC p=quarantine ✓", "success")
            elif "p=reject" in txt:
                log_fn(f"[DNS] {domain}: DMARC p=reject ✓✓", "success")
    except dns.resolver.NXDOMAIN:
        found_fn("dns", domain, "Missing DMARC Record", "HIGH",
                 "No DMARC record found — phishing/spoofing risk")
    except Exception as e:
        log_fn(f"[DNS] DMARC check: {e}", "warn")

    # DKIM (check common selector)
    for selector in ["default", "google", "mail", "dkim", "k1"]:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            log_fn(f"[DNS] {domain}: DKIM selector '{selector}' found ✓", "success")
            break
        except:
            pass
    else:
        found_fn("dns", domain, "DKIM Not Verified", "LOW",
                 "No DKIM record found with common selectors")

    # Zone Transfer attempt
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        for ns in ns_answers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=3))
                if zone:
                    found_fn("dns", domain, f"Zone Transfer Allowed via {ns}", "CRITICAL",
                             f"DNS zone transfer succeeded on {ns} — full DNS exposed!")
            except:
                pass
        log_fn(f"[DNS] Zone transfer attempts complete (likely blocked ✓)", "success")
    except Exception as e:
        log_fn(f"[DNS] NS/zone check: {e}", "warn")


def check_http_headers(host, log_fn, found_fn):
    if not REQUESTS_OK:
        log_fn("[HTTP] requests library not available", "warn")
        return

    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{host}",
                timeout=8, allow_redirects=True,
                headers={"User-Agent": "VulnScanPro/2.5 Security Scanner"},
                verify=False
            )
            log_fn(f"[HTTP] {scheme}://{host} → HTTP {r.status_code}", "info")
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Server banner → CVE correlation
            server = headers.get("server", "")
            if server:
                log_fn(f"[HTTP] Server: {server}", "info")
                for sig, cve, sev, desc in CVE_SIGNATURES:
                    if sig.lower() in server.lower():
                        found_fn("cve", host, cve, sev, f"{desc} (Server: {server})")

            # Security headers
            missing = []
            security_headers = {
                "strict-transport-security": ("HSTS Missing", "MEDIUM",
                    "HSTS header missing — SSL stripping attacks possible"),
                "x-frame-options": ("Clickjacking Risk", "MEDIUM",
                    "X-Frame-Options missing — clickjacking possible"),
                "x-content-type-options": ("MIME Sniffing", "LOW",
                    "X-Content-Type-Options missing — MIME sniffing possible"),
                "content-security-policy": ("No CSP", "MEDIUM",
                    "Content-Security-Policy missing — XSS risk elevated"),
                "referrer-policy": ("No Referrer Policy", "LOW",
                    "Referrer-Policy missing — data leakage in HTTP referrer"),
                "permissions-policy": ("No Permissions Policy", "LOW",
                    "Permissions-Policy missing"),
            }
            for hdr, (label, sev, msg) in security_headers.items():
                if hdr not in headers:
                    found_fn("headers", host, label, sev, msg)
                    missing.append(hdr)

            if not missing:
                log_fn(f"[HTTP] {host}: All security headers present ✓", "success")

            # Information disclosure
            if "x-powered-by" in headers:
                found_fn("headers", host, f"Info Disclosure: {headers['x-powered-by']}",
                         "LOW", f"X-Powered-By header exposes technology stack: {headers['x-powered-by']}")

            # Check for open redirect / sensitive paths
            sensitive_paths = [
                "/.git/config", "/.env", "/wp-config.php", "/config.php",
                "/phpinfo.php", "/server-status", "/admin", "/.htaccess",
            ]
            for path in sensitive_paths:
                try:
                    pr = requests.get(
                        f"{scheme}://{host}{path}", timeout=4,
                        headers={"User-Agent": "VulnScanPro/2.5"},
                        verify=False, allow_redirects=False
                    )
                    if pr.status_code in (200, 301, 302):
                        found_fn("web", host, f"Exposed Path: {path}", "HIGH",
                                 f"Sensitive path {path} returned HTTP {pr.status_code}")
                except:
                    pass

            return  # stop after first successful scheme
        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            log_fn(f"[HTTP] {host}: {e}", "warn")
            continue


def check_hibp_email(email, api_key, log_fn, found_fn):
    if not REQUESTS_OK:
        log_fn("[HIBP] requests not available", "warn")
        return []
    if not api_key:
        log_fn("[HIBP] No API key — skipping breach check", "warn")
        return []
    try:
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "VulnScanPro/2.5",
        }
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers=headers, timeout=10
        )
        if r.status_code == 200:
            breaches = r.json()
            for b in breaches:
                classes = ", ".join(b.get("DataClasses", []))
                found_fn("breach", email, b.get("Name", "Unknown"),
                         "HIGH" if "Passwords" in classes else "MEDIUM",
                         f"Breached in '{b.get('Name')}' — Data: {classes[:80]}")
            log_fn(f"[HIBP] {email}: {len(breaches)} breach(es) found", "warn" if breaches else "success")
            return breaches
        elif r.status_code == 404:
            log_fn(f"[HIBP] {email}: Not found in any breach ✓", "success")
        elif r.status_code == 429:
            log_fn("[HIBP] Rate limited — waiting 2s...", "warn")
            time.sleep(2)
        else:
            log_fn(f"[HIBP] {email}: HTTP {r.status_code}", "warn")
    except Exception as e:
        log_fn(f"[HIBP] {email}: {e}", "warn")
    return []


def check_shodan_domain(domain, api_key, log_fn, found_fn):
    if not REQUESTS_OK:
        return
    if not api_key:
        log_fn("[SHODAN] No API key — skipping Shodan lookup", "warn")
        return
    try:
        r = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}?key={api_key}",
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            subdomains = data.get("subdomains", [])
            log_fn(f"[SHODAN] {domain}: {len(subdomains)} subdomains via Shodan DNS", "success")
            for sub in subdomains[:50]:
                fqdn = f"{sub}.{domain}"
                ip = resolve_domain(fqdn)
                if ip:
                    found_fn("shodan", fqdn, ip, "INFO", f"Subdomain via Shodan DNSDB")
        else:
            log_fn(f"[SHODAN] API response: {r.status_code}", "warn")
    except Exception as e:
        log_fn(f"[SHODAN] {domain}: {e}", "warn")


def check_virustotal(domain, api_key, log_fn, found_fn):
    if not REQUESTS_OK:
        return
    if not api_key:
        log_fn("[VT] No VirusTotal API key — skipping", "warn")
        return
    try:
        headers = {"x-apikey": api_key}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers, timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            log_fn(f"[VT] {domain}: malicious={malicious}, suspicious={suspicious}", "info")
            if malicious > 0:
                found_fn("virustotal", domain, f"{malicious} malicious detections", "CRITICAL",
                         f"VirusTotal: {malicious} engines flagged domain as malicious")
            elif suspicious > 0:
                found_fn("virustotal", domain, f"{suspicious} suspicious detections", "HIGH",
                         f"VirusTotal: {suspicious} engines flagged domain as suspicious")
            else:
                log_fn(f"[VT] {domain}: Clean (0 malicious) ✓", "success")
        else:
            log_fn(f"[VT] API response: {r.status_code}", "warn")
    except Exception as e:
        log_fn(f"[VT] {domain}: {e}", "warn")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GUI APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

class VulnScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VulnScan Pro v2.5 — Vulnerability Assessment Framework")
        self.geometry("1280x820")
        self.minsize(1024, 680)
        self.configure(bg=DARK["bg"])

        # State
        self.findings = []
        self.scan_running = False
        self.api_keys = {
            "hibp": tk.StringVar(),
            "shodan": tk.StringVar(),
            "virustotal": tk.StringVar(),
        }

        self._build_styles()
        self._build_ui()
        self._log("VulnScan Pro v2.5.0 initialized", "success")
        self._log("Enter target domain and click Scan to begin.", "info")
        if not REQUESTS_OK:
            self._log("⚠ 'requests' not installed. Run: pip install requests", "warn")
        if not DNS_OK:
            self._log("⚠ 'dnspython' not installed. Run: pip install dnspython", "warn")

    # ── STYLES ────────────────────────────────────────────────────────────────
    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",
            background=DARK["bg"], borderwidth=0, tabmargins=[0,0,0,0])
        style.configure("TNotebook.Tab",
            background=DARK["surface"], foreground=DARK["muted"],
            font=(DARK["font"], 10), padding=[18, 8], borderwidth=0)
        style.map("TNotebook.Tab",
            background=[("selected", DARK["surface2"])],
            foreground=[("selected", DARK["text"])])
        style.configure("Treeview",
            background=DARK["surface"], fieldbackground=DARK["surface"],
            foreground=DARK["text"], rowheight=28,
            font=(DARK["font"], 9), borderwidth=0)
        style.configure("Treeview.Heading",
            background=DARK["surface2"], foreground=DARK["muted"],
            font=(DARK["font"], 9, "bold"), relief="flat", borderwidth=0)
        style.map("Treeview",
            background=[("selected", DARK["primary"])],
            foreground=[("selected", "#fff")])
        style.configure("Vertical.TScrollbar",
            background=DARK["border"], troughcolor=DARK["surface"],
            arrowcolor=DARK["muted"], borderwidth=0, width=10)
        style.configure("TProgressbar",
            troughcolor=DARK["surface2"], background=DARK["primary"],
            borderwidth=0, thickness=6)
        style.configure("TEntry",
            fieldbackground=DARK["surface2"], foreground=DARK["text"],
            insertcolor=DARK["text"], borderwidth=1, relief="flat")

    # ── MAIN UI ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Top bar
        topbar = tk.Frame(self, bg=DARK["surface"], height=56)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        # Logo
        logo_frame = tk.Frame(topbar, bg=DARK["surface"])
        logo_frame.pack(side="left", padx=20)
        tk.Label(logo_frame, text="🛡", bg=DARK["surface"], fg=DARK["primary"],
                 font=(DARK["font"], 18)).pack(side="left")
        tk.Label(logo_frame, text="VulnScan", bg=DARK["surface"], fg=DARK["text"],
                 font=(DARK["font"], 14, "bold")).pack(side="left", padx=(4,0))
        tk.Label(logo_frame, text="Pro", bg=DARK["surface"], fg=DARK["primary"],
                 font=(DARK["font"], 14, "bold")).pack(side="left")
        tk.Label(logo_frame, text="v2.5", bg=DARK["surface"], fg=DARK["faint"],
                 font=(DARK["font"], 9)).pack(side="left", padx=(4,0))

        # Status dot
        self.status_label = tk.Label(topbar, text="● READY", bg=DARK["surface"],
                                      fg=DARK["success"], font=(DARK["font"], 9, "bold"))
        self.status_label.pack(side="right", padx=20)

        # Scan bar
        scanbar = tk.Frame(self, bg=DARK["surface2"], height=52)
        scanbar.pack(fill="x", side="top")
        scanbar.pack_propagate(False)

        tk.Label(scanbar, text="Target:", bg=DARK["surface2"], fg=DARK["muted"],
                 font=(DARK["font"], 10)).pack(side="left", padx=(16,6))
        self.target_var = tk.StringVar(value="example.com")
        self.target_entry = tk.Entry(scanbar, textvariable=self.target_var, width=30,
            bg=DARK["surface"], fg=DARK["text"], insertbackground=DARK["text"],
            relief="flat", font=(DARK["font"], 11), bd=4)
        self.target_entry.pack(side="left", padx=(0,12))

        # Module checkboxes
        self.mod_vars = {}
        modules = [
            ("subdomain", "Subdomains", True),
            ("ports", "Ports", True),
            ("ssl", "SSL/TLS", True),
            ("dns", "DNS", True),
            ("headers", "HTTP Headers", True),
            ("cve", "CVE Match", True),
        ]
        for key, label, default in modules:
            v = tk.BooleanVar(value=default)
            self.mod_vars[key] = v
            cb = tk.Checkbutton(scanbar, text=label, variable=v,
                bg=DARK["surface2"], fg=DARK["text"], selectcolor=DARK["surface"],
                activebackground=DARK["surface2"], activeforeground=DARK["primary"],
                font=(DARK["font"], 9), bd=0, highlightthickness=0)
            cb.pack(side="left", padx=4)

        self.scan_btn = tk.Button(scanbar, text="▶  Scan", command=self._start_scan,
            bg=DARK["primary"], fg="#fff", font=(DARK["font"], 10, "bold"),
            relief="flat", padx=16, pady=4, cursor="hand2",
            activebackground=DARK["primary"], activeforeground="#fff")
        self.scan_btn.pack(side="left", padx=10)

        self.stop_btn = tk.Button(scanbar, text="■  Stop", command=self._stop_scan,
            bg=DARK["error"], fg="#fff", font=(DARK["font"], 10, "bold"),
            relief="flat", padx=12, pady=4, cursor="hand2", state="disabled",
            activebackground=DARK["error"], activeforeground="#fff")
        self.stop_btn.pack(side="left", padx=2)

        # Progress bar
        self.progress = ttk.Progressbar(scanbar, mode="indeterminate", length=140)
        self.progress.pack(side="left", padx=12)

        self.prog_label = tk.Label(scanbar, text="", bg=DARK["surface2"],
                                    fg=DARK["muted"], font=(DARK["font"], 9))
        self.prog_label.pack(side="left")

        tk.Button(scanbar, text="Export CSV", command=self._export_csv,
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["font"], 9),
            relief="flat", padx=10, pady=4, cursor="hand2",
            activebackground=DARK["border"]).pack(side="right", padx=(0,16))

        tk.Button(scanbar, text="⚙ API Keys", command=self._open_api_dialog,
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["font"], 9),
            relief="flat", padx=10, pady=4, cursor="hand2",
            activebackground=DARK["border"]).pack(side="right", padx=4)

        # KPI bar
        kpi_bar = tk.Frame(self, bg=DARK["bg"], height=64)
        kpi_bar.pack(fill="x", side="top", padx=12, pady=(8,4))
        kpi_bar.pack_propagate(False)

        self.kpi_vars = {}
        kpi_defs = [
            ("critical", "CRITICAL", DARK["critical"]),
            ("high",     "HIGH",     DARK["error"]),
            ("medium",   "MEDIUM",   DARK["warning"]),
            ("low",      "LOW",      DARK["success"]),
            ("total",    "TOTAL FINDINGS", DARK["primary"]),
        ]
        for key, label, color in kpi_defs:
            frame = tk.Frame(kpi_bar, bg=DARK["surface"], relief="flat",
                             highlightbackground=DARK["border"], highlightthickness=1)
            frame.pack(side="left", expand=True, fill="both", padx=4, pady=4)
            v = tk.StringVar(value="0")
            self.kpi_vars[key] = v
            tk.Label(frame, textvariable=v, bg=DARK["surface"], fg=color,
                     font=(DARK["mono"], 20, "bold")).pack(pady=(6,0))
            tk.Label(frame, text=label, bg=DARK["surface"], fg=DARK["faint"],
                     font=(DARK["font"], 8)).pack()

        # Main tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0,12))

        # Tab 1: Findings
        findings_tab = tk.Frame(notebook, bg=DARK["bg"])
        notebook.add(findings_tab, text="  🔍 Findings  ")
        self._build_findings_tab(findings_tab)

        # Tab 2: Console
        console_tab = tk.Frame(notebook, bg=DARK["bg"])
        notebook.add(console_tab, text="  📟 Console  ")
        self._build_console_tab(console_tab)

        # Tab 3: Email Checker
        email_tab = tk.Frame(notebook, bg=DARK["bg"])
        notebook.add(email_tab, text="  ✉ Email Breach  ")
        self._build_email_tab(email_tab)

        # Tab 4: Report
        report_tab = tk.Frame(notebook, bg=DARK["bg"])
        notebook.add(report_tab, text="  📄 Report  ")
        self._build_report_tab(report_tab)

    # ── FINDINGS TAB ──────────────────────────────────────────────────────────
    def _build_findings_tab(self, parent):
        # Filter bar
        fbar = tk.Frame(parent, bg=DARK["bg"])
        fbar.pack(fill="x", pady=(8,4))
        tk.Label(fbar, text="Filter:", bg=DARK["bg"], fg=DARK["muted"],
                 font=(DARK["font"], 9)).pack(side="left", padx=(4,6))
        self.filter_var = tk.StringVar(value="ALL")
        for label in ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            color = SEVERITY_COLORS.get(label, DARK["text"])
            rb = tk.Radiobutton(fbar, text=label, variable=self.filter_var, value=label,
                bg=DARK["bg"], fg=color, selectcolor=DARK["surface"],
                activebackground=DARK["bg"], activeforeground=color,
                font=(DARK["font"], 9, "bold"), command=self._apply_filter)
            rb.pack(side="left", padx=6)

        self.count_label = tk.Label(fbar, text="0 findings", bg=DARK["bg"],
                                     fg=DARK["faint"], font=(DARK["font"], 9))
        self.count_label.pack(side="right", padx=8)

        # Treeview
        cols = ("severity", "type", "host", "finding", "description")
        frame = tk.Frame(parent, bg=DARK["bg"])
        frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("severity",    text="Severity")
        self.tree.heading("type",        text="Type")
        self.tree.heading("host",        text="Host/Target")
        self.tree.heading("finding",     text="Finding")
        self.tree.heading("description", text="Description")
        self.tree.column("severity",    width=90,  minwidth=80,  anchor="center")
        self.tree.column("type",        width=110, minwidth=80)
        self.tree.column("host",        width=200, minwidth=120)
        self.tree.column("finding",     width=220, minwidth=120)
        self.tree.column("description", width=500, minwidth=200)

        # Tag colors
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Detail panel
        detail_frame = tk.Frame(parent, bg=DARK["surface"], height=100)
        detail_frame.pack(fill="x", padx=0, pady=(2,0))
        detail_frame.pack_propagate(False)
        tk.Label(detail_frame, text="Detail:", bg=DARK["surface"], fg=DARK["muted"],
                 font=(DARK["font"], 9, "bold")).pack(anchor="w", padx=8, pady=(4,0))
        self.detail_label = tk.Label(detail_frame, text="Click a finding for details",
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["font"], 9),
            wraplength=1200, justify="left", anchor="w")
        self.detail_label.pack(anchor="w", padx=8)
        self.tree.bind("<<TreeviewSelect>>", self._on_finding_select)

    # ── CONSOLE TAB ───────────────────────────────────────────────────────────
    def _build_console_tab(self, parent):
        btn_frame = tk.Frame(parent, bg=DARK["bg"])
        btn_frame.pack(fill="x", pady=(6,2))
        tk.Button(btn_frame, text="Clear Console", command=self._clear_console,
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["font"], 9),
            relief="flat", padx=10, pady=3, cursor="hand2").pack(side="left", padx=8)

        self.console = scrolledtext.ScrolledText(parent, bg=DARK["bg"],
            fg=DARK["text"], font=(DARK["mono"], 9), bd=0, relief="flat",
            insertbackground=DARK["text"], state="disabled")
        self.console.pack(fill="both", expand=True, padx=4, pady=(0,4))

        # Console tags
        self.console.tag_configure("success", foreground=DARK["success"])
        self.console.tag_configure("warn",    foreground=DARK["warning"])
        self.console.tag_configure("error",   foreground=DARK["error"])
        self.console.tag_configure("info",    foreground=DARK["primary"])
        self.console.tag_configure("time",    foreground=DARK["faint"])
        self.console.tag_configure("normal",  foreground=DARK["text"])

    # ── EMAIL TAB ─────────────────────────────────────────────────────────────
    def _build_email_tab(self, parent):
        outer = tk.Frame(parent, bg=DARK["bg"])
        outer.pack(fill="both", expand=True, padx=16, pady=12)

        left = tk.Frame(outer, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(0,12))

        tk.Label(left, text="Email Breach Checker", bg=DARK["bg"], fg=DARK["text"],
                 font=(DARK["font"], 13, "bold")).pack(anchor="w", pady=(0,8))

        tk.Label(left, text="Enter emails (one per line):", bg=DARK["bg"],
                 fg=DARK["muted"], font=(DARK["font"], 9)).pack(anchor="w")
        self.email_input = scrolledtext.ScrolledText(left, width=38, height=12,
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["mono"], 9),
            bd=0, relief="flat", insertbackground=DARK["text"])
        self.email_input.pack(pady=(4,8))
        self.email_input.insert("end", "admin@example.com\nceo@example.com\ndevops@example.com")

        tk.Label(left, text="HIBP API Key:", bg=DARK["bg"], fg=DARK["muted"],
                 font=(DARK["font"], 9)).pack(anchor="w")
        tk.Entry(left, textvariable=self.api_keys["hibp"], width=38, show="*",
            bg=DARK["surface"], fg=DARK["text"], insertbackground=DARK["text"],
            relief="flat", bd=4, font=(DARK["mono"], 9)).pack(pady=(2,8))

        tk.Button(left, text="▶  Check Emails", command=self._check_emails,
            bg=DARK["primary"], fg="#fff", font=(DARK["font"], 10, "bold"),
            relief="flat", padx=16, pady=6, cursor="hand2").pack(anchor="w")

        tk.Label(left, text="\nNote: HIBP API key required for\nfull breach lookup.\nGet one at haveibeenpwned.com",
                 bg=DARK["bg"], fg=DARK["faint"], font=(DARK["font"], 8),
                 justify="left").pack(anchor="w")

        right = tk.Frame(outer, bg=DARK["bg"])
        right.pack(side="left", fill="both", expand=True)

        tk.Label(right, text="Breach Results", bg=DARK["bg"], fg=DARK["text"],
                 font=(DARK["font"], 13, "bold")).pack(anchor="w", pady=(0,8))

        self.email_results = scrolledtext.ScrolledText(right, bg=DARK["surface"],
            fg=DARK["text"], font=(DARK["mono"], 9), bd=0, relief="flat",
            insertbackground=DARK["text"], state="disabled")
        self.email_results.pack(fill="both", expand=True)
        self.email_results.tag_configure("breach_found", foreground=DARK["error"])
        self.email_results.tag_configure("breach_clean", foreground=DARK["success"])
        self.email_results.tag_configure("breach_name",  foreground=DARK["warning"])
        self.email_results.tag_configure("header",       foreground=DARK["primary"])

    # ── REPORT TAB ────────────────────────────────────────────────────────────
    def _build_report_tab(self, parent):
        ctrl = tk.Frame(parent, bg=DARK["bg"])
        ctrl.pack(fill="x", pady=(8,4), padx=8)
        tk.Button(ctrl, text="📋 Generate Text Report", command=self._generate_report,
            bg=DARK["primary"], fg="#fff", font=(DARK["font"], 10, "bold"),
            relief="flat", padx=14, pady=5, cursor="hand2").pack(side="left", padx=4)
        tk.Button(ctrl, text="💾 Save Report (.txt)", command=self._save_report,
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["font"], 9),
            relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left", padx=4)
        tk.Button(ctrl, text="📊 Export CSV", command=self._export_csv,
            bg=DARK["surface"], fg=DARK["text"], font=(DARK["font"], 9),
            relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left", padx=4)

        self.report_text = scrolledtext.ScrolledText(parent, bg=DARK["bg"],
            fg=DARK["text"], font=(DARK["mono"], 9), bd=0, relief="flat",
            insertbackground=DARK["text"], state="disabled")
        self.report_text.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.report_text.tag_configure("header",   foreground=DARK["primary"])
        self.report_text.tag_configure("critical", foreground=DARK["critical"])
        self.report_text.tag_configure("high",     foreground=DARK["error"])
        self.report_text.tag_configure("medium",   foreground=DARK["warning"])
        self.report_text.tag_configure("low",      foreground=DARK["success"])
        self.report_text.tag_configure("info",     foreground=DARK["primary"])
        self.report_text.tag_configure("dim",      foreground=DARK["faint"])

    # ── LOGGING & FINDINGS ────────────────────────────────────────────────────
    def _log(self, message, tag="normal"):
        def _do():
            self.console.configure(state="normal")
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self.console.insert("end", f"[{ts}] ", "time")
            self.console.insert("end", f"{message}\n", tag)
            self.console.see("end")
            self.console.configure(state="disabled")
        self.after(0, _do)

    def _add_finding(self, ftype, host, finding, severity, description):
        rec = {
            "time": datetime.datetime.now().isoformat(),
            "type": ftype.upper(),
            "host": host,
            "finding": finding,
            "severity": severity.upper(),
            "description": description,
        }
        self.findings.append(rec)

        def _do():
            sev = rec["severity"]
            iid = self.tree.insert("", "end",
                values=(sev, rec["type"], rec["host"], rec["finding"], rec["description"]),
                tags=(sev,))
            # Auto-scroll to latest
            self.tree.see(iid)
            # Update KPIs
            self._refresh_kpis()
        self.after(0, _do)

    def _refresh_kpis(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            s = f["severity"]
            if s in counts:
                counts[s] += 1
        self.kpi_vars["critical"].set(str(counts["CRITICAL"]))
        self.kpi_vars["high"].set(str(counts["HIGH"]))
        self.kpi_vars["medium"].set(str(counts["MEDIUM"]))
        self.kpi_vars["low"].set(str(counts["LOW"]))
        self.kpi_vars["total"].set(str(len(self.findings)))
        self.count_label.configure(text=f"{len(self.findings)} findings")

    def _apply_filter(self):
        filt = self.filter_var.get()
        for item in self.tree.get_children():
            self.tree.delete(item)
        shown = 0
        for rec in self.findings:
            if filt == "ALL" or rec["severity"] == filt:
                self.tree.insert("", "end",
                    values=(rec["severity"], rec["type"], rec["host"],
                            rec["finding"], rec["description"]),
                    tags=(rec["severity"],))
                shown += 1
        self.count_label.configure(text=f"{shown} findings (filter: {filt})")

    def _on_finding_select(self, event):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            if vals:
                self.detail_label.configure(
                    text=f"[{vals[0]}] {vals[1]} | Host: {vals[2]} | Finding: {vals[3]}\n{vals[4]}")

    def _clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

    # ── SCAN ORCHESTRATION ────────────────────────────────────────────────────
    def _start_scan(self):
        domain = self.target_var.get().strip().lower()
        domain = re.sub(r"^https?://", "", domain).rstrip("/")
        if not domain:
            messagebox.showwarning("VulnScan Pro", "Please enter a target domain.")
            return

        # Clear old results
        self.findings.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._refresh_kpis()

        self.scan_running = True
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="● SCANNING", fg=DARK["warning"])
        self.progress.start(10)
        self.prog_label.configure(text=f"Scanning {domain}...")

        thread = threading.Thread(target=self._run_scan, args=(domain,), daemon=True)
        thread.start()

    def _stop_scan(self):
        self.scan_running = False
        self._log("Scan stopped by user.", "warn")
        self._scan_done()

    def _scan_done(self):
        def _do():
            self.scan_running = False
            self.progress.stop()
            self.scan_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_label.configure(text="● DONE", fg=DARK["success"])
            self.prog_label.configure(text=f"Complete — {len(self.findings)} findings")
        self.after(0, _do)

    def _run_scan(self, domain):
        self._log(f"═══ Starting scan: {domain} ═══", "success")
        ip = resolve_domain(domain)
        if not ip:
            self._log(f"Cannot resolve {domain} — check the domain name.", "error")
            self._scan_done()
            return
        self._log(f"Resolved {domain} → {ip}", "success")

        mods = self.mod_vars
        shodan_key = self.api_keys["shodan"].get().strip()
        vt_key = self.api_keys["virustotal"].get().strip()

        # 1. Subdomain enum
        if mods["subdomain"].get() and self.scan_running:
            self.after(0, lambda: self.prog_label.configure(text="Enumerating subdomains..."))
            subs = enumerate_subdomains(domain, self._log, self._add_finding)
        else:
            subs = [(domain, ip)]

        if not self.scan_running:
            self._scan_done(); return

        # Shodan enrichment
        if shodan_key:
            check_shodan_domain(domain, shodan_key, self._log, self._add_finding)

        # VirusTotal
        if vt_key and self.scan_running:
            check_virustotal(domain, vt_key, self._log, self._add_finding)

        # 2. Port scan on main domain + top subdomains
        if mods["ports"].get() and self.scan_running:
            self.after(0, lambda: self.prog_label.configure(text="Scanning ports..."))
            targets = [(domain, ip)] + subs[:8]  # limit to avoid rate issues
            for host, host_ip in targets:
                if not self.scan_running: break
                if host_ip:
                    check_ports = COMMON_PORTS  # full list
                    scan_ports(host, host_ip, self._log, self._add_finding, check_ports)

        if not self.scan_running:
            self._scan_done(); return

        # 3. SSL
        if mods["ssl"].get() and self.scan_running:
            self.after(0, lambda: self.prog_label.configure(text="Checking SSL/TLS..."))
            check_ssl(domain, self._log, self._add_finding)
            for sub, sub_ip in subs[:5]:
                if not self.scan_running: break
                check_ssl(sub, self._log, self._add_finding)

        # 4. DNS
        if mods["dns"].get() and self.scan_running:
            self.after(0, lambda: self.prog_label.configure(text="Checking DNS config..."))
            check_dns(domain, self._log, self._add_finding)

        # 5. HTTP headers
        if mods["headers"].get() and self.scan_running:
            self.after(0, lambda: self.prog_label.configure(text="Checking HTTP headers & paths..."))
            check_http_headers(domain, self._log, self._add_finding)
            for sub, sub_ip in subs[:3]:
                if not self.scan_running: break
                check_http_headers(sub, self._log, self._add_finding)

        self._log(f"═══ Scan complete: {len(self.findings)} findings on {domain} ═══", "success")
        self._scan_done()
        self.after(0, self._generate_report)

    # ── EMAIL BREACH CHECK ────────────────────────────────────────────────────
    def _check_emails(self):
        raw = self.email_input.get("1.0", "end").strip()
        emails = [e.strip() for e in raw.splitlines() if e.strip() and "@" in e]
        if not emails:
            messagebox.showwarning("VulnScan Pro", "Enter at least one email address.")
            return
        api_key = self.api_keys["hibp"].get().strip()

        self.email_results.configure(state="normal")
        self.email_results.delete("1.0", "end")
        self.email_results.insert("end", f"Checking {len(emails)} email(s)...\n\n", "header")
        self.email_results.configure(state="disabled")

        def run():
            for email in emails:
                breaches = check_hibp_email(email, api_key, self._log, self._add_finding)
                def _update(em=email, br=breaches):
                    self.email_results.configure(state="normal")
                    if br:
                        self.email_results.insert("end", f"⚠ {em} — {len(br)} breach(es):\n", "breach_found")
                        for b in br:
                            classes = ", ".join(b.get("DataClasses", []))
                            self.email_results.insert("end",
                                f"   • {b.get('Name','?')} ({b.get('BreachDate','?')}) — {classes[:60]}\n",
                                "breach_name")
                    else:
                        self.email_results.insert("end", f"✓ {em} — Not found in breaches\n", "breach_clean")
                    self.email_results.see("end")
                    self.email_results.configure(state="disabled")
                self.after(0, _update)
                time.sleep(1.6)  # HIBP rate limit

            self.after(0, lambda: self.email_results.configure(state="normal") or
                       self.email_results.insert("end", "\n✓ Email check complete.\n", "breach_clean") or
                       self.email_results.configure(state="disabled"))

        threading.Thread(target=run, daemon=True).start()

    # ── REPORT ────────────────────────────────────────────────────────────────
    def _generate_report(self):
        domain = self.target_var.get().strip()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        lines = []
        lines.append(("═" * 72 + "\n", "header"))
        lines.append(("  VulnScan Pro — Vulnerability Assessment Report\n", "header"))
        lines.append(("═" * 72 + "\n", "header"))
        lines.append((f"  Target    : {domain}\n", "dim"))
        lines.append((f"  Generated : {now}\n", "dim"))
        lines.append((f"  Engine    : VulnScan Pro v2.5 (OSINT + Active Scan)\n", "dim"))
        lines.append(("─" * 72 + "\n", "dim"))
        lines.append(("\n  EXECUTIVE SUMMARY\n", "header"))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            n = counts.get(sev, 0)
            tag = sev.lower() if sev != "INFO" else "info"
            lines.append((f"  {sev:<12}: {n} finding(s)\n", tag))
        lines.append((f"\n  Total Findings: {len(self.findings)}\n", "header"))
        lines.append(("─" * 72 + "\n", "dim"))
        lines.append(("\n  FINDINGS DETAIL\n", "header"))

        for i, f in enumerate(sorted(self.findings,
                key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])
                    if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99), 1):
            sev = f["severity"].lower() if f["severity"] != "INFO" else "info"
            lines.append((f"\n  [{i:03d}] [{f['severity']}] {f['type']}\n", sev))
            lines.append((f"        Host    : {f['host']}\n", "dim"))
            lines.append((f"        Finding : {f['finding']}\n", "dim"))
            lines.append((f"        Detail  : {f['description']}\n", "dim"))

        lines.append(("\n" + "─" * 72 + "\n", "dim"))
        lines.append(("  REMEDIATION GUIDANCE\n", "header"))
        remediations = {
            "CRITICAL": "Immediate action required. Patch or mitigate within 24 hours.",
            "HIGH":     "Prioritize fix within 7 days. Exploits may be publicly available.",
            "MEDIUM":   "Schedule fix within 30 days. Monitor for exploitation attempts.",
            "LOW":      "Address in next maintenance cycle.",
        }
        for sev, guidance in remediations.items():
            if counts.get(sev, 0):
                tag = sev.lower()
                lines.append((f"\n  {sev}: {guidance}\n", tag))

        lines.append(("\n" + "═" * 72 + "\n", "header"))
        lines.append(("  Generated by VulnScan Pro v2.5 | For authorized use only\n", "dim"))

        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        for text, tag in lines:
            self.report_text.insert("end", text, tag)
        self.report_text.configure(state="disabled")

        # Store for saving
        self._report_content = "".join(t for t, _ in lines)

    def _save_report(self):
        if not hasattr(self, "_report_content") or not self._report_content:
            self._generate_report()
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("All Files", "*.*")],
            initialfile=f"vulnscan_report_{self.target_var.get().replace('.','_')}.txt"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._report_content)
            messagebox.showinfo("VulnScan Pro", f"Report saved:\n{path}")

    def _export_csv(self):
        if not self.findings:
            messagebox.showwarning("VulnScan Pro", "No findings to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv"), ("All Files", "*.*")],
            initialfile=f"vulnscan_{self.target_var.get().replace('.','_')}.csv"
        )
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["time","severity","type","host","finding","description"])
                w.writeheader()
                w.writerows(self.findings)
            messagebox.showinfo("VulnScan Pro", f"CSV exported:\n{path}")

    # ── API KEY DIALOG ────────────────────────────────────────────────────────
    def _open_api_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("API Key Configuration")
        dlg.geometry("540x400")
        dlg.configure(bg=DARK["surface"])
        dlg.grab_set()

        tk.Label(dlg, text="API Key Configuration", bg=DARK["surface"], fg=DARK["text"],
                 font=(DARK["font"], 13, "bold")).pack(pady=(16,4), padx=20, anchor="w")
        tk.Label(dlg, text="Keys are stored in memory only (not saved to disk).",
                 bg=DARK["surface"], fg=DARK["muted"], font=(DARK["font"], 9)).pack(padx=20, anchor="w")

        for label, key, placeholder, url in [
            ("HaveIBeenPwned API Key", "hibp",
             "Get at haveibeenpwned.com/API/Key", "https://haveibeenpwned.com/API/Key"),
            ("Shodan API Key", "shodan",
             "Get at account.shodan.io", "https://account.shodan.io"),
            ("VirusTotal API Key", "virustotal",
             "Get at virustotal.com/gui/my-apikey", "https://www.virustotal.com/gui/my-apikey"),
        ]:
            frame = tk.Frame(dlg, bg=DARK["surface"])
            frame.pack(fill="x", padx=20, pady=(12,0))
            tk.Label(frame, text=label, bg=DARK["surface"], fg=DARK["text"],
                     font=(DARK["font"], 10, "bold")).pack(anchor="w")
            tk.Label(frame, text=placeholder, bg=DARK["surface"], fg=DARK["faint"],
                     font=(DARK["font"], 8)).pack(anchor="w")
            tk.Entry(frame, textvariable=self.api_keys[key], width=55, show="",
                bg=DARK["surface2"], fg=DARK["text"], insertbackground=DARK["text"],
                relief="flat", bd=4, font=(DARK["mono"], 9)).pack(fill="x", pady=(2,0))

        tk.Button(dlg, text="✓ Save & Close", command=dlg.destroy,
            bg=DARK["primary"], fg="#fff", font=(DARK["font"], 10, "bold"),
            relief="flat", padx=14, pady=6, cursor="hand2").pack(pady=20)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")  # suppress SSL warnings in output
    app = VulnScanApp()
    app.mainloop()
