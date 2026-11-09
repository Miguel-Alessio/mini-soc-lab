#!/usr/bin/env python3
"""
SOC Engine - detectie SSH Brute Force + atacuri Web (LFI / SQLi)
cu raspuns automat (SOAR) prin iptables pe nodul victima.

Rulare:
    python3 scripts/soc_engine.py --config configs/config.json
    python3 scripts/soc_engine.py --dry-run      # detecteaza, dar nu blocheaza
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict

DEFAULT_CONFIG = os.environ.get("SOC_CONFIG", "configs/config.json")
ALLOWED_PORTS = {22, 80}

IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"
SSH_FAIL_REGEX = re.compile(
    rf"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from ({IP_RE})"
)
NGINX_REGEX = re.compile(
    rf"nginx_access:\s+({IP_RE})\s+-\s+\S+\s+\[.*?\]\s+\"(\w+)\s+(.*?)\s+HTTP/[^\"]*\"\s+(\d{{3}})"
)

LFI_PATTERNS = [r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow", r"/proc/self"]
SQLI_PATTERNS = [
    r"union\s+select",
    r"'\s*or\s*'?1'?\s*=\s*'?1",
    r"--(?:\s|$)",          # comentariu SQL la final / urmat de spatiu (mai putine FP decat "--")
    r"/\*.*?\*/",
    r";\s*drop\s+table",
    r";\s*select",
]
LFI_REGEX = re.compile("|".join(LFI_PATTERNS), re.IGNORECASE)
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


# ---------------------------------------------------------------- config

def load_config(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[FATAL] Config inexistent: {path} (copiaza configs/config.example.json)")
    except json.JSONDecodeError as e:
        sys.exit(f"[FATAL] JSON invalid in {path}: {e}")

    for key in ("log_file", "target", "whitelist", "ssh_bruteforce", "response"):
        if key not in cfg:
            sys.exit(f"[FATAL] Lipseste cheia '{key}' din {path}")
    return cfg


def parse_ip(value):
    """Returneaza un obiect IP valid sau None. Nimic nevalidat nu ajunge in comenzi."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


# ---------------------------------------------------------------- engine

class SocEngine:
    def __init__(self, cfg, force_dry_run=False):
        target = cfg["target"]
        self.target_host = target["host"]
        self.target_user = target["user"]
        self.ssh_key = os.path.expanduser(target.get("ssh_key", "~/.ssh/id_ed25519"))

        try:
            self.whitelist = [ipaddress.ip_network(n, strict=False) for n in cfg["whitelist"]]
        except ValueError as e:
            sys.exit(f"[FATAL] Whitelist invalid: {e}")

        bf = cfg["ssh_bruteforce"]
        self.threshold = int(bf["threshold"])
        self.window = float(bf["window_seconds"])

        resp = cfg["response"]
        self.response_enabled = bool(resp.get("enabled", True))
        self.dry_run = force_dry_run or bool(resp.get("dry_run", False))

        self.log_file = cfg["log_file"]
        self.failed_attempts = defaultdict(list)
        self.blocked = set()  # {(ip, port)} blocate in sesiunea curenta

    # ---------- helpers

    def is_whitelisted(self, ip):
        return any(ip in net for net in self.whitelist)

    def block_ip(self, ip_str, port):
        ip = parse_ip(ip_str)
        if ip is None:
            print(f"[ACTION SKIP] IP invalid, nu se executa nimic: {ip_str!r}")
            return
        if port not in ALLOWED_PORTS:
            print(f"[ACTION SKIP] Port nepermis: {port}")
            return
        if self.is_whitelisted(ip):
            print(f"[ACTION SKIP] {ip} este in whitelist, refuz blocarea")
            return
        if (str(ip), port) in self.blocked:
            print(f"[ACTION SKIP] {ip} deja blocat pe portul {port}")
            return
        if not self.response_enabled:
            print(f"[DETECT ONLY] Raspunsul automat e dezactivat ({ip}:{port})")
            return
        if self.dry_run:
            print(f"[DRY-RUN] As bloca {ip} pe portul {port} (victima: {self.target_host})")
            self.blocked.add((str(ip), port))
            return

        # -C verifica daca regula exista deja; -I INPUT 1 o pune inaintea regulii
        # ESTABLISHED,RELATED, deci taie si conexiunile deja deschise ale atacatorului.
        spec = f"-s {ip} -p tcp --dport {port} -j DROP"
        remote_cmd = f"sudo iptables -C INPUT {spec} 2>/dev/null || sudo iptables -I INPUT 1 {spec}"
        cmd = [
            "ssh",
            "-i", self.ssh_key,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5",
            f"{self.target_user}@{self.target_host}",
            remote_cmd,
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            print(f"[ACTION ERROR] Timeout SSH catre {self.target_host}")
            return

        if res.returncode == 0:
            self.blocked.add((str(ip), port))
            print(f"[ACTION SUCCESS] IP {ip} blocat pe portul {port} (victima: {self.target_host})")
        else:
            print(f"[ACTION ERROR] {res.stderr.strip()}")

    # ---------- detectie SSH

    def handle_ssh_fail(self, user, src_ip):
        ip = parse_ip(src_ip)
        if ip is None:
            return
        if self.is_whitelisted(ip):
            print(f"[-] [FALSE POSITIVE] Esec SSH ignorat de la IP din whitelist: {ip}")
            return

        now = time.time()
        attempts = [t for t in self.failed_attempts[src_ip] if now - t <= self.window]
        attempts.append(now)
        self.failed_attempts[src_ip] = attempts

        print(f"[!] [ALERT - SSH] Esec #{len(attempts)} pentru '{user}' de la {src_ip}")
        if len(attempts) >= self.threshold:
            print(f"\n[CRITICAL INCIDENT] SSH Brute Force de la {src_ip} - Blocare declansata")
            self.block_ip(src_ip, 22)
            self.failed_attempts[src_ip].clear()

    # ---------- detectie Web

    def handle_web(self, src_ip, method, raw_uri, status_code):
        ip = parse_ip(src_ip)
        if ip is None:
            return
        uri = urllib.parse.unquote_plus(raw_uri)

        if self.is_whitelisted(ip):
            print(f"[-] [FALSE POSITIVE] Trafic web ignorat de la IP din whitelist: {ip}")
            return

        for name, regex in (("Local File Inclusion / Traversal", LFI_REGEX),
                            ("SQL Injection", SQLI_REGEX)):
            if regex.search(uri):
                print("\n" + "!" * 50)
                print(f"[CRITICAL WEB INCIDENT] {name} detectat!")
                print(f"[*] Sursa: {src_ip} | Metoda: {method} | Cod HTTP: {status_code}")
                print(f"[*] URI: {uri}")
                print("!" * 50 + "\n")
                self.block_ip(src_ip, 80)
                return

        if status_code.startswith("4"):
            print(f"[*] [SUSPICIOUS_WEB] Client error ({status_code}) de la {src_ip}: {method} {uri}")
        elif status_code.startswith("2"):
            print(f"[-] [BENIGN_WEB] Trafic legitim ({status_code}) de la {src_ip}: {method} {uri}")

    # ---------- dispatcher

    def process_line(self, line):
        m = SSH_FAIL_REGEX.search(line)
        if m:
            self.handle_ssh_fail(*m.groups())
            return
        m = NGINX_REGEX.search(line)
        if m:
            self.handle_web(*m.groups())


# ---------------------------------------------------------------- log tailing

def follow(path):
    """tail -F: urmareste fisierul si il redeschide dupa logrotate / truncare."""
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    buf = ""

    while True:
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                yield buf
                buf = ""
            continue

        time.sleep(0.5)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue  # fisierul e in curs de rotire
        if st.st_ino != inode or st.st_size < f.tell():
            f.close()
            f = open(path, "r", errors="replace")
            inode = os.fstat(f.fileno()).st_ino
            buf = ""
            print("[i] Fisier de log rotit/trunchiat - redeschis")


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description="Mini-SOC detection & response engine")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="cale catre config.json")
    parser.add_argument("--dry-run", action="store_true", help="detecteaza fara sa blocheze")
    args = parser.parse_args()

    sys.stdout.reconfigure(line_buffering=True)  # output imediat in journalctl

    engine = SocEngine(load_config(args.config), force_dry_run=args.dry_run)
    mode = "DRY-RUN" if engine.dry_run else ("ACTIV" if engine.response_enabled else "DETECT ONLY")
    print(f"[+] SOC Engine v4 (SSH + Web IDS/IPS) pe lab-server | mod: {mode}")
    print(f"[+] Log: {engine.log_file} | Victima: {engine.target_host} | "
          f"Prag SSH: {engine.threshold}/{engine.window:g}s")

    try:
        for line in follow(engine.log_file):
            engine.process_line(line)
    except PermissionError:
        sys.exit(f"[FATAL] Fara drept de citire pe {engine.log_file} (adauga userul in grupul adm)")
    except KeyboardInterrupt:
        print("\n[+] Oprit.")


if __name__ == "__main__":
    main()
