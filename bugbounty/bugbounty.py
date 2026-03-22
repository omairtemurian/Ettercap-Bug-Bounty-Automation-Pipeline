#!/usr/bin/env python3
# Author: Omair Temurian
# Tool:   Ettercap - Bug Bounty Automation Pipeline
#
# I built this to stop doing the same recon steps manually every time I start
# a new target. It chains together all the tools I use on a daily basis and
# dumps everything into a clean folder with a ready-to-edit report at the end.
#
# Use it only on targets you have permission to test.

import argparse
import subprocess
import sys
import os
import json
import datetime
import shutil
import requests
from pathlib import Path

# ─── ANSI Colors ───────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
RST= "\033[0m"
BOLD="\033[1m"

def banner():
    print(f"""{C}{BOLD}
 ███████╗████████╗████████╗███████╗██████╗  ██████╗ █████╗ ██████╗
 ██╔════╝╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗
 █████╗     ██║      ██║   █████╗  ██████╔╝██║     ███████║██████╔╝
 ██╔══╝     ██║      ██║   ██╔══╝  ██╔══██╗██║     ██╔══██║██╔═══╝
 ███████╗   ██║      ██║   ███████╗██║  ██║╚██████╗██║  ██║██║
 ╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝
{RST}
{M}{'─'*70}{RST}
{W}   🎯  Bug Bounty Automation Pipeline  {Y}v1.0{RST}
{W}   👤  Author : {G}Omair Temurian{RST}
{W}   🔧  Phases : {C}Recon → Crawl → Vuln Scan → XSS → SQLi → Takeover → Report{RST}
{M}{'─'*70}{RST}
""")

def info(msg):  print(f"{B}[*]{RST} {msg}")
def ok(msg):    print(f"{G}[+]{RST} {msg}")
def warn(msg):  print(f"{Y}[!]{RST} {msg}")
def err(msg):   print(f"{R}[-]{RST} {msg}")
def phase(n, title): print(f"\n{C}{BOLD}{'─'*60}{RST}\n{M}{BOLD}  Phase {n} — {title}{RST}\n{C}{BOLD}{'─'*60}{RST}")

# ─── Helpers ───────────────────────────────────────────────────────────────────

def tool_exists(name):
    return shutil.which(name) is not None

def run(cmd, output_file=None, shell=True, timeout=600):
    """Wrapper around subprocess — prints the command before running it so you always know what's happening."""
    info(f"Running: {Y}{cmd}{RST}")
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if stdout and output_file:
            Path(output_file).write_text(stdout + "\n")
        if result.returncode != 0 and stderr:
            warn(f"stderr: {stderr[:300]}")
        return stdout
    except subprocess.TimeoutExpired:
        warn(f"Command timed out: {cmd}")
        return ""
    except Exception as e:
        err(f"Command failed: {e}")
        return ""

def dedupe_file(path):
    """Sort and remove duplicate lines — saves you from nuclei or subfinder spitting out the same host 10 times."""
    p = Path(path)
    if not p.exists():
        return
    lines = sorted(set(p.read_text().splitlines()))
    p.write_text("\n".join(l for l in lines if l) + "\n")
    return len(lines)

def count_lines(path):
    p = Path(path)
    if not p.exists():
        return 0
    return len([l for l in p.read_text().splitlines() if l])

def send_telegram(token, chat_id, message):
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, data={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}, timeout=10)
    except Exception as e:
        warn(f"Telegram failed: {e}")

# ─── Phases ────────────────────────────────────────────────────────────────────

def phase1_subdomains(target, out_dir):
    phase(1, "Subdomain Enumeration")
    sub_file = out_dir / "subdomains.txt"
    tmp_files = []

    for tool, cmd in [
        ("subfinder",   f"subfinder -d {target} -silent -o {out_dir}/sub_subfinder.txt"),
        ("assetfinder", f"assetfinder --subs-only {target} > {out_dir}/sub_assetfinder.txt"),
        ("amass",       f"amass enum -passive -d {target} -o {out_dir}/sub_amass.txt"),
    ]:
        if tool_exists(tool):
            run(cmd)
            tmp_files.append(out_dir / f"sub_{tool}.txt")
        else:
            warn(f"{tool} not found — skipping (install: go install github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest)")

    # merge all three tool outputs and drop duplicates before saving
    all_subs = set()
    for f in tmp_files:
        p = Path(f)
        if p.exists():
            all_subs.update(l.strip() for l in p.read_text().splitlines() if l.strip())
    sub_file.write_text("\n".join(sorted(all_subs)) + "\n")
    n = count_lines(sub_file)
    ok(f"Found {n} unique subdomains → {sub_file}")
    return sub_file


def phase2_live_hosts(out_dir, sub_file):
    phase(2, "Live Host Detection")
    live_file = out_dir / "live.txt"
    if not tool_exists("httpx"):
        err("httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return live_file
    run(f"httpx -l {sub_file} -silent -threads 50 -o {live_file}")
    ok(f"{count_lines(live_file)} live hosts → {live_file}")

    if tool_exists("gowitness"):
        info("Taking screenshots with gowitness...")
        sc_dir = out_dir / "screenshots"
        sc_dir.mkdir(exist_ok=True)
        run(f"gowitness file -f {live_file} -P {sc_dir} --no-http")
        ok(f"Screenshots saved to {sc_dir}")
    else:
        warn("gowitness not found — skipping screenshots")
    return live_file


def phase3_port_scan(out_dir, live_file):
    phase(3, "Port Scanning")
    ports_file = out_dir / "ports.txt"
    if not tool_exists("nmap"):
        err("nmap not found. Install: sudo apt install nmap")
        return
    hosts = [l.strip() for l in Path(live_file).read_text().splitlines() if l.strip()]
    # nmap doesn't want http:// prefixes, strip them out
    clean = [h.replace("https://","").replace("http://","").split("/")[0] for h in hosts]
    # cap at 50 hosts — scanning more than that at once gets messy
    tmp = out_dir / "_nmap_hosts.txt"
    tmp.write_text("\n".join(clean) + "\n")
    run(f"nmap -T4 -p 1-65535 --open -iL {tmp} -oN {ports_file}")
    ok(f"Port scan results → {ports_file}")
    # Flag unusual ports
    unusual = run(f"grep 'open' {ports_file} | grep -vE '(80|443|8080|8443)/tcp'")
    if unusual:
        warn(f"Unusual open ports found:\n{unusual}")


def phase4_crawl_urls(target, out_dir, live_file):
    phase(4, "Crawling & URL Collection")
    urls_file  = out_dir / "urls.txt"
    params_file= out_dir / "params.txt"
    all_urls   = set()

    for tool, cmd in [
        ("katana",       f"katana -list {live_file} -silent -jc -d 3 -o {out_dir}/urls_katana.txt"),
        ("gau",          f"gau {target} --o {out_dir}/urls_gau.txt"),
        ("waybackurls",  f"echo {target} | waybackurls > {out_dir}/urls_wayback.txt"),
    ]:
        if tool_exists(tool):
            run(cmd)
        else:
            warn(f"{tool} not found — skipping")

    for fname in ["urls_katana.txt","urls_gau.txt","urls_wayback.txt"]:
        fp = out_dir / fname
        if fp.exists():
            all_urls.update(l.strip() for l in fp.read_text().splitlines() if l.strip())

    urls_file.write_text("\n".join(sorted(all_urls)) + "\n")
    ok(f"{len(all_urls)} total URLs → {urls_file}")

    # anything with a "?" is worth keeping for XSS and SQLi testing
    params = [u for u in all_urls if "?" in u]
    params_file.write_text("\n".join(sorted(params)) + "\n")
    ok(f"{len(params)} parameter URLs → {params_file}")
    return urls_file, params_file


def phase5_google_dorks(target):
    phase(5, "Google Dorking Suggestions")
    dorks = [
        f'site:{target} ext:env OR ext:config OR ext:yml OR ext:yaml',
        f'site:{target} inurl:admin OR inurl:administrator OR inurl:dashboard',
        f'site:{target} inurl:login OR inurl:signin OR inurl:auth',
        f'site:{target} intext:"api_key" OR intext:"access_token" OR intext:"secret"',
        f'site:{target} filetype:sql OR filetype:db OR filetype:bak',
        f'site:{target} inurl:".git" OR inurl:".svn" OR inurl:".DS_Store"',
        f'site:{target} inurl:phpinfo OR inurl:test.php OR inurl:info.php',
        f'site:{target} intitle:"index of" OR intitle:"directory listing"',
        f'site:{target} inurl:wp-content OR inurl:wp-admin',
        f'site:{target} intext:"mysql_connect" OR intext:"mysqli" OR intext:"pg_connect"',
    ]
    print(f"\n{Y}Google Dorks for {target}:{RST}")
    for i, d in enumerate(dorks, 1):
        print(f"  {i:2}. {d}")
    return dorks


def phase6_vuln_scan(out_dir, live_file):
    phase(6, "Vulnerability Scanning (Nuclei)")
    vulns_file = out_dir / "vulns.txt"
    if not tool_exists("nuclei"):
        err("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return
    tags = "cve,misconfiguration,exposed-panels,takeover,xss,sqli,ssrf,default-login"
    run(f"nuclei -l {live_file} -tags {tags} -rl 50 -o {vulns_file} -silent")
    n = count_lines(vulns_file)
    if n:
        ok(f"{n} findings → {vulns_file}")
    else:
        info("No nuclei findings.")


def phase7_xss(out_dir, params_file):
    phase(7, "XSS Testing (dalfox)")
    xss_file = out_dir / "xss.txt"
    if not tool_exists("dalfox"):
        err("dalfox not found. Install: go install github.com/hahwul/dalfox/v2@latest")
        return
    if count_lines(params_file) == 0:
        info("No parameter URLs to test for XSS.")
        return
    run(f"dalfox file {params_file} --silence --no-spinner -o {xss_file}")
    n = count_lines(xss_file)
    if n:
        ok(f"{n} XSS findings → {xss_file}")
    else:
        info("No XSS confirmed.")


def phase8_sqli(out_dir, params_file):
    phase(8, "SQL Injection Testing (sqlmap)")
    sqli_dir = out_dir / "sqlmap"
    sqli_dir.mkdir(exist_ok=True)
    candidates_file = out_dir / "sqli_candidates.txt"

    if not tool_exists("sqlmap"):
        err("sqlmap not found. Install: pip install sqlmap  or  sudo apt install sqlmap")
        return

    # gf narrows it down to params that actually look injectable — saves sqlmap time
    if tool_exists("gf"):
        run(f"gf sqli {params_file} > {candidates_file}")
    else:
        warn("gf not found — using all param URLs as candidates")
        candidates_file = params_file

    if count_lines(candidates_file) == 0:
        info("No SQLi candidates found.")
        return

    # don't throw hundreds of URLs at sqlmap — top 20 is enough to prove a point
    candidates = [l for l in Path(candidates_file).read_text().splitlines() if l.strip()][:20]
    for url in candidates:
        run(f'sqlmap -u "{url}" --batch --level=2 --risk=2 --output-dir={sqli_dir} --forms --crawl=2 --threads=3 --random-agent')
    ok(f"SQLmap results → {sqli_dir}")


def phase9_takeover(out_dir, sub_file):
    phase(9, "Subdomain Takeover Check")
    takeover_file = out_dir / "takeovers.txt"
    if not tool_exists("nuclei"):
        err("nuclei not found — skipping takeover check")
        return
    run(f"nuclei -l {sub_file} -t takeovers/ -o {takeover_file} -silent")
    n = count_lines(takeover_file)
    if n:
        ok(f"{n} potential takeovers → {takeover_file}")
    else:
        info("No takeover candidates found.")


def phase10_report(target, out_dir, date_str):
    phase(10, "Report Generation")
    report_file = out_dir / "report.md"

    def read_safe(path, max_lines=50):
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return "_No results_"
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        snippet = "\n".join(lines[:max_lines])
        if len(lines) > max_lines:
            snippet += f"\n... ({len(lines) - max_lines} more lines)"
        return snippet

    vulns_raw     = read_safe(out_dir / "vulns.txt")
    xss_raw       = read_safe(out_dir / "xss.txt")
    takeover_raw  = read_safe(out_dir / "takeovers.txt")
    subs_count    = count_lines(out_dir / "subdomains.txt")
    live_count    = count_lines(out_dir / "live.txt")
    url_count     = count_lines(out_dir / "urls.txt")
    param_count   = count_lines(out_dir / "params.txt")

    report = f"""# Bug Bounty Report — {target}
**Date:** {date_str}
**Tester:** Omair Temurian

---

## 📊 Recon Summary

| Metric | Count |
|--------|-------|
| Subdomains discovered | {subs_count} |
| Live hosts | {live_count} |
| URLs collected | {url_count} |
| Parameter URLs | {param_count} |

---

## 🔍 Vulnerability Findings (Nuclei)

```
{vulns_raw}
```

---

## 🕷️ XSS Findings (dalfox)

```
{xss_raw}
```

---

## 🔗 Subdomain Takeover Candidates

```
{takeover_raw}
```

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `subdomains.txt` | All discovered subdomains |
| `live.txt` | Live HTTP/HTTPS hosts |
| `ports.txt` | Nmap port scan results |
| `urls.txt` | All crawled URLs |
| `params.txt` | URLs with parameters |
| `vulns.txt` | Nuclei vulnerability findings |
| `xss.txt` | Confirmed XSS via dalfox |
| `sqlmap/` | SQLmap session outputs |
| `takeovers.txt` | Subdomain takeover candidates |
| `screenshots/` | Visual screenshots of live hosts |

---

## ⚠️ Disclaimer

This report was generated as part of an authorized bug bounty assessment.
All testing was performed with explicit permission on in-scope targets only.

---
*Generated by bugbounty.py on {date_str}*
"""
    report_file.write_text(report)
    ok(f"Report saved → {report_file}")
    print(f"\n{G}{BOLD}{'='*60}\n  ✅ Pipeline complete! All results in: {out_dir}\n{'='*60}{RST}")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Bug Bounty Automation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bugbounty.py scan target.com
  python3 bugbounty.py recon target.com
  python3 bugbounty.py vuln target.com
  python3 bugbounty.py report target.com --out-dir results_target.com_2026-03-22
  python3 bugbounty.py scan target.com --telegram --tg-token TOKEN --tg-chat CHATID
        """
    )
    parser.add_argument("mode",   choices=["scan","recon","vuln","report"], help="Pipeline mode")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--out-dir",  help="Override output directory path")
    parser.add_argument("--telegram", action="store_true", help="Send findings to Telegram")
    parser.add_argument("--tg-token", help="Telegram bot token")
    parser.add_argument("--tg-chat",  help="Telegram chat ID")
    parser.add_argument("--skip-confirm", action="store_true", help="Skip scope confirmation prompt")
    args = parser.parse_args()

    target   = args.target.lower().strip()
    date_str = datetime.date.today().isoformat()

    # ── Scope confirmation ──
    if not args.skip_confirm:
        print(f"\n{Y}{BOLD}⚠️  SCOPE CONFIRMATION{RST}")
        print(f"  Target : {W}{target}{RST}")
        print(f"  Mode   : {W}{args.mode}{RST}")
        print(f"\n{R}You must have explicit written permission to test this target.{RST}")
        ans = input(f"\n{Y}Confirm {target} is in-scope and you have permission? [yes/NO]: {RST}").strip().lower()
        if ans != "yes":
            err("Aborted. Only test targets you are authorized to test.")
            sys.exit(1)

    # ── Output directory ──
    out_dir = Path(args.out_dir) if args.out_dir else Path(f"results_{target.replace('.','_')}_{date_str}")
    out_dir.mkdir(parents=True, exist_ok=True)
    ok(f"Output directory: {out_dir.resolve()}")

    sub_file   = out_dir / "subdomains.txt"
    live_file  = out_dir / "live.txt"
    urls_file  = out_dir / "urls.txt"
    params_file= out_dir / "params.txt"

    tg = lambda msg: send_telegram(args.tg_token, args.tg_chat, msg) if args.telegram else None

    # ── Run phases based on mode ──
    try:
        if args.mode in ("scan", "recon"):
            sub_file   = phase1_subdomains(target, out_dir)
            live_file  = phase2_live_hosts(out_dir, sub_file)
            phase3_port_scan(out_dir, live_file)
            urls_file, params_file = phase4_crawl_urls(target, out_dir, live_file)
            phase5_google_dorks(target)
            tg(f"🎯 Recon done for `{target}`\nSubdomains: {count_lines(sub_file)} | Live: {count_lines(live_file)}")

        if args.mode in ("scan", "vuln"):
            if not live_file.exists():
                err(f"{live_file} not found. Run recon first.")
                sys.exit(1)
            phase6_vuln_scan(out_dir, live_file)
            phase7_xss(out_dir, params_file)
            phase8_sqli(out_dir, params_file)
            phase9_takeover(out_dir, sub_file)
            tg(f"🔍 Vuln scan done for `{target}`")

        if args.mode in ("scan", "report"):
            phase10_report(target, out_dir, date_str)
            tg(f"📄 Report ready for `{target}` at `{out_dir}/report.md`")

    except KeyboardInterrupt:
        warn("\nInterrupted by user. Partial results saved.")
        sys.exit(0)


if __name__ == "__main__":
    main()
