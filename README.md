# Ettercap — Bug Bounty Automation Pipeline

> A personal recon and vulnerability scanning automation tool I put together to stop repeating the same manual steps on every new target. Give it a domain, it does the rest.

---

## What it does

Chains together all the tools I use regularly into one pipeline with 10 phases:

| Phase | What happens |
|-------|-------------|
| 1 | Subdomain enumeration via subfinder, assetfinder, amass |
| 2 | Live host detection with httpx + optional screenshots via gowitness |
| 3 | Full port scan with nmap, flags anything that isn't 80/443 |
| 4 | URL crawling with katana, gau, and waybackurls — extracts parameter URLs |
| 5 | Prints 10 targeted Google dorks for the target |
| 6 | Nuclei scan across CVE, misconfiguration, exposed panels, SSRF, XSS, SQLi tags |
| 7 | XSS testing on parameter URLs via dalfox |
| 8 | SQL injection candidates filtered with gf, tested with sqlmap |
| 9 | Subdomain takeover check via nuclei takeover templates |
| 10 | Generates a markdown report summarizing everything |

All output lands in a folder named `results_TARGET_DATE/` so nothing gets mixed up between engagements.

---

## Requirements

Python 3.8+ and any of these tools you have installed (it skips the ones it can't find):

```
subfinder    assetfinder    amass
httpx        gowitness      nmap
katana       gau            waybackurls
nuclei       dalfox         sqlmap
gf
```

Install missing Go tools:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
```

Python dependency:
```bash
pip install requests
```

---

## Usage

```bash
# Full pipeline (all 10 phases)
python3 bugbounty.py scan target.com

# Recon only — subdomains, live hosts, ports, URL crawl, dorks
python3 bugbounty.py recon target.com

# Vuln scanning only — needs existing recon output in the results folder
python3 bugbounty.py vuln target.com

# Just generate the report from an existing results folder
python3 bugbounty.py report target.com --out-dir results_target_com_2026-03-22

# Get Telegram notifications when each phase finishes
python3 bugbounty.py scan target.com --telegram --tg-token YOUR_TOKEN --tg-chat YOUR_CHAT_ID
```

The tool will ask you to confirm scope before running anything active. Pass `--skip-confirm` if you're running it in automation.

---

## Output structure

```
results_target_com_2026-03-22/
├── subdomains.txt       # all discovered subdomains
├── live.txt             # live HTTP/HTTPS hosts
├── ports.txt            # nmap results
├── urls.txt             # all crawled URLs
├── params.txt           # URLs with parameters
├── vulns.txt            # nuclei findings
├── xss.txt              # confirmed XSS via dalfox
├── sqlmap/              # sqlmap session output
├── takeovers.txt        # subdomain takeover candidates
├── screenshots/         # gowitness screenshots (if available)
└── report.md            # final report, ready to edit
```

---

## Telegram notifications

Set up a bot via `@BotFather` on Telegram, grab your chat ID from `@userinfobot`, then pass them with `--telegram --tg-token ... --tg-chat ...`. You'll get a ping after recon, after vuln scanning, and when the report is ready — useful when you kick off a scan and walk away.

---

## Disclaimer

This tool is for authorized security testing only. Only run it against targets you have explicit permission to test. I'm not responsible for how you use it.

---

**Author:** Omair Temurian
