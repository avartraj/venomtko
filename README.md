# VenomTKO — Automated Subdomain Takeover Hunter

Part of the **Venom recon toolkit**. A single-file `asyncio` Python pipeline that turns wildcard/apex domains into ranked, fingerprinted subdomain-takeover findings — or accepts a ready-made URL list and skips straight to detection.

> **Detection only** — never registers, claims, or modifies any resource.
> Run **only** against assets you are explicitly authorized to test.
<img width="2752" height="1536" alt="Gemini_Generated_Image_5o83t25o83t25o83" src="https://github.com/user-attachments/assets/ece5d324-ec91-4396-8c15-e809fe5a808d" />
---

## Features

| Feature | Description |
|---|---|
| **8-Stage Pipeline** | Input → Enumerate → Resolve → Probe → Filter → Fingerprint → Verify → Report |
| **6 Passive Sources** | crt.sh, Wayback/CDX, AlienVault OTX, HackerTarget, RapidDNS, Anubis (keyless, always on) |
| **6 CLI Tools** | subfinder, findomain, subdominator, amass, assetfinder, thexrecon (auto-detected on `$PATH`) |
| **Full CNAME Chain** | Async DNS resolution, detects NXDOMAIN **and** SERVFAIL dangling targets |
| **HTTP(S) Probing** | Follows redirects, captures status + 8KB body for fingerprinting |
| **Smart Filtering** | Keeps only hosts with CNAME + (dangling/error/known-service) — drops healthy noise |
| **Fingerprint DB** | Built-in 17 services + auto-fetch full EdOverflow community DB (76+ services) |
| **SERVFAIL Detection** | Flags SERVFAIL alongside NXDOMAIN (Azure, etc. return SERVFAIL for unclaimed resources) |
| **Wildcard DNS Guard** | Detects per-domain wildcards and warns about false-positive risk |
| **Confidence Model** | High (CNAME+body or CNAME+dangling), Medium (off-domain dangling), suppressed otherwise |
| **Cross-Check** | `--verify` with subzy and/or nuclei — independent confirmation promotes to High |
| **Outputs** | Ranked console table + JSON + CSV reports |
| **Precision-Focused** | Same-org dangling suppressed; body-only matches suppressed; non-vulnerable services ignored |
| **WSL-Friendly** | dnspython-backed HTTP resolver avoids `getaddrinfo` hangs |

---

## Pipeline Overview

```
INPUT (domains.txt or urls.txt)
  │
  ├─ domains ──► ENUMERATE (6 passive + 6 CLI sources)
  │                    │
  │                    └─► UNIFIED EXTRACTOR (regex pulls *.<domain> from any format)
  │
  └─ urls ────► use as-is (skip enumeration)
                    │
                    ▼
              RESOLVE (async DNS: A/AAAA + full CNAME chain)
                    │
                    ├─► NXDOMAIN target? ───► DANGLING SIGNAL
                    ├─► SERVFAIL target? ───► DANGLING SIGNAL
                    │
                    ▼
              HTTP(S) PROBE (HTTPS → HTTP, follow redirects)
                    │
                    ▼
              CANDIDATE FILTER
                    │  Keep: CNAME + (dangling OR 4xx/5xx OR known-service CNAME)
                    │  Drop: no CNAME, healthy 200 without known CNAME
                    │
                    ▼
              FINGERPRINT MATCH (can-i-take-over-xyz DB)
                    │
                    ├─► HIGH: CNAME → vulnerable service + (body match OR dangling)
                    ├─► MEDIUM: dangling CNAME → off-domain unknown target
                    └─► SUPPRESSED: live service, same-org dangling, body-only
                    │
                    ▼
              CROSS-CHECK (optional: subzy / nuclei)
                    │
                    └─► PROMOTE to High if confirmed
                    │
                    ▼
              REPORT (console + JSON + CSV)
```

---

## Installation

### Prerequisites
- Python 3.10+
- `pip`

### Install Dependencies
```bash
git clone https://github.com/avartraj/VenomTKO.git
cd VenomTKO
pip install -r requirements.txt
```

### Optional CLI Tools (any subset; auto-detected if on `$PATH`)
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest
cargo install findomain
# subdominator, thexrecon — per their install docs
```

### Optional Cross-Check Verifiers
```bash
go install github.com/praetorian-inc/subzy@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Usage

### Basic Commands

```bash
# 1) Enumerate + hunt from wildcard domains
python venomtko.py -i domains.txt --mode domains --confirm-authorized

# 2) Hunt from pre-enumerated URL list (skip enumeration)
python venomtko.py -i urls.txt --mode urls --confirm-authorized

# 3) Passive sources only (no external CLI tools)
python venomtko.py -i domains.txt --no-tools --confirm-authorized
```

### Advanced Usage

```bash
# Full fingerprint DB + cross-check with subzy & nuclei + custom DNS
python venomtko.py -i scope.txt --update-fingerprints --verify all \
    --resolver 1.1.1.1 -c 100 --confirm-authorized

# Custom fingerprints file
python venomtko.py -i domains.txt --fingerprints my_fingerprints.json \
    --confirm-authorized

# Specific CLI tools only
python venomtko.py -i domains.txt --tools subfinder,findomain \
    --confirm-authorized

# Flaky DNS / WSL-friendly: shorter timeout + custom resolver
python venomtko.py -i urls.txt -m urls \
    --resolver 1.1.1.1 --probe-timeout 8 -c 20 --confirm-authorized
```

### One-Time Setup
```bash
# Fetch the full community fingerprint DB (cached at ~/.venomtko/fingerprints.json)
python venomtko.py --update-fingerprints
```

---

## CLI Arguments

| Argument | Description | Default |
|---|---|---|
| `-i, --input FILE` | Input file (domains or URLs, one per line) | **Required** |
| `-m, --mode` | Input mode: `auto`, `domains`, `urls` | `auto` |
| `-f, --fingerprints FILE` | Custom fingerprints JSON path | Built-in subset |
| `--update-fingerprints` | Fetch latest can-i-take-over-xyz DB and exit | — |
| `-c, --concurrency N` | Max concurrent probes | `50` |
| `--probe-timeout SECS` | Per-host HTTP probe timeout | `15.0` |
| `--resolver IP` | Custom DNS resolver (repeatable) | System default |
| `--tools LIST` | Comma-separated external enumerators, or `all` | `all` |
| `--no-tools` | Use only passive HTTP sources | — |
| `--verify [LIST]` | Cross-check with `subzy`, `nuclei`, or `all` | — |
| `--json FILE` | JSON output path | `takeover_report.json` |
| `--csv FILE` | CSV output path | `takeover_report.csv` |
| `--all` | Write all hosts to reports (not just candidates) | — |
| `--confirm-authorized` | **Mandatory** authorization acknowledgment | **Required** |
| `-h, --help` | Show colored help screen | — |

---

## Output

### Console Report (ranked by severity)
```
================================================================================
  >> VenomTKO TAKEOVER REPORT  -  2 candidate(s) from 425 host(s)
================================================================================
  HIGH: 1   MEDIUM: 1
================================================================================

  [  HIGH] sub.victim.com  (VULNERABLE)
      service : GitHub Pages
      cname   : sub.victim.com.github.io
      status  : 404   dangling=True   (nx=True,servfail=False)
      evidence: cname,body,dangling-cname

  [ MEDIUM] api.victim.com  (review)
      service : -
      cname   : dead.unknown-cdn.net
      status  : 200   dangling=True   (nx=True,servfail=False)
      evidence: dangling-cname

  Remediation: remove or repoint the dangling DNS record, or re-claim the
  resource on the provider. Verify ownership before acting.
```

### JSON Report (`takeover_report.json`)
```json
[
  {
    "host": "sub.victim.com",
    "confidence": "high",
    "vulnerable": true,
    "matched_service": "GitHub Pages",
    "cname_chain": ["sub.victim.com.github.io"],
    "status": 404,
    "nxdomain_target": true,
    "servfail_target": false,
    "matched_on": ["cname", "body", "dangling-cname"],
    "crosscheck": ["nuclei:github-pages-takeover"],
    "final_url": "https://sub.victim.com",
    "error": null,
    "dangling": true
  }
]
```

### CSV Report (`takeover_report.csv`)
| host | confidence | vulnerable | service | cname_chain | status | matched_on |
|---|---|---|---|---|---|---|
| sub.victim.com | high | True | GitHub Pages | sub.victim.com.github.io | 404 | cname,body,dangling-cname |

---

## Enumeration Sources

### Passive HTTP Sources (built-in, always active)

| Source | Endpoint | Rate Limit |
|---|---|---|
| crt.sh | `crt.sh/?q=%25.<domain>&output=json` | None |
| Wayback Machine | `web.archive.org/cdx/search/cdx` | None |
| AlienVault OTX | `otx.alienvault.com/api/v1/indicators/domain/<domain>/passive_dns` | None |
| HackerTarget | `api.hackertarget.com/hostsearch/?q=<domain>` | Free tier: limited |
| RapidDNS | `rapiddns.io/subdomain/<domain>?full=1` | None |
| Anubis | `jldc.me/anubis/subdomains/<domain>` | None |

### External CLI Tools (auto-detected on `$PATH`)

| Tool | Command |
|---|---|
| subfinder | `subfinder -d <domain> -silent` |
| findomain | `findomain -t <domain> -q` |
| subdominator | `subdominator -d <domain>` |
| amass | `amass enum -passive -d <domain> -silent` |
| assetfinder | `assetfinder --subs-only <domain>` |
| thexrecon | `thexrecon -u <domain>` |

---

## Fingerprint Database

VenomTKO ships with **17 built-in fingerprints** for common services:

AWS/S3, GitHub Pages, Heroku, Fastly, Shopify, Zendesk, Tumblr, Surge.sh, Bitbucket, Ghost, Pantheon, WordPress, Azure (cloudapp), Readme.io, Cargo Collective, Netlify, Help Scout

For **full coverage (76+ services)**, run once:
```bash
python venomtko.py --update-fingerprints
```
This caches the community DB at `~/.venomtko/fingerprints.json` and uses it automatically thereafter.

### Custom Fingerprints Format
```json
[
  {
    "service": "MyService",
    "cname": ["myservice.com"],
    "fingerprint": ["404 Not Found", "doesn't exist"],
    "nxdomain": false,
    "vulnerable": true
  }
]
```

---

## Confidence Model

| Level | Condition | Vulnerable |
|---|---|---|
| **HIGH** | CNAME → vulnerable service **AND** (body fingerprint match **OR** dangling NXDOMAIN/SERVFAIL target) — also forced by cross-check confirmation | ✅ Yes |
| **MEDIUM** | Dangling CNAME to **off-domain** target (not a known fingerprinted service) | ❌ No (review) |
| *(suppressed)* | Live services serving normal content / same-org dangling (internal DNS hygiene) / body-only matches (generic string FP) / non-vulnerable services (Netlify, Zendesk) | ❌ |

---

## Code Structure

| File | Purpose |
|---|---|
| `venomtko.py` | Main tool (1195 lines, single-file pipeline) |
| `test_venomtko.py` | Offline logic tests (no network/DNS) |
| `requirements.txt` | Python dependencies |
| `domain.txt` | Example input file |
| `PROMPT.md` | Original build prompt |

### Core Functions in `venomtko.py`

| Function | Line | Purpose |
|---|---|---|
| `to_host()` | 338 | Normalize URL/host to bare hostname |
| `make_extractor()` | 365 | Build regex subdomain extractor for a domain |
| `src_crtsh()` | 401 | Fetch from crt.sh |
| `src_wayback()` | 408 | Fetch from Wayback CDX |
| `src_otx()` | 415 | Fetch from AlienVault OTX |
| `src_hackertarget()` | 421 | Fetch from HackerTarget |
| `src_rapiddns()` | 427 | Fetch from RapidDNS |
| `src_anubis()` | 433 | Fetch from Anubis |
| `detect_wildcard()` | 470 | Detect wildcard DNS for a domain |
| `enumerate_subdomains()` | 509 | Orchestrate all-source enumeration |
| `resolve_cname_chain()` | 535 | Async CNAME chain resolution |
| `probe_http()` | 644 | Async HTTP(S) probe |
| `is_candidate()` | 675 | Filter for takeover-worthy hosts |
| `classify()` | 697 | Assign confidence level |
| `crosscheck_subzy()` | 762 | Run subzy verification |
| `crosscheck_nuclei()` | 796 | Run nuclei takeover templates |
| `apply_crosscheck()` | 830 | Merge verifier results |
| `report()` | 932 | Console + JSON + CSV output |
| `HostResult` (dataclass) | 304 | Data model for scan results |

---

## Testing

Run the offline logic tests (no network, no DNS, no external tools):
```bash
python test_venomtko.py
```

Tests cover:
- Input normalization (`to_host`, `detect_mode`)
- Hostname extraction (`make_extractor`)
- Fingerprint loading/normalization
- Candidate filtering (`is_candidate`)
- Classification logic (`classify`) — high/medium/suppressed
- Verifier resolution

---

## Performance

| Parameter | Value |
|---|---|
| Max concurrency (default) | 50 |
| Per-host HTTP timeout (default) | 15s |
| Per-host DNS timeout | 5s |
| CNAME chain max depth | 10 |
| Body snippet size | 8 KB |
| Rate-limiting | Per-source (HackerTarget free tier capped) |

---

## Safety & Ethics

- **`--confirm-authorized` mandatory** — tool refuses to run without it
- **Detection only** — never registers, claims, or modifies any resource
- **Clear User-Agent**: `VenomTKO/1.0 (authorized-security-testing)`
- **Per-domain wildcard detection** — warns about potential false positives
- **Same-org dangling suppression** — avoids flagging internal DNS hygiene issues
- Always **manually verify** findings before any action
- Remediation: remove/repoint the dangling DNS record, or re-claim the resource on the provider

---

## Complementary Tools

| Purpose | Tools |
|---|---|
| Subdomain Enumeration | subfinder, amass, assetfinder, findomain |
| DNS Resolution | dnsx, massdns |
| HTTP Probing | httpx |
| Takeover Verification | subzy, nuclei takeover templates |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Author

**avartraj** — [GitHub](https://github.com/avartraj)

Part of the **Venom Recon Toolkit**.
