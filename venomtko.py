#!/usr/bin/env python3
"""
VenomTKO - Automated subdomain takeover hunter (v1.0).

Part of the Venom recon toolkit. A single-file asyncio pipeline that turns a
list of wildcard/apex domains (or ready-made URLs) into ranked, fingerprinted
subdomain-takeover findings.

Pipeline:
  1. INPUT      : accept a list of apex/wildcard domains OR a list of URLs/hosts.
  2. ENUMERATE  : if domains -> discover subdomains (6 passive sources + optional
                  CLI tools), with a per-domain wildcard-DNS false-positive guard.
  3. RESOLVE    : async-resolve A/AAAA + full CNAME chain; flag NXDOMAIN *and*
                  SERVFAIL dangling targets (both are classic takeover signals).
  4. PROBE      : async HTTP(S) probe -> status code, final URL, body snippet.
  5. FILTER     : keep "dangling candidates" (dangling CNAME target, an error
                  status with a CNAME, or a CNAME that points at a known service).
  6. FINGERPRINT: match CNAME + body against the can-i-take-over-xyz DB. The full
                  community DB can be auto-fetched with --update-fingerprints.
  7. VERIFY     : assign confidence (high/medium/low); optionally cross-check every
                  high/medium finding with subzy and/or nuclei takeover templates.
  8. REPORT     : console table + JSON + CSV, with remediation guidance.

DETECTION ONLY. This tool never registers, claims, or modifies any resource.
Only run it against assets you are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse

# ---- third-party deps (see requirements.txt) -------------------------------
try:
    import aiohttp
except ImportError:  # pragma: no cover
    sys.exit("[!] Missing dependency 'aiohttp'. Run: pip install -r requirements.txt")

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
except ImportError:  # pragma: no cover
    sys.exit("[!] Missing dependency 'dnspython'. Run: pip install -r requirements.txt")


# ===========================================================================
# Hacker-vibe terminal colors
# ===========================================================================
# Zero-dependency ANSI styling. Colour is on by default; disabled by the NO_COLOR
# env var, or automatically when stdout is not a TTY (keeps redirected output clean).
NAME = "VenomTKO"
VERSION = "1.0"


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[38;5;46m"     # matrix green
    LIME = "\033[38;5;118m"
    DGREEN = "\033[38;5;28m"
    RED = "\033[38;5;196m"
    YELLOW = "\033[38;5;226m"
    ORANGE = "\033[38;5;208m"
    CYAN = "\033[38;5;51m"
    MAGENTA = "\033[38;5;201m"
    GREY = "\033[38;5;244m"
    WHITE = "\033[97m"


_USE_COLOR = True


def _enable_windows_ansi() -> None:
    """Turn on virtual-terminal processing so ANSI codes render on Windows."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        for handle in (-11, -12):  # STDOUT, STDERR
            kernel32.SetConsoleMode(kernel32.GetStdHandle(handle), 7)
    except Exception:  # noqa: BLE001
        pass


def init_color(enabled: bool) -> None:
    global _USE_COLOR
    _USE_COLOR = bool(enabled) and os.environ.get("NO_COLOR") is None
    if _USE_COLOR:
        _enable_windows_ansi()


def col(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes (no-op when colour is disabled)."""
    if not _USE_COLOR or not codes:
        return text
    return "".join(codes) + text + C.RESET


def banner() -> None:
    """Print the VenomTKO ASCII banner to stderr."""
    art = r"""
 ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗████████╗██╗  ██╗ ██████╗
 ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║╚══██╔══╝██║ ██╔╝██╔═══██╗
 ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║   ██║   █████╔╝ ██║   ██║
 ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║   ██║   ██╔═██╗ ██║   ██║
  ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║   ██║   ██║  ██╗╚██████╔╝
   ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝
"""
    sub = (f"  {NAME} v{VERSION}  ::  subdomain takeover hunter  ::  "
           f"detection only  ::  venom recon toolkit")
    print(col(art, C.GREEN, C.BOLD), file=sys.stderr)
    print(col(sub, C.DGREEN), file=sys.stderr)
    print(col("  [ use only on assets you are authorized to test ]\n",
              C.GREY, C.DIM), file=sys.stderr)


# Coloured stderr log helpers -------------------------------------------------
def log_info(msg: str) -> None:
    print(col("[*] ", C.CYAN, C.BOLD) + col(msg, C.GREY), file=sys.stderr)


def log_good(msg: str) -> None:
    print(col("[+] ", C.GREEN, C.BOLD) + col(msg, C.LIME), file=sys.stderr)


def log_warn(msg: str) -> None:
    print(col("[!] ", C.YELLOW, C.BOLD) + col(msg, C.YELLOW), file=sys.stderr)


def log_err(msg: str) -> None:
    print(col("[x] ", C.RED, C.BOLD) + col(msg, C.RED), file=sys.stderr)


# ===========================================================================
# Fingerprints
# ===========================================================================
# A representative subset modelled on EdOverflow's can-i-take-over-xyz project.
# Each normalised entry carries: service name, CNAME substrings that point at the
# service, HTTP body fingerprint strings, an `nxdomain` flag (services whose ONLY
# takeover signal is a non-resolving CNAME target, e.g. some Azure resources), and
# whether the service is currently considered exploitable (`vulnerable`).
#
# For full, current coverage, fetch the community DB once with:
#   python venomtko.py --update-fingerprints
# (cached at ~/.venomtko/fingerprints.json and used automatically thereafter), or
# point at any file with --fingerprints path.json.
FINGERPRINT_DB_URL = (
    "https://raw.githubusercontent.com/EdOverflow/"
    "can-i-take-over-xyz/master/fingerprints.json"
)
FINGERPRINT_CACHE = Path.home() / ".venomtko" / "fingerprints.json"

DEFAULT_FINGERPRINTS: list[dict] = [
    {"service": "AWS/S3", "cname": ["amazonaws.com"],
     "fingerprint": ["The specified bucket does not exist", "NoSuchBucket"],
     "nxdomain": False, "vulnerable": True},
    {"service": "GitHub Pages", "cname": ["github.io", "githubusercontent"],
     "fingerprint": ["There isn't a GitHub Pages site here",
                     "For root URLs (like http://example.com/) you must provide an index.html file"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokussl.com", "herokudns.com"],
     "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Fastly", "cname": ["fastly.net"],
     "fingerprint": ["Fastly error: unknown domain"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "fingerprint": ["Sorry, this shop is currently unavailable",
                     "Only one step left!"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Zendesk", "cname": ["zendesk.com"],
     "fingerprint": ["Help Center Closed"],
     "nxdomain": False, "vulnerable": False},
    {"service": "Tumblr", "cname": ["domains.tumblr.com"],
     "fingerprint": ["Whatever you were looking for doesn't currently exist at this address",
                     "There's nothing here."],
     "nxdomain": False, "vulnerable": True},
    {"service": "Surge.sh", "cname": ["surge.sh"],
     "fingerprint": ["project not found"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "fingerprint": ["Repository not found"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Ghost", "cname": ["ghost.io"],
     "fingerprint": ["The thing you were looking for is no longer here, or never was"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "fingerprint": ["The gods are wise", "404 error unknown site!"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Wordpress", "cname": ["wordpress.com"],
     "fingerprint": ["Do you want to register"],
     "nxdomain": False, "vulnerable": False},
    {"service": "Azure (cloudapp)", "cname": ["cloudapp.net", "cloudapp.azure.com",
                                              "azurewebsites.net", "trafficmanager.net",
                                              "blob.core.windows.net", "azure-api.net",
                                              "azureedge.net", "azurefd.net"],
     "fingerprint": ["404 Web Site not found", "The specified blob does not exist",
                     "Our services aren't available right now"],
     "nxdomain": True, "vulnerable": True},
    {"service": "Readme.io", "cname": ["readme.io"],
     "fingerprint": ["Project doesnt exist... yet!"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Cargo Collective", "cname": ["cargocollective.com"],
     "fingerprint": ["404 Not Found", "If you're moving your domain away from Cargo"],
     "nxdomain": False, "vulnerable": True},
    {"service": "Netlify", "cname": ["netlify.app", "netlify.com"],
     "fingerprint": ["Not Found - Request ID"],
     "nxdomain": False, "vulnerable": False},
    {"service": "Help Scout", "cname": ["helpscoutdocs.com"],
     "fingerprint": ["No settings were found for this company"],
     "nxdomain": False, "vulnerable": True},
]


def _as_list(value) -> list[str]:
    """Coerce a fingerprint field that may be a str, list, or None into a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [v for v in value if v]


def _as_bool(value) -> bool:
    """Coerce the community DB's mixed bool/str truthiness into a real bool."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def normalise_fingerprints(entries: list[dict]) -> list[dict]:
    """Normalise raw can-i-take-over-xyz entries into the shape classify() expects."""
    out: list[dict] = []
    for e in entries:
        out.append({
            "service": e.get("service", "unknown"),
            "cname": [c.lower() for c in _as_list(e.get("cname"))],
            "fingerprint": [f.lower() for f in _as_list(e.get("fingerprint"))],
            "nxdomain": _as_bool(e.get("nxdomain")),
            "vulnerable": _as_bool(e.get("vulnerable")),
        })
    return out


def update_fingerprints(dest: Path = FINGERPRINT_CACHE) -> int:
    """Fetch the live can-i-take-over-xyz DB and cache it locally. Returns count."""
    req = urllib.request.Request(
        FINGERPRINT_DB_URL,
        headers={"User-Agent": "VenomTKO/1.0 (authorized-security-testing)"},
    )
    log_info(f"Fetching fingerprint DB from {FINGERPRINT_DB_URL} ...")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted URL)
        raw = json.loads(resp.read().decode("utf-8", errors="ignore"))
    entries = raw.get("fingerprints", raw) if isinstance(raw, dict) else raw
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    log_good(f"Cached {len(entries)} fingerprint signature(s) to {dest}")
    return len(entries)


def load_fingerprints(path: str | None) -> list[dict]:
    """Load fingerprints, preferring (1) explicit path, (2) cached community DB,
    (3) the built-in default subset."""
    source = path or (str(FINGERPRINT_CACHE) if FINGERPRINT_CACHE.exists() else None)
    if not source:
        return normalise_fingerprints(DEFAULT_FINGERPRINTS)
    try:
        with open(source, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log_warn(f"Could not read fingerprints from {source}: {exc}; "
                 f"using built-in subset.")
        return normalise_fingerprints(DEFAULT_FINGERPRINTS)
    entries = raw.get("fingerprints", raw) if isinstance(raw, dict) else raw
    out = normalise_fingerprints(entries)
    return out or normalise_fingerprints(DEFAULT_FINGERPRINTS)


# ===========================================================================
# Data model
# ===========================================================================
ERROR_STATUSES = {400, 401, 403, 404, 410, 500, 502, 503, 504}


@dataclass
class HostResult:
    host: str
    cname_chain: list[str] = field(default_factory=list)
    resolved: bool = False
    nxdomain_target: bool = False        # CNAME present but final target is NXDOMAIN
    servfail_target: bool = False        # CNAME present but final target is SERVFAIL
    status: int | None = None
    final_url: str | None = None
    error: str | None = None
    matched_service: str | None = None
    matched_on: list[str] = field(default_factory=list)  # cname | body | dangling-cname
    crosscheck: list[str] = field(default_factory=list)  # subzy/nuclei verdicts
    confidence: str = "none"             # high | medium | low | none
    vulnerable: bool = False

    @property
    def dangling(self) -> bool:
        """A non-resolving CNAME target (NXDOMAIN or SERVFAIL) is the core signal."""
        return self.nxdomain_target or self.servfail_target


# ===========================================================================
# Stage 1 - input handling
# ===========================================================================
def read_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def looks_like_url(line: str) -> bool:
    return line.lower().startswith(("http://", "https://"))


def to_host(line: str) -> str:
    """Normalise a URL or host line down to a bare hostname."""
    if looks_like_url(line):
        return (urlparse(line).hostname or line).lower()
    host = line.split("/")[0].strip().lower()
    if host.startswith("*."):
        host = host[2:]
    return host


def detect_mode(lines: list[str], forced: str) -> str:
    if forced != "auto":
        return forced
    url_like = sum(1 for ln in lines if looks_like_url(ln))
    # If most lines are full URLs, assume the user already enumerated.
    return "urls" if url_like >= max(1, len(lines) // 2) else "domains"


# ===========================================================================
# Stage 2 - enumeration (domains mode)
# ===========================================================================
# Goal: gather as many subdomains as possible from many independent sources,
# then dedupe + validate. Two families of sources:
#   (A) keyless passive HTTP sources  -> run in-process via aiohttp
#   (B) external CLI tools (if on PATH) -> shelled out, output parsed
# Every source is best-effort: a failure in one never aborts the run.

def make_extractor(domain: str):
    """Build a function that pulls every hostname ending in `domain` out of text.

    Works on raw JSON, HTML, CSV or URL lists alike, so the same parser handles
    crt.sh, wayback URLs, passive-DNS APIs and CLI tool output uniformly.
    """
    pat = re.compile(r"(?:[a-z0-9_*\-]+\.)+" + re.escape(domain.lower()))

    def extract(text: str) -> set[str]:
        # Some sources escape separators as literal "\n" / "\t" in the body;
        # turn those into spaces so a stray 'n'/'t' can't fuse onto a label.
        text = re.sub(r"\\[nrtfv]", " ", text.lower())
        out: set[str] = set()
        for raw in pat.findall(text):
            host = raw.replace("*.", "").strip(".")
            if host.endswith(domain.lower()) and " " not in host \
                    and re.fullmatch(r"[a-z0-9_\-\.]+", host):
                out.add(host)
        return out

    return extract


# ---- (A) keyless passive HTTP sources -------------------------------------
async def _fetch_text(session: aiohttp.ClientSession, url: str, label: str,
                      domain: str) -> str:
    try:
        async with session.get(url, ssl=False) as resp:
            if resp.status != 200:
                return ""
            return await resp.text(errors="ignore")
    except Exception as exc:  # noqa: BLE001
        print(col(f"    [{label}] {domain}: {exc}", C.GREY, C.DIM), file=sys.stderr)
        return ""


async def src_crtsh(session, domain, extract) -> set[str]:
    """crt.sh certificate-transparency logs."""
    txt = await _fetch_text(session, f"https://crt.sh/?q=%25.{domain}&output=json",
                            "crt.sh", domain)
    return extract(txt)


async def src_wayback(session, domain, extract) -> set[str]:
    """Wayback Machine CDX archive (historical URLs reveal old subdomains)."""
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=text&fl=original&collapse=urlkey")
    return extract(await _fetch_text(session, url, "wayback", domain))


async def src_otx(session, domain, extract) -> set[str]:
    """AlienVault OTX passive DNS."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    return extract(await _fetch_text(session, url, "otx", domain))


async def src_hackertarget(session, domain, extract) -> set[str]:
    """HackerTarget hostsearch (free tier is rate-limited)."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    return extract(await _fetch_text(session, url, "hackertarget", domain))


async def src_rapiddns(session, domain, extract) -> set[str]:
    """RapidDNS subdomain index (HTML)."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    return extract(await _fetch_text(session, url, "rapiddns", domain))


async def src_anubis(session, domain, extract) -> set[str]:
    """Anubis (jldc.me) aggregated passive subdomains."""
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    return extract(await _fetch_text(session, url, "anubis", domain))


PASSIVE_SOURCES = [src_crtsh, src_wayback, src_otx,
                   src_hackertarget, src_rapiddns, src_anubis]


# ---- (B) external CLI tools (run only if found on PATH) --------------------
# argv templates; {d} is substituted with the domain. Flags reflect common
# versions -- adjust per your installed build if a tool changes its interface.
EXTERNAL_TOOLS: dict[str, list[str]] = {
    "subfinder":    ["subfinder", "-d", "{d}", "-silent"],
    "findomain":    ["findomain", "-t", "{d}", "-q"],
    "subdominator": ["subdominator", "-d", "{d}"],
    "amass":        ["amass", "enum", "-passive", "-d", "{d}", "-silent"],
    "assetfinder":  ["assetfinder", "--subs-only", "{d}"],
    "thexrecon":    ["thexrecon", "-u", "{d}"],
}


def run_external_tool(name: str, domain: str, extract) -> set[str]:
    """Shell out to an external enumerator if its binary is on PATH."""
    if not shutil.which(name):
        return set()
    cmd = [arg.replace("{d}", domain) for arg in EXTERNAL_TOOLS[name]]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=600, check=False)
        return extract(proc.stdout)
    except Exception as exc:  # noqa: BLE001
        print(col(f"    [{name}] {domain}: {exc}", C.GREY, C.DIM), file=sys.stderr)
        return set()


async def detect_wildcard(resolver, domain: str) -> set[str]:
    """Detect wildcard DNS for a domain by resolving an unlikely random label.

    Returns the set of CNAME targets / addresses the wildcard resolves to (empty
    if no wildcard). Hosts that resolve *only* via the wildcard are likely
    false positives, so we surface this to the operator.
    """
    probe = f"venomtko-wildcard-probe-zzqx.{domain}"
    targets: set[str] = set()
    for rtype in ("CNAME", "A", "AAAA"):
        try:
            ans = await resolver.resolve(probe, rtype)
            for rr in ans:
                targets.add(str(getattr(rr, "target", rr)).rstrip(".").lower())
        except dns.exception.DNSException:
            continue
    return targets


async def enumerate_one(session, domain: str, tools: list[str], extract) -> set[str]:
    found: set[str] = {domain}

    passive = await asyncio.gather(
        *[src(session, domain, extract) for src in PASSIVE_SOURCES],
        return_exceptions=True)
    for r in passive:
        if isinstance(r, set):
            found |= r

    if tools:
        tool_out = await asyncio.gather(
            *[asyncio.to_thread(run_external_tool, n, domain, extract) for n in tools],
            return_exceptions=True)
        for r in tool_out:
            if isinstance(r, set):
                found |= r
    return found


async def enumerate_subdomains(domains: list[str], tools: list[str],
                               resolver) -> tuple[list[str], set[str]]:
    """Return (sorted unique hosts, set of wildcard-domains detected)."""
    hosts: set[str] = set()
    wildcard_domains: set[str] = set()
    timeout = aiohttp.ClientTimeout(total=45)
    headers = {"User-Agent": "VenomTKO/1.0 (authorized-security-testing)"}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for d in domains:
            log_info(f"Enumerating {col(d, C.WHITE, C.BOLD)} "
                     f"(passive x{len(PASSIVE_SOURCES)} + tools x{len(tools)}) ...")
            wc = await detect_wildcard(resolver, d)
            if wc:
                wildcard_domains.add(d)
                log_warn(f"{d}: wildcard DNS detected ({', '.join(sorted(wc))}) "
                         f"-- resolving-only hosts may be false positives.")
            got = await enumerate_one(session, d, tools, make_extractor(d))
            print(col(f"    {d}: ", C.GREY) + col(f"{len(got)} host(s)", C.LIME),
                  file=sys.stderr)
            hosts |= got
    return sorted(hosts), wildcard_domains


# ===========================================================================
# Stage 3 - DNS resolution / CNAME chain
# ===========================================================================
async def resolve_cname_chain(resolver: "dns.asyncresolver.Resolver", host: str
                              ) -> tuple[list[str], bool, bool, bool]:
    """
    Return (cname_chain, resolved, nxdomain_target, servfail_target).

    cname_chain     - ordered list of CNAME targets following the host.
    resolved        - True if the host (or its chain end) resolves to an address.
    nxdomain_target - True if a CNAME exists but its final target is NXDOMAIN.
    servfail_target - True if a CNAME exists but its final target is SERVFAIL
                      (some providers return SERVFAIL for unclaimed resources).
    Both dangling flags are classic "dangling DNS record" takeover signals.
    """
    chain: list[str] = []
    current = host
    seen: set[str] = set()
    resolved = False
    nxdomain_target = False
    servfail_target = False

    for _ in range(10):  # cap chain depth, detect loops
        if current in seen:
            break
        seen.add(current)
        try:
            ans = await resolver.resolve(current, "CNAME")
            target = str(ans[0].target).rstrip(".").lower()
            chain.append(target)
            current = target
            continue
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.DNSException):
            pass
        break

    # Does the end of the chain resolve to an address?
    try:
        await resolver.resolve(current, "A")
        resolved = True
    except dns.resolver.NXDOMAIN:
        if chain:
            nxdomain_target = True
    except dns.resolver.NoNameservers:   # SERVFAIL from all nameservers
        if chain:
            servfail_target = True
    except dns.exception.DNSException:
        pass

    if not resolved and not nxdomain_target and not servfail_target:
        try:
            await resolver.resolve(current, "AAAA")
            resolved = True
        except dns.exception.DNSException:
            pass

    return chain, resolved, nxdomain_target, servfail_target


# ---- aiohttp DNS via dnspython --------------------------------------------
class DnspythonResolver(aiohttp.abc.AbstractResolver):
    """aiohttp name resolver backed by dnspython instead of getaddrinfo.

    Two wins: (1) it honours --resolver, so the HTTP client queries the same
    nameservers as the DNS stage; (2) it sidesteps the system getaddrinfo path
    that hangs under WSL, and makes unresolvable internal hosts fail fast
    (OSError) instead of burning the full probe timeout on every one.
    """

    def __init__(self, resolver: "dns.asyncresolver.Resolver") -> None:
        self._resolver = resolver

    async def resolve(self, host: str, port: int = 0,
                      family: int = socket.AF_INET) -> list[dict]:
        # Pass through IP literals untouched (no lookup needed).
        try:
            socket.inet_pton(family if family in (socket.AF_INET, socket.AF_INET6)
                             else socket.AF_INET, host)
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            return [{"hostname": host, "host": host, "port": port,
                     "family": fam, "proto": 0, "flags": socket.AI_NUMERICHOST}]
        except OSError:
            pass

        wanted = []
        if family in (socket.AF_INET, socket.AF_UNSPEC, 0):
            wanted.append(("A", socket.AF_INET))
        if family in (socket.AF_INET6, socket.AF_UNSPEC, 0):
            wanted.append(("AAAA", socket.AF_INET6))

        hosts: list[dict] = []
        for rtype, fam in wanted:
            try:
                ans = await self._resolver.resolve(host, rtype)
            except dns.exception.DNSException:
                continue
            for rr in ans:
                hosts.append({"hostname": host, "host": rr.address, "port": port,
                              "family": fam, "proto": 0,
                              "flags": socket.AI_NUMERICHOST})
        if not hosts:
            raise OSError(f"DNS lookup failed for {host}")
        return hosts

    async def close(self) -> None:
        pass


# ===========================================================================
# Stage 4 - HTTP probe
# ===========================================================================
async def probe_http(session: aiohttp.ClientSession, host: str,
                     timeout: float = 15.0
                     ) -> tuple[int | None, str | None, str, str | None]:
    """Return (status, final_url, body_snippet, error). Tries HTTPS then HTTP."""
    last_err: str | None = None
    # Cap the connect phase so a black-holed host can't eat the whole budget
    # twice (once per scheme); the total still bounds the slower read phase.
    client_timeout = aiohttp.ClientTimeout(
        total=timeout, sock_connect=min(timeout, 10.0))
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            async with session.get(
                url, allow_redirects=True, timeout=client_timeout, ssl=False,
            ) as resp:
                body = (await resp.text(errors="ignore"))[:8192]
                return resp.status, str(resp.url), body, None
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"
    return None, None, "", last_err


# ===========================================================================
# Stage 5/6 - candidate filter + fingerprint match
# ===========================================================================
def cname_matches_service(res: HostResult, fingerprints: list[dict]) -> bool:
    """True if the CNAME chain points at any fingerprinted service."""
    cname_blob = " ".join(res.cname_chain).lower()
    return any(c in cname_blob for fp in fingerprints for c in fp["cname"])


def is_candidate(res: HostResult, fingerprints: list[dict]) -> bool:
    """Filter for hosts worth fingerprinting. We keep a host if it has a CNAME AND
    any of: the CNAME target is dangling (NXDOMAIN/SERVFAIL), the HTTP status is an
    error, or the CNAME points at a known third-party service (catches services
    that serve an 'unclaimed' body on a 200, e.g. some S3/Shopify edge cases).
    Healthy 200s with no CNAME are dropped."""
    if not res.cname_chain:
        return False
    if res.dangling:
        return True
    if res.status in ERROR_STATUSES:
        return True
    return cname_matches_service(res, fingerprints)


def _apex(host: str) -> str:
    """Crude registrable apex (last two labels). Good enough to tell an
    off-domain dangling target apart from a same-org internal one."""
    parts = (host or "").rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def classify(res: HostResult, body: str, fingerprints: list[dict]) -> None:
    """Assign a confidence level, optimised for precision (true positives only).

    The decision is anchored on what the CNAME chain actually points at, so a
    stray body string can't mislabel a host as a different service:

      high   - CNAME points at a *vulnerable* fingerprinted service AND that is
               corroborated by either (a) that same service's unclaimed-page
               body fingerprint, or (b) a dangling (NXDOMAIN/SERVFAIL) target.
      medium - dangling CNAME whose final target is on a *different* registrable
               domain than the host and isn't a known live service (an
               off-domain dead record an attacker may be able to claim).
      none   - everything else: live services serving normal content, CNAMEs to
               a same-org/internal target that no longer resolves, body-only
               matches with no CNAME corroboration (generic-string false
               positives), and non-vulnerable services.
    """
    body_lc = body.lower()
    cname_blob = " ".join(res.cname_chain).lower()
    dangling = res.dangling

    # Which fingerprinted service does the CNAME chain actually resolve toward?
    cname_fp = next((fp for fp in fingerprints
                     if fp["cname"] and any(c in cname_blob for c in fp["cname"])),
                    None)

    if cname_fp is not None:
        if not cname_fp["vulnerable"]:
            return  # live, non-exploitable service (Netlify/Zendesk/ELB/…)
        body_hit = any(f in body_lc for f in cname_fp["fingerprint"])
        if body_hit or dangling:
            res.matched_service = cname_fp["service"]
            res.vulnerable = True
            evidence = ["cname"]
            if body_hit:
                evidence.append("body")
            if dangling:
                evidence.append("dangling-cname")
            res.matched_on = evidence
            res.confidence = "high"
        # else: CNAME to a vulnerable service but it's live and serving normal
        # content -> not a takeover, leave as 'none' (kills most fatigue).
        return

    # CNAME doesn't point at any known service. Only a dangling target that
    # leaves the host's own registrable domain is a real takeover candidate;
    # a same-org dead record is internal DNS hygiene, not exploitable.
    if dangling and res.cname_chain:
        target = res.cname_chain[-1]
        if _apex(target) != _apex(res.host):
            res.confidence = "medium"
            res.matched_on = ["dangling-cname"]


# ===========================================================================
# Stage 7 - cross-check verification (subzy / nuclei)
# ===========================================================================
def _write_targets(hosts: list[str]) -> str:
    """Write hosts to a temp file and return its path (caller deletes it)."""
    fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    fh.write("\n".join(hosts) + "\n")
    fh.close()
    return fh.name


def crosscheck_subzy(hosts: list[str]) -> dict[str, list[str]]:
    """Run subzy against the candidate hosts; return {host: ['subzy:VULNERABLE']}."""
    if not shutil.which("subzy") or not hosts:
        return {}
    targets = _write_targets(hosts)
    out_json = targets + ".subzy.json"
    verdicts: dict[str, list[str]] = {}
    try:
        subprocess.run(["subzy", "run", "--targets", targets,
                        "--output", out_json, "--hide_fails"],
                       capture_output=True, text=True, timeout=300, check=False)
        if os.path.exists(out_json):
            with open(out_json, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            rows = data if isinstance(data, list) else data.get("results", data.get("data", []))
            for row in rows or []:
                sub = (row.get("subdomain") or row.get("Subdomain")
                       or row.get("host") or "").lower().strip()
                status = str(row.get("status") or row.get("Status") or "").upper()
                host = to_host(sub) if sub else ""
                if host and "VULNERABLE" in status and "NOT" not in status:
                    verdicts.setdefault(host, []).append(
                        f"subzy:{row.get('engine') or row.get('Engine') or 'vulnerable'}")
    except Exception as exc:  # noqa: BLE001
        log_warn(f"[subzy] cross-check failed: {exc}")
    finally:
        for p in (targets, out_json):
            try:
                os.unlink(p)
            except OSError:
                pass
    return verdicts


def crosscheck_nuclei(hosts: list[str]) -> dict[str, list[str]]:
    """Run nuclei takeover templates; return {host: ['nuclei:<template-id>']}."""
    if not shutil.which("nuclei") or not hosts:
        return {}
    targets = _write_targets(hosts)
    verdicts: dict[str, list[str]] = {}
    try:
        proc = subprocess.run(
            ["nuclei", "-l", targets, "-tags", "takeover",
             "-jsonl", "-silent", "-duc"],
            capture_output=True, text=True, timeout=600, check=False)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw_host = rec.get("host") or rec.get("matched-at") or ""
            host = to_host(raw_host)
            tid = rec.get("template-id") or rec.get("templateID") or "takeover"
            if host:
                verdicts.setdefault(host, []).append(f"nuclei:{tid}")
    except Exception as exc:  # noqa: BLE001
        log_warn(f"[nuclei] cross-check failed: {exc}")
    finally:
        try:
            os.unlink(targets)
        except OSError:
            pass
    return verdicts


def apply_crosscheck(results: list[HostResult], verifiers: list[str]) -> None:
    """Run requested verifiers on flagged hosts and merge verdicts in place.

    A confirming verdict promotes the finding to 'high' confidence: an independent
    tool agreeing is the strongest signal we can get without exploitation."""
    flagged = [r for r in results if r.confidence != "none"]
    hosts = [r.host for r in flagged]
    if not hosts:
        return

    merged: dict[str, list[str]] = {}
    if "subzy" in verifiers:
        log_info(f"Cross-checking {len(hosts)} candidate(s) with subzy ...")
        for h, v in crosscheck_subzy(hosts).items():
            merged.setdefault(h, []).extend(v)
    if "nuclei" in verifiers:
        log_info(f"Cross-checking {len(hosts)} candidate(s) with nuclei ...")
        for h, v in crosscheck_nuclei(hosts).items():
            merged.setdefault(h, []).extend(v)

    by_host = {r.host: r for r in flagged}
    for host, verdicts in merged.items():
        res = by_host.get(host)
        if res:
            res.crosscheck.extend(verdicts)
            res.confidence = "high"   # independent confirmation
            res.vulnerable = True


def resolve_verifiers(spec: str | None) -> list[str]:
    """Map --verify spec to the list of installed verifier tools to run."""
    if not spec:
        return []
    names = ["subzy", "nuclei"] if spec.strip().lower() == "all" \
        else [t.strip() for t in spec.split(",") if t.strip() in ("subzy", "nuclei")]
    available = [n for n in names if shutil.which(n)]
    missing = [n for n in names if n not in available]
    if missing:
        log_warn(f"Verifier(s) not on PATH, skipping: {', '.join(missing)}")
    return available


# ===========================================================================
# Orchestration
# ===========================================================================
async def process_host(host: str, resolver, session, fingerprints, sem,
                       probe_timeout: float) -> HostResult:
    async with sem:
        res = HostResult(host=host)
        chain, resolved, nx, sf = await resolve_cname_chain(resolver, host)
        res.cname_chain, res.resolved = chain, resolved
        res.nxdomain_target, res.servfail_target = nx, sf

        status, final_url, body, err = await probe_http(session, host, probe_timeout)
        res.status, res.final_url, res.error = status, final_url, err

        if is_candidate(res, fingerprints):
            classify(res, body, fingerprints)
        return res


async def run_pipeline(hosts: list[str], fingerprints: list[dict],
                       concurrency: int, nameservers: list[str] | None,
                       resolver=None, probe_timeout: float = 15.0) -> list[HostResult]:
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        if nameservers:
            resolver.nameservers = nameservers

    sem = asyncio.Semaphore(concurrency)
    # Resolve HTTP-client DNS through dnspython too (honours --resolver, dodges
    # the WSL getaddrinfo hang). Fall back to the default resolver if aiohttp's
    # resolver interface is unavailable for some reason.
    try:
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False, family=0,
                                         resolver=DnspythonResolver(resolver))
    except Exception:  # noqa: BLE001  pragma: no cover
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {"User-Agent": "VenomTKO/1.0 (authorized-security-testing)"}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [process_host(h, resolver, session, fingerprints, sem, probe_timeout)
                 for h in hosts]
        results: list[HostResult] = []
        for i, fut in enumerate(asyncio.as_completed(tasks), 1):
            results.append(await fut)
            if i % 25 == 0 or i == len(tasks):
                print(col(f"    probed {i}/{len(tasks)}", C.GREY, C.DIM),
                      file=sys.stderr)
    return results


# ===========================================================================
# Reporting
# ===========================================================================
RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}
CONF_COLOR = {"high": (C.RED, C.BOLD), "medium": (C.ORANGE, C.BOLD),
              "low": (C.CYAN,), "none": (C.GREY,)}


def report(results: list[HostResult], json_path: str | None, csv_path: str | None,
           show_all: bool = False) -> None:
    flagged = [r for r in results if r.confidence != "none"]
    flagged.sort(key=lambda r: RANK[r.confidence], reverse=True)
    # By default the saved report holds only true-positive candidates, so the
    # output isn't buried under thousands of clean hosts. --all dumps every host.
    saved = results if show_all else flagged

    bar = col("=" * 78, C.GREEN, C.BOLD)
    print("\n" + bar)
    print(col("  >> ", C.GREEN, C.BOLD)
          + col(f"{NAME} TAKEOVER REPORT", C.LIME, C.BOLD)
          + col(f"  -  {len(flagged)} candidate(s) from {len(results)} host(s)",
                C.GREY))
    print(bar)
    tally = {lvl: sum(1 for r in flagged if r.confidence == lvl)
             for lvl in ("high", "medium")}
    print("  " + "   ".join(
        col(f"{lvl.upper()}: {tally[lvl]}", *CONF_COLOR[lvl])
        for lvl in ("high", "medium")))
    print(bar)
    if not flagged:
        print(col("  No takeover candidates found.", C.DGREEN))
    for r in flagged:
        cc = CONF_COLOR.get(r.confidence, (C.GREY,))
        tag = (col("VULNERABLE", C.RED, C.BOLD) if r.vulnerable
               else col("review", C.GREY))
        print("\n  " + col(f"[{r.confidence.upper():6}]", *cc) + " "
              + col(r.host, C.WHITE, C.BOLD) + f"  ({tag})")
        print(col("      service : ", C.GREY) + col(r.matched_service or "-", C.CYAN))
        print(col("      cname   : ", C.GREY)
              + col(" -> ".join(r.cname_chain) or "-", C.MAGENTA))
        dang = col(str(r.dangling), C.RED if r.dangling else C.GREY)
        print(col("      status  : ", C.GREY)
              + f"{r.status}   dangling={dang} "
              + col(f"(nx={r.nxdomain_target},servfail={r.servfail_target})", C.GREY)
              + "   evidence=" + col(",".join(r.matched_on) or "-", C.YELLOW))
        if r.crosscheck:
            print(col("      verified: ", C.GREY)
                  + col(", ".join(sorted(set(r.crosscheck))), C.GREEN, C.BOLD))
    print("\n" + col("  Remediation: ", C.GREEN, C.BOLD)
          + col("remove or repoint the dangling DNS record, or re-claim the\n"
                "  resource on the provider. Verify ownership before acting.\n", C.GREY))

    rows = [{k: v for k, v in asdict(r).items()} for r in saved]
    for row, r in zip(rows, saved):
        row["dangling"] = r.dangling  # property isn't in asdict; include it
    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        log_good(f"JSON written to {json_path} ({len(saved)} record(s))")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "confidence", "vulnerable", "service",
                        "cname_chain", "status", "nxdomain_target", "servfail_target",
                        "matched_on", "crosscheck", "final_url", "error"])
            for r in saved:
                w.writerow([r.host, r.confidence, r.vulnerable, r.matched_service,
                            " -> ".join(r.cname_chain), r.status, r.nxdomain_target,
                            r.servfail_target, ",".join(r.matched_on),
                            ",".join(r.crosscheck), r.final_url, r.error])
        log_good(f"CSV written to {csv_path}")


# ===========================================================================
# CLI
# ===========================================================================
USAGE = ("venomtko -i FILE [-m {auto,domains,urls}] [--verify [subzy,nuclei]] "
         "[options] --confirm-authorized")

EXAMPLES = [
    ("enumerate + hunt from a wildcard/apex domain list",
     "venomtko.py -i domains.txt -m domains --confirm-authorized"),
    ("hunt a ready-made list of URLs / hosts",
     "venomtko.py -i urls.txt -m urls --confirm-authorized"),
    ("max coverage: full DB + subzy/nuclei cross-check, 100 workers",
     "venomtko.py -i scope.txt --verify all -c 100 --confirm-authorized"),
    ("refresh the community fingerprint DB (run once in a while)",
     "venomtko.py --update-fingerprints"),
]

def build_parser() -> argparse.ArgumentParser:
    # add_help=False: we render our own coloured help (see print_help).
    p = argparse.ArgumentParser(
        prog="venomtko", add_help=False, usage=USAGE,
        description=f"{NAME} v{VERSION} - automated subdomain takeover hunter "
                    f"(detection only).")
    p.add_argument("-h", "--help", action="store_true",
                   help="Show this help message and exit.")
    p.add_argument("-i", "--input", metavar="FILE",
                   help="File with domains or URLs (one per line).")
    p.add_argument("-m", "--mode", choices=["auto", "domains", "urls"], default="auto",
                   help="Input type. 'domains' enumerates subdomains first; "
                        "'urls' skips enum. Default: auto-detect.")
    p.add_argument("-f", "--fingerprints", metavar="FILE",
                   help="Path to a can-i-take-over-xyz style fingerprints.json.")
    p.add_argument("--update-fingerprints", action="store_true",
                   help="Fetch the live can-i-take-over-xyz DB, cache it at "
                        f"{FINGERPRINT_CACHE}, and exit.")
    p.add_argument("-c", "--concurrency", type=int, default=50, metavar="N",
                   help="Max concurrent probes (default 50).")
    p.add_argument("--probe-timeout", type=float, default=15.0, metavar="SECS",
                   help="Per-host HTTP probe timeout in seconds (default 15).")
    p.add_argument("--resolver", action="append", default=None, metavar="IP",
                   help="Custom DNS resolver IP (repeatable). Drives both the DNS "
                        "stage and the HTTP client's name resolution.")
    p.add_argument("--tools", default="all", metavar="LIST",
                   help="Comma list of external enumerators to use if installed "
                        f"({', '.join(EXTERNAL_TOOLS)}), or 'all' (default).")
    p.add_argument("--no-tools", action="store_true",
                   help="Use only the built-in passive HTTP sources; skip CLI tools.")
    p.add_argument("--verify", nargs="?", const="all", default=None, metavar="LIST",
                   help="Cross-check high/medium findings with external takeover "
                        "scanners if installed: 'subzy', 'nuclei', or 'all'.")
    p.add_argument("--json", default="takeover_report.json", metavar="FILE",
                   help="JSON output path.")
    p.add_argument("--csv", default="takeover_report.csv", metavar="FILE",
                   help="CSV output path.")
    p.add_argument("--all", action="store_true",
                   help="Write every probed host to the reports. Default: only "
                        "true-positive candidates (high/medium) are saved.")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="Required acknowledgement that you are authorized to test "
                        "these assets.")
    return p


def _colorize_invocation(inv: str) -> str:
    """Colour option flags cyan and metavars/choices yellow."""
    out = []
    for tok in inv.split():
        bare, comma = (tok[:-1], ",") if tok.endswith(",") else (tok, "")
        if bare.startswith("-"):
            out.append(col(bare, C.CYAN, C.BOLD) + col(comma, C.GREY))
        else:
            out.append(col(bare, C.YELLOW) + col(comma, C.GREY))
    return " ".join(out)


def print_help(parser: argparse.ArgumentParser) -> None:
    """Render a coloured, aligned, hacker-vibe help screen."""
    width = shutil.get_terminal_size((100, 24)).columns
    fmt = parser._get_formatter()
    rows = [(fmt._format_action_invocation(a), a.help or "")
            for a in parser._actions]
    label_w = max(len(inv) for inv, _ in rows)
    help_indent = 2 + label_w + 2
    wrap_w = max(24, width - help_indent - 1)

    print(col("usage: ", C.GREEN, C.BOLD)
          + col("venomtko ", C.LIME, C.BOLD) + col(USAGE[len("venomtko "):], C.GREY))
    print()
    print(col("  " + (parser.description or ""), C.DGREEN, C.BOLD))
    print()
    print(col("options:", C.GREEN, C.BOLD))
    for inv, htext in rows:
        cinv = _colorize_invocation(inv)
        pad = " " * (label_w - len(inv) + 2)
        wrapped = textwrap.wrap(htext, wrap_w) or [""]
        print("  " + cinv + pad + col(wrapped[0], C.GREY))
        for cont in wrapped[1:]:
            print(" " * help_indent + col(cont, C.GREY))

    print()
    print(col("examples:", C.GREEN, C.BOLD))
    for desc, cmd in EXAMPLES:
        print(col(f"  # {desc}", C.GREY, C.DIM))
        print(col("    $ ", C.GREEN, C.BOLD) + col(cmd, C.LIME))
    print()
    print(col("  detection only -- never registers or claims any resource. "
              "authorized targets only.", C.GREY, C.DIM))


def parse_args(argv: list[str]) -> argparse.Namespace:
    return build_parser().parse_args(argv)


async def main_async(args: argparse.Namespace) -> int:
    if args.update_fingerprints:
        try:
            update_fingerprints()
            return 0
        except Exception as exc:  # noqa: BLE001
            log_err(f"Fingerprint update failed: {exc}")
            return 1

    if not args.input:
        log_err("--input is required (or use --update-fingerprints).")
        return 2

    if not args.confirm_authorized:
        log_err("You must pass --confirm-authorized to acknowledge that you have "
                "explicit permission to test the supplied targets.")
        return 2

    lines = read_lines(args.input)
    if not lines:
        log_err("Input file is empty.")
        return 1

    mode = detect_mode(lines, args.mode)
    log_info(f"Mode: {col(mode, C.WHITE, C.BOLD)}  ({len(lines)} input line(s))")

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    if args.resolver:
        resolver.nameservers = args.resolver

    if mode == "domains":
        domains = sorted({to_host(ln) for ln in lines})
        if args.no_tools:
            tools: list[str] = []
        elif args.tools.strip().lower() == "all":
            tools = list(EXTERNAL_TOOLS)
        else:
            tools = [t.strip() for t in args.tools.split(",")
                     if t.strip() in EXTERNAL_TOOLS]
        available = [t for t in tools if shutil.which(t)]
        if tools and not available:
            log_info("None of the requested CLI tools are installed; "
                     "using passive sources only.")
        hosts, _wildcards = await enumerate_subdomains(domains, available, resolver)
        log_good(f"Enumerated {len(hosts)} unique host(s).")
    else:
        hosts = sorted({to_host(ln) for ln in lines})
        log_info(f"Probing {len(hosts)} supplied host(s).")

    fingerprints = load_fingerprints(args.fingerprints)
    log_info(f"Loaded {len(fingerprints)} fingerprint signature(s).")

    t0 = time.time()
    results = await run_pipeline(hosts, fingerprints, args.concurrency,
                                 args.resolver, resolver=resolver,
                                 probe_timeout=args.probe_timeout)
    log_good(f"Pipeline finished in {time.time() - t0:.1f}s.")

    verifiers = resolve_verifiers(args.verify)
    if verifiers:
        apply_crosscheck(results, verifiers)

    report(results, args.json, args.csv, show_all=args.all)
    return 0


def main() -> None:
    init_color(enabled=sys.stdout.isatty())
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:])
    banner()
    if args.help:
        print_help(parser)
        sys.exit(0)
    try:
        rc = asyncio.run(main_async(args))
    except KeyboardInterrupt:
        log_warn("Interrupted by user.")
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
