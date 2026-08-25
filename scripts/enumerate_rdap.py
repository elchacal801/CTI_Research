#!/usr/bin/env python3
"""
RDAP (and WHOIS port-43 fallback) enumeration for the CTI domain set.

RDAP is the modern, structured replacement for WHOIS and is the preferred
source for registrar, registration/expiry dates, status codes, registrant
contact/abuse data and delegated nameservers.

This script is network-egress sensitive: it needs outbound HTTPS to the
RDAP bootstrap/registry servers, or outbound TCP/43 for the WHOIS fallback.
Where those are blocked it records the block per-domain rather than failing,
so the run is re-playable in an environment that permits the egress.

Output: output/rdap_enumeration.json
"""
import csv, json, os, socket, ssl, sys, time, threading, argparse
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_CSV = os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv")
OUT_JSON = os.path.join(ROOT, "output", "rdap_enumeration.json")

# Registry RDAP endpoints (IANA bootstrap equivalents) keyed by TLD.
RDAP_BASE = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "io":  "https://rdap.identitydigital.services/rdap/domain/",
    "co":  "https://rdap.identitydigital.services/rdap/domain/",
    "me":  "https://rdap.identitydigital.services/rdap/domain/",
    "pro": "https://rdap.afilias.net/rdap/domain/",
    "us":  "https://rdap.nic.us/domain/",
    "careers": "https://rdap.identitydigital.services/rdap/domain/",
    "email":   "https://rdap.identitydigital.services/rdap/domain/",
    "help":    "https://rdap.centralnic.com/help/domain/",
    "cloud":   "https://rdap.nic.cloud/domain/",
    "ai":      "https://rdap.identitydigital.services/rdap/domain/",
}
BOOTSTRAP = "https://rdap.org/domain/"          # generic fallback
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "io": "whois.nic.io", "co": "whois.nic.co",
    "me": "whois.nic.me", "uk": "whois.nic.uk", "ca": "whois.cira.ca",
    "ru": "whois.tcinet.ru", "ch": "whois.nic.ch", "no": "whois.norid.no",
    "in": "whois.registry.in", "us": "whois.nic.us", "ai": "whois.nic.ai",
}

_lock = threading.Lock()
_done = {"n": 0, "total": 0}


def http_json(url, timeout=25):
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "cti-research-rdap/1.0",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def whois43(domain, server, timeout=15):
    q = domain + "\r\n"
    if server == "whois.nic.uk":
        q = domain + "\r\n"
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall(q.encode())
        buf = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
    return buf.decode("utf-8", "replace")


def parse_rdap(js):
    """Flatten the RDAP response into the fields that matter for CTI pivoting."""
    out = {"registrar": None, "registrar_iana_id": None, "created": None,
           "expires": None, "last_changed": None, "status": js.get("status", []),
           "nameservers": [], "abuse_email": None, "registrant_country": None,
           "registrant_org": None, "dnssec": js.get("secureDNS", {}).get("delegationSigned")}

    for ev in js.get("events", []):
        a, d = ev.get("eventAction"), ev.get("eventDate")
        if a == "registration":
            out["created"] = d
        elif a == "expiration":
            out["expires"] = d
        elif a in ("last changed", "last update of RDAP database"):
            out["last_changed"] = out["last_changed"] or d

    out["nameservers"] = [ns.get("ldhName", "").lower()
                          for ns in js.get("nameservers", []) if ns.get("ldhName")]

    def vcard_get(ent, field):
        for item in ent.get("vcardArray", [[], []])[1]:
            if item and item[0] == field:
                return item[3]
        return None

    for ent in js.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            out["registrar"] = vcard_get(ent, "fn") or ent.get("handle")
            for pid in ent.get("publicIds", []):
                if "IANA" in str(pid.get("type", "")):
                    out["registrar_iana_id"] = pid.get("identifier")
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    out["abuse_email"] = vcard_get(sub, "email")
        if "registrant" in roles:
            adr = vcard_get(ent, "adr")
            if isinstance(adr, list) and len(adr) >= 7:
                out["registrant_country"] = adr[6]
            out["registrant_org"] = vcard_get(ent, "org") or vcard_get(ent, "fn")
    return out


def lookup(row):
    d = row["Domain"].strip().lower()
    tld = d.rsplit(".", 1)[-1]
    rec = {"domain": d, "tld": tld, "source": None, "ok": False,
           "error": None, "rdap": None, "whois_raw": None}

    urls = []
    if tld in RDAP_BASE:
        urls.append(RDAP_BASE[tld] + d)
    urls.append(BOOTSTRAP + d)

    for url in urls:
        try:
            js = http_json(url)
            rec["rdap"] = parse_rdap(js)
            rec["source"] = url
            rec["ok"] = True
            break
        except urllib.error.HTTPError as e:
            rec["error"] = f"HTTP {e.code} from {url}"
            if e.code in (404, 400):
                break            # authoritative "not registered"
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {e} ({url})"

    if not rec["ok"] and tld in WHOIS_SERVERS:
        try:
            rec["whois_raw"] = whois43(d, WHOIS_SERVERS[tld])
            rec["source"] = f"whois://{WHOIS_SERVERS[tld]}"
            rec["ok"] = True
        except Exception as e:  # noqa: BLE001
            rec["error"] = (rec["error"] or "") + f" | whois43: {type(e).__name__}"

    with _lock:
        _done["n"] += 1
        if _done["n"] % 10 == 0:
            print(f"  {_done['n']}/{_done['total']}", file=sys.stderr, flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = list(csv.DictReader(open(IN_CSV)))
    if args.limit:
        rows = rows[: args.limit]
    _done["total"] = len(rows)

    print(f"[*] RDAP/WHOIS for {len(rows)} domains", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        res = list(ex.map(lookup, rows))

    ok = sum(1 for r in res if r["ok"])
    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "succeeded": ok,
        "failed": len(res) - ok,
        "records": res,
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON} ({ok} ok / {len(res)-ok} failed)", file=sys.stderr)


if __name__ == "__main__":
    main()
