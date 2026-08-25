#!/usr/bin/env python3
"""
Full DNS / infrastructure enumeration for the CTI domain set.

Collects, per domain: NS, SOA, A, AAAA, MX, TXT, CNAME, CAA, DMARC, DKIM,
MTA-STS / SMTP-TLSRPT, plus subdomain probing, MX/NS host resolution,
reverse DNS (PTR) and ASN / BGP prefix / country enrichment for every IP
observed (via the Team Cymru DNS-based IP-to-ASN service).

Output: output/dns_enumeration.json
"""
import csv, json, os, sys, threading, itertools, argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.resolver, dns.reversename, dns.exception

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_CSV = os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv")
OUT_JSON = os.path.join(ROOT, "output", "dns_enumeration.json")

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]
RECORD_TYPES = ["NS", "SOA", "A", "AAAA", "MX", "TXT", "CNAME", "CAA"]

DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "dkim", "k1", "k2",
    "s1", "s2", "mail", "smtp", "zoho", "mandrill", "everlytickey1",
    "protonmail", "pm-bounces", "mx", "key1",
]
SUBDOMAINS = [
    "www", "mail", "smtp", "webmail", "imap", "pop", "autodiscover",
    "autoconfig", "cpanel", "ftp", "ns1", "ns2", "mx", "mx1", "api",
    "app", "portal", "login", "admin", "cdn", "vpn", "remote", "test",
    "dev", "staging", "m", "blog", "secure",
]

_tls = threading.local()
_counter = itertools.count()
_lock = threading.Lock()
_progress = {"done": 0, "total": 0}


def resolver():
    """Per-thread resolver, pinned to one public resolver to spread load."""
    r = getattr(_tls, "r", None)
    if r is None:
        r = dns.resolver.Resolver(configure=False)
        idx = next(_counter) % len(RESOLVERS)
        r.nameservers = [RESOLVERS[idx]] + [n for n in RESOLVERS if n != RESOLVERS[idx]]
        r.timeout = 3.0
        r.lifetime = 6.0
        _tls.r = r
    return r


def query(name, rtype):
    """Return (list_of_record_strings, status)."""
    try:
        ans = resolver().resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return [], "NOANSWER"
        return [rr.to_text() for rr in ans], "OK"
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NOANSWER"
    except dns.resolver.NoNameservers:
        return [], "SERVFAIL"
    except dns.exception.Timeout:
        return [], "TIMEOUT"
    except Exception as e:  # noqa: BLE001 - record whatever went wrong
        return [], f"ERROR:{type(e).__name__}"


def txt_join(records):
    """dnspython quotes and splits long TXT strings; rebuild the logical value."""
    out = []
    for rec in records:
        parts = []
        buf, in_q, esc = "", False, False
        for ch in rec:
            if esc:
                buf += ch
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                if in_q:
                    parts.append(buf)
                    buf = ""
                in_q = not in_q
            elif in_q:
                buf += ch
        out.append("".join(parts) if parts else rec)
    return out


def ips_of(host):
    ips = []
    for rt in ("A", "AAAA"):
        recs, _ = query(host, rt)
        ips.extend(recs)
    return ips


def enumerate_domain(row):
    d = row["Domain"].strip().lower()
    rec = {
        "domain": d,
        "domain_class": row.get("Domain Class", ""),
        "risk_score": row.get("Risk Score", ""),
        "risk_tier": row.get("Risk Tier", ""),
        "resolves": False,
        "records": {},
        "status": {},
        "dmarc": [],
        "dkim": {},
        "mta_sts": [],
        "tls_rpt": [],
        "subdomains": {},
        "mx_hosts": {},
        "ns_hosts": {},
        "ips": [],
    }

    for rt in RECORD_TYPES:
        recs, st = query(d, rt)
        if rt == "TXT":
            recs = txt_join(recs)
        rec["records"][rt] = recs
        rec["status"][rt] = st

    apex_nx = rec["status"]["A"] == "NXDOMAIN" and rec["status"]["NS"] == "NXDOMAIN"
    rec["resolves"] = bool(
        rec["records"]["A"] or rec["records"]["AAAA"] or rec["records"]["NS"]
        or rec["records"]["MX"] or rec["records"]["SOA"]
    )
    rec["nxdomain"] = apex_nx

    if not apex_nx:
        r, _ = query(f"_dmarc.{d}", "TXT")
        rec["dmarc"] = txt_join(r)
        r, _ = query(f"_mta-sts.{d}", "TXT")
        rec["mta_sts"] = txt_join(r)
        r, _ = query(f"_smtp._tls.{d}", "TXT")
        rec["tls_rpt"] = txt_join(r)

        # DKIM selectors only worth probing where mail is actually configured
        if rec["records"]["MX"]:
            for sel in DKIM_SELECTORS:
                r, st = query(f"{sel}._domainkey.{d}", "TXT")
                if r:
                    rec["dkim"][sel] = txt_join(r)
                else:
                    cn, _ = query(f"{sel}._domainkey.{d}", "CNAME")
                    if cn:
                        rec["dkim"][sel] = ["CNAME " + cn[0]]

        for sub in SUBDOMAINS:
            fq = f"{sub}.{d}"
            a, _ = query(fq, "A")
            cn, _ = query(fq, "CNAME")
            aaaa, _ = query(fq, "AAAA") if a or cn else ([], "")
            if a or cn or aaaa:
                rec["subdomains"][fq] = {"A": a, "AAAA": aaaa, "CNAME": cn}

        for mx in rec["records"]["MX"]:
            host = mx.split()[-1].rstrip(".")
            if host and host not in rec["mx_hosts"]:
                rec["mx_hosts"][host] = ips_of(host)
        for ns in rec["records"]["NS"]:
            host = ns.rstrip(".")
            if host and host not in rec["ns_hosts"]:
                rec["ns_hosts"][host] = ips_of(host)

    seen = []
    for src in (rec["records"]["A"], rec["records"]["AAAA"]):
        seen.extend(src)
    for m in rec["subdomains"].values():
        seen.extend(m["A"])
        seen.extend(m["AAAA"])
    for lst in rec["mx_hosts"].values():
        seen.extend(lst)
    rec["ips"] = sorted(set(seen))

    with _lock:
        _progress["done"] += 1
        if _progress["done"] % 20 == 0 or _progress["done"] == _progress["total"]:
            print(f"  domains {_progress['done']}/{_progress['total']}", file=sys.stderr, flush=True)
    return rec


def is_ipv4(ip):
    return ip.count(".") == 3 and ":" not in ip


def enrich_ip(ip):
    info = {"ip": ip, "ptr": [], "asn": None, "bgp_prefix": None,
            "cc": None, "registry": None, "allocated": None, "as_name": None}
    try:
        rev = dns.reversename.from_address(ip)
        ptr, _ = query(rev.to_text(), "PTR")
        info["ptr"] = [p.rstrip(".") for p in ptr]
    except Exception:
        pass

    if is_ipv4(ip):
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        exp = "".join(f"{int(b):08b}" for b in [0])  # placeholder, expanded below
        try:
            import ipaddress
            full = ipaddress.IPv6Address(ip).exploded.replace(":", "")
            q = ".".join(reversed(full)) + ".origin6.asn.cymru.com"
        except Exception:
            q = None
    if q:
        recs = txt_join(query(q, "TXT")[0])
        if recs:
            # "ASN | BGP prefix | CC | registry | allocated"
            best = sorted(recs, key=lambda s: -int(s.split("|")[1].strip().split("/")[-1] or 0))
            parts = [p.strip() for p in best[0].split("|")]
            if len(parts) >= 5:
                info["asn"] = parts[0].split()[0]
                info["bgp_prefix"] = parts[1]
                info["cc"] = parts[2]
                info["registry"] = parts[3]
                info["allocated"] = parts[4]
    if info["asn"]:
        recs = txt_join(query(f"AS{info['asn']}.asn.cymru.com", "TXT")[0])
        if recs:
            parts = [p.strip() for p in recs[0].split("|")]
            if len(parts) >= 5:
                info["as_name"] = parts[4]
                info["cc"] = info["cc"] or parts[1]
    with _lock:
        _progress["done"] += 1
        if _progress["done"] % 25 == 0 or _progress["done"] == _progress["total"]:
            print(f"  ips {_progress['done']}/{_progress['total']}", file=sys.stderr, flush=True)
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = list(csv.DictReader(open(IN_CSV)))
    if args.limit:
        rows = rows[: args.limit]

    print(f"[*] enumerating {len(rows)} domains", file=sys.stderr)
    _progress["total"] = len(rows)
    _progress["done"] = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(enumerate_domain, rows))

    all_ips = sorted({ip for r in results for ip in r["ips"]}
                     | {ip for r in results for lst in r["ns_hosts"].values() for ip in lst})
    print(f"[*] enriching {len(all_ips)} unique IPs", file=sys.stderr)
    _progress["total"] = len(all_ips)
    _progress["done"] = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        ipinfo = list(ex.map(enrich_ip, all_ips))

    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": os.path.relpath(IN_CSV, ROOT),
        "resolvers": RESOLVERS,
        "collection_notes": {
            "dns": "collected live over UDP/53 against public resolvers",
            "asn": "Team Cymru IP-to-ASN DNS service (origin.asn.cymru.com / asn.cymru.com)",
        },
        "domains": results,
        "ip_intel": {i["ip"]: i for i in ipinfo},
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=False)
    print(f"[+] wrote {OUT_JSON}", file=sys.stderr)


if __name__ == "__main__":
    main()
