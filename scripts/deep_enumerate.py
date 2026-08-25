#!/usr/bin/env python3
"""
Deeper second-pass enumeration: wider subdomain wordlist, longer DKIM selector
sweep, DNSSEC status and NSEC zone walking.

Every domain is wildcard-tested first. A zone that answers arbitrary labels
returns a "hit" for every probe, which would otherwise inflate the subdomain
and DKIM results into nonsense -- the same failure that produced 67 bogus
cluster members in the first expansion sweep. Wildcard zones are marked and
their probe results suppressed.

NSEC walking applies only to DNSSEC-signed zones that use NSEC rather than
NSEC3: NSEC records chain to the next existing name, which enumerates the zone
exactly. NSEC3 hashes the names and is not walkable here.

Output: output/deep_enumeration.json
"""
import csv, json, os, sys, threading, itertools, argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.resolver, dns.exception

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_JSON = os.path.join(ROOT, "output", "deep_enumeration.json")

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]

SUBDOMAINS = [
    "www", "mail", "smtp", "webmail", "imap", "pop", "pop3", "autodiscover",
    "autoconfig", "cpanel", "whm", "ftp", "sftp", "ns1", "ns2", "ns3", "mx",
    "mx1", "mx2", "api", "app", "apps", "portal", "login", "signin", "sso",
    "admin", "administrator", "dashboard", "panel", "cdn", "static", "assets",
    "img", "images", "media", "files", "download", "downloads", "docs", "doc",
    "vpn", "remote", "rdp", "citrix", "gateway", "proxy", "test", "testing",
    "dev", "develop", "staging", "stage", "uat", "qa", "demo", "beta", "sandbox",
    "m", "mobile", "blog", "news", "shop", "store", "secure", "ssl", "auth",
    "account", "accounts", "user", "users", "client", "clients", "customer",
    "support", "help", "helpdesk", "ticket", "status", "monitor", "grafana",
    "jenkins", "git", "gitlab", "jira", "confluence", "wiki", "intranet",
    "internal", "corp", "office", "exchange", "owa", "lync", "sip", "voip",
    "track", "click", "link", "go", "redirect", "r", "email", "mailer",
    "newsletter", "campaign", "list", "unsubscribe", "form", "forms", "apply",
    "career", "careers", "jobs", "job", "hire", "recruit", "cv", "resume",
    "upload", "uploads", "share", "drive", "cloud", "backup", "db", "sql",
    "old", "new", "v1", "v2", "legacy", "archive",
]

DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "dkim", "dkim1", "dkim2",
    "k1", "k2", "k3", "s1", "s2", "s3", "mail", "smtp", "email", "mx",
    "zoho", "zohomail", "mandrill", "everlytickey1", "everlytickey2",
    "protonmail", "protonmail2", "protonmail3", "pm-bounces", "key1", "key2",
    "sendgrid", "sg", "mailgun", "mg", "mailjet", "amazonses", "ses",
    "postmark", "pm", "sparkpost", "scph0119", "titan1", "titan2",
    "migadu", "fm1", "fm2", "fm3", "mesmtp", "cm", "dkimrnd", "hs1", "hs2",
    "20161025", "20230601", "selector", "main", "primary",
]

CANARIES = ["zz9qx7kv3nope", "qq2mz8rw1none"]

_tls = threading.local()
_counter = itertools.count()
_lock = threading.Lock()
_prog = {"n": 0, "total": 0}


def resolver():
    r = getattr(_tls, "r", None)
    if r is None:
        r = dns.resolver.Resolver(configure=False)
        i = next(_counter) % len(RESOLVERS)
        r.nameservers = [RESOLVERS[i]] + [n for n in RESOLVERS if n != RESOLVERS[i]]
        r.timeout, r.lifetime = 3.0, 7.0
        _tls.r = r
    return r


def q(name, rtype, tries=2):
    """Returns list of records, [] for definitive absence, None if undecidable."""
    for _ in range(tries):
        try:
            ans = resolver().resolve(name, rtype, raise_on_no_answer=False)
            return [rr.to_text() for rr in ans] if ans.rrset is not None else []
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            continue
    return None


def wildcard_state(domain):
    """'wildcard' / 'clean' / 'undecided' for A and TXT at arbitrary labels."""
    undecided = False
    for c in CANARIES:
        for rt in ("A", "TXT"):
            r = q(f"{c}.{domain}", rt)
            if r is None:
                undecided = True
            elif r:
                return "wildcard"
    return "undecided" if undecided else "clean"


def walk_nsec(domain, limit=200):
    """Follow the NSEC chain. Only works on NSEC-signed (not NSEC3) zones."""
    names, cur = [], domain
    for _ in range(limit):
        recs = q(cur, "NSEC")
        if not recs:
            break
        nxt = recs[0].split()[0].rstrip(".")
        if not nxt or nxt == cur or not nxt.endswith(domain):
            break
        # RFC 4470 "white lies": the resolver synthesises \000-prefixed names on
        # demand instead of revealing the zone, so the chain is infinite and empty.
        if nxt.startswith("\\000."):
            names = []
            break
        names.append(nxt)
        cur = nxt
        if cur == domain:
            break
    return names


def enumerate_deep(row):
    d = row["Domain"].strip().lower()
    rec = {"domain": d, "wildcard": None, "subdomains": {}, "dkim": {},
           "dnssec": False, "nsec_type": None, "nsec_walk": [],
           "probes_suppressed": False}

    rec["wildcard"] = wildcard_state(d)
    if rec["wildcard"] in ("wildcard", "undecided"):
        rec["probes_suppressed"] = True
    else:
        for sub in SUBDOMAINS:
            fq = f"{sub}.{d}"
            a = q(fq, "A") or []
            cn = q(fq, "CNAME") or []
            if a or cn:
                aaaa = q(fq, "AAAA") or []
                rec["subdomains"][fq] = {"A": a, "AAAA": aaaa,
                                         "CNAME": [c.rstrip(".") for c in cn]}
        for sel in DKIM_SELECTORS:
            t = q(f"{sel}._domainkey.{d}", "TXT") or []
            if t:
                rec["dkim"][sel] = [x.replace('" "', "").strip('"') for x in t]
            else:
                cn = q(f"{sel}._domainkey.{d}", "CNAME") or []
                if cn:
                    rec["dkim"][sel] = ["CNAME " + cn[0].rstrip(".")]

    dnskey = q(d, "DNSKEY") or []
    rec["dnssec"] = bool(dnskey)
    if rec["dnssec"]:
        if q(d, "NSEC3PARAM"):
            rec["nsec_type"] = "NSEC3"        # hashed, not walkable here
        elif q(d, "NSEC"):
            rec["nsec_type"] = "NSEC"
            rec["nsec_walk"] = walk_nsec(d)
            if not rec["nsec_walk"]:
                rec["nsec_type"] = "NSEC-white-lies"   # online signing, not walkable
        else:
            rec["nsec_type"] = "unknown"

    with _lock:
        _prog["n"] += 1
        if _prog["n"] % 10 == 0:
            print(f"  {_prog['n']}/{_prog['total']}", file=sys.stderr, flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--inputs", nargs="+", default=[
        os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv"),
        os.path.join(ROOT, "data", "Discovered_Domains.csv"),
    ])
    args = ap.parse_args()

    rows, seen = [], set()
    for path in args.inputs:
        if not os.path.exists(path):
            continue
        for r in csv.DictReader(open(path)):
            d = r["Domain"].strip().lower()
            if d not in seen:
                seen.add(d)
                rows.append(r)

    _prog["total"] = len(rows)
    print(f"[*] deep enumeration of {len(rows)} domains "
          f"({len(SUBDOMAINS)} subdomains, {len(DKIM_SELECTORS)} DKIM selectors)",
          file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        res = list(ex.map(enumerate_deep, rows))

    wc = sum(1 for r in res if r["wildcard"] == "wildcard")
    und = sum(1 for r in res if r["wildcard"] == "undecided")
    signed = [r for r in res if r["dnssec"]]
    walked = [r for r in res if r["nsec_walk"]]
    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "subdomain_wordlist_size": len(SUBDOMAINS),
        "dkim_selector_count": len(DKIM_SELECTORS),
        "wildcard_zones": wc,
        "undecided_zones": und,
        "dnssec_signed": len(signed),
        "nsec_walkable": len(walked),
        "domains": res,
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}", file=sys.stderr)
    print(f"    subdomains found: {sum(len(r['subdomains']) for r in res)}", file=sys.stderr)
    print(f"    DKIM keys found : {sum(len(r['dkim']) for r in res)}", file=sys.stderr)
    print(f"    wildcard zones  : {wc} (probes suppressed), undecided: {und}", file=sys.stderr)
    print(f"    DNSSEC signed   : {len(signed)}, NSEC-walkable: {len(walked)}", file=sys.stderr)


if __name__ == "__main__":
    main()
