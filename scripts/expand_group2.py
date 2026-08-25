#!/usr/bin/env python3
"""
Expand Group 2 using its DMARC reporting-platform account as the marker.

Group 2's members all publish a DMARC record whose rua points at
p7rqadcw.uriports.com. That account id is chosen by the operator, so the test
is content-matched: a wildcard zone cannot fake it the way it faked the
Group 1 SPF-name probe, because the string has to appear inside the record.

Note on what is NOT used as a marker: 12 of the 15 known members resolve
autoconfig.<domain> to 141.94.97.141. That is autoconfig.migadu.com, the mail
vendor's shared host -- every Migadu customer points there, so it identifies
the vendor, not the operator.

Candidate vocabulary is induced from the synthetic_generic_mailbox_brand
naming style rather than the job/CV compounds used for Group 1.

Output: output/group2_expansion.json
"""
import csv, itertools, json, os, sys, threading, argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.resolver, dns.exception

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_JSON = os.path.join(ROOT, "output", "group2_expansion.json")
KNOWN_CSV = os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv")

URIPORTS_ACCOUNT = "p7rqadcw"
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]

ADJ = ["rapid", "swift", "smart", "true", "active", "pulse", "quick", "fast",
       "speed", "speedy", "prime", "elite", "top", "next", "bright", "clear",
       "sharp", "solid", "pure", "bold", "vivid", "blaze", "comet", "phoenix",
       "zenith", "celestial", "quantum", "orbital", "stellar", "flash", "jet",
       "zoom", "glide", "courier", "express", "pro", "secure", "safe", "easy",
       "simple", "instant", "turbo", "ultra", "nova", "apex", "nexus"]
NOUN = ["mail", "mails", "email", "emails", "inbox", "post", "postbox",
        "mailbox", "box", "message", "letter"]
SUF = ["", "host", "hub", "core", "pro", "plus", "box", "center", "express", "s"]
TLDS = ["com", "net", "co"]

_tls = threading.local()
_counter = itertools.count()
_lock = threading.Lock()
_prog = {"n": 0, "total": 0, "hits": 0}


def resolver():
    r = getattr(_tls, "r", None)
    if r is None:
        r = dns.resolver.Resolver(configure=False)
        i = next(_counter) % len(RESOLVERS)
        r.nameservers = [RESOLVERS[i]] + [n for n in RESOLVERS if n != RESOLVERS[i]]
        r.timeout, r.lifetime = 3.0, 6.0
        _tls.r = r
    return r


def txt(name):
    try:
        ans = resolver().resolve(name, "TXT", raise_on_no_answer=False)
        if ans.rrset is None:
            return []
        return [rr.to_text().replace('" "', "").strip('"') for rr in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def gen_candidates(known):
    out = set()
    for a, n, s in itertools.product(ADJ, NOUN, SUF):
        for stem in (f"{a}{n}{s}", f"{n}{a}{s}"):
            if 5 <= len(stem) <= 24:
                for tld in TLDS:
                    out.add(f"{stem}.{tld}")
    return sorted(out - known)


def probe(name):
    recs = txt(f"_dmarc.{name}")
    hit = any(URIPORTS_ACCOUNT in r for r in recs)
    with _lock:
        _prog["n"] += 1
        if hit:
            _prog["hits"] += 1
        if _prog["n"] % 2000 == 0:
            print(f"  {_prog['n']}/{_prog['total']} probed, {_prog['hits']} hits",
                  file=sys.stderr, flush=True)
    return {"domain": name, "hit": hit, "dmarc": ";".join(recs)} if recs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=48)
    args = ap.parse_args()

    known = {r["Domain"].strip().lower() for r in csv.DictReader(open(KNOWN_CSV))}
    cands = gen_candidates(known)
    _prog["total"] = len(cands)
    print(f"[*] probing {len(cands)} Group-2-style candidates", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        res = [r for r in ex.map(probe, cands) if r]

    hits = sorted(r["domain"] for r in res if r["hit"])
    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "method": (f"content-matched DMARC probe for {URIPORTS_ACCOUNT}.uriports.com; "
                   "wildcard-safe because the account id must appear inside the record"),
        "not_used_as_marker": ("141.94.97.141 == autoconfig.migadu.com, the mail vendor's "
                               "shared host; it identifies Migadu customers, not this operator"),
        "candidates_probed": len(cands),
        "with_any_dmarc": len(res),
        "new_group2_members": hits,
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}: {len(hits)} new members "
          f"({len(res)} candidates had any DMARC)", file=sys.stderr)


if __name__ == "__main__":
    main()
