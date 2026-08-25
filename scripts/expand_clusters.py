#!/usr/bin/env python3
"""
Expand the operator clusters beyond the supplied domain list.

Membership in either large cluster is directly testable over DNS:

  Group 1  ->  a TXT record exists at dc-aa8e722993._spfm.<domain>
  Group 2  ->  the domain's DMARC rua points at p7rqadcw.uriports.com

So candidate names generated from the corpus's own naming grammar can be
tested for membership with one or two queries each. Registered candidates
that match the grammar but carry neither marker are still reported: they are
naming-adjacent and worth manual triage.

Output: output/cluster_expansion.json
"""
import csv, json, itertools, os, sys, threading, argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.resolver, dns.exception

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_JSON = os.path.join(ROOT, "output", "cluster_expansion.json")
KNOWN_CSV = os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv")

SPFM_TENANT = "aa8e722993"
# Parking providers commonly serve wildcard DNS, which answers *any* subdomain and
# so returns a hit for the tenant marker on domains that have nothing to do with the
# cluster. Every marker hit is therefore re-tested against a random label; if that
# also answers, the zone is a wildcard and the hit is discarded.
# Two independent canaries at different depths, each retried, because a query
# timeout must never be mistaken for "no wildcard". Only a definitive NXDOMAIN
# clears a zone. The marker content is checked too: a bare "v=spf1 -all" is a
# parking default, not this tenant's record.
CANARY_LABELS = ["qq1zz9k7x._spfm.{d}", "zz7pq2xv9.{d}"]
PARKING_MARKERS = {"v=spf1 -all", "v=spf1 ?all", "v=spf1 ~all"}
URIPORTS_ACCOUNT = "p7rqadcw"

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]

# Naming grammar induced from the corpus.
PREFIX = ["", "my", "the"]
WORK   = ["job", "jobs", "it", "tech", "techs", "work", "works", "career",
          "careers", "cv", "talent", "hire", "hires", "apply", "resume",
          "candidate", "task", "tasks"]
MAIL   = ["mail", "mails", "email", "emails", "inbox", "box", "post",
          "mailbox", "message", "webmail", "mailhub", "mailer"]
SUFFIX = ["", "s", "hub", "box", "pro"]
TLDS   = ["com", "net", "co"]
# Same stem on another TLD is the highest-yield pivot of all, so known stems are
# re-tested across a wider TLD set than the generated names.
SWAP_TLDS = ["com", "net", "co", "io", "org", "us", "me", "pro", "email", "careers"]

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


def q(name, rtype):
    try:
        ans = resolver().resolve(name, rtype, raise_on_no_answer=False)
        return [rr.to_text() for rr in ans] if ans.rrset is not None else []
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def q_definitive(name, rtype, tries=3):
    """Distinguish "does not exist" from "could not be resolved".

    Returns [] only on a real NXDOMAIN/NoAnswer; returns None when every attempt
    errored, so callers can refuse to draw a conclusion from a failed lookup.
    """
    for _ in range(tries):
        try:
            ans = resolver().resolve(name, rtype, raise_on_no_answer=False)
            return [rr.to_text() for rr in ans] if ans.rrset is not None else []
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            continue
    return None


def has_wildcard(name):
    """True if the zone answers arbitrary labels; None if it could not be decided."""
    undecided = False
    for tmpl in CANARY_LABELS:
        res = q_definitive(tmpl.format(d=name), "TXT")
        if res is None:
            undecided = True
        elif res:
            return True
    return None if undecided else False


def unquote(recs):
    return [r.replace('" "', "").strip('"') for r in recs]


def gen_candidates(known):
    """Two sources: TLD swaps of known stems, and the corpus naming grammar."""
    out = set()

    # 1. same stem, different TLD
    for d in known:
        parts = d.split(".")
        if len(parts) < 2:
            continue
        stem = parts[0]
        if len(parts) > 2:          # skip test-google-a.com style artefacts
            continue
        for tld in SWAP_TLDS:
            out.add(f"{stem}.{tld}")

    # 2. grammar: work+mail and mail+work orderings, optional prefix/suffix
    for p, w, m, sfx in itertools.product(PREFIX, WORK, MAIL, SUFFIX):
        for stem in (f"{p}{w}{m}{sfx}", f"{p}{m}{w}{sfx}"):
            if not (5 <= len(stem) <= 24):
                continue
            for tld in TLDS:
                out.add(f"{stem}.{tld}")

    return sorted(out - known)


def probe(name):
    """One query settles Group-1 membership; registered names get a full check."""
    res = {"domain": name, "registered": False, "group": None, "wildcard": False,
           "ns": [], "mx": [], "spf": "", "dmarc": "", "marker_txt": ""}

    spfm = q(f"dc-{SPFM_TENANT}._spfm.{name}", "TXT")
    if spfm:
        res["registered"] = True
        marker = unquote(spfm)
        res["marker_txt"] = ";".join(marker)
        if all(m.strip() in PARKING_MARKERS for m in marker):
            res["wildcard"] = True          # parking default, not this tenant
        else:
            wc = has_wildcard(name)
            if wc is True:
                res["wildcard"] = True
            elif wc is False:
                res["group"] = "group1_spfm"
            else:
                res["group"] = "undecided_wildcard_check_failed"

    if res["group"] is None:
        ns = q(name, "NS")
        if not ns:
            _tick()
            return res
        res["registered"] = True
        res["ns"] = [x.rstrip(".") for x in ns]
    else:
        res["ns"] = [x.rstrip(".") for x in q(name, "NS")]

    dmarc = unquote(q(f"_dmarc.{name}", "TXT"))
    res["dmarc"] = ";".join(dmarc)
    # content-matched, so a wildcard cannot fake it
    if any(URIPORTS_ACCOUNT in t for t in dmarc):
        res["group"] = "group2_uriports"

    res["mx"] = [x.rstrip(".") for x in q(name, "MX")]
    res["spf"] = ";".join(t for t in unquote(q(name, "TXT"))
                          if t.lower().startswith("v=spf1"))
    _tick(hit=res["group"] is not None)
    return res


def _tick(hit=False):
    with _lock:
        _prog["n"] += 1
        if hit:
            _prog["hits"] += 1
        if _prog["n"] % 500 == 0:
            print(f"  {_prog['n']}/{_prog['total']} probed, "
                  f"{_prog['hits']} cluster hits", file=sys.stderr, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    known = {r["Domain"].strip().lower() for r in csv.DictReader(open(KNOWN_CSV))}
    cands = gen_candidates(known)
    if args.limit:
        cands = cands[: args.limit]
    _prog["total"] = len(cands)
    print(f"[*] probing {len(cands)} generated candidates "
          f"(excluding {len(known)} already known)", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(probe, cands))

    registered = [r for r in results if r["registered"]]
    g1 = [r for r in results if r["group"] == "group1_spfm"]
    g2 = [r for r in results if r["group"] == "group2_uriports"]

    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "method": ("candidate names generated from the corpus naming grammar and tested "
                   "for cluster membership via DNS markers "
                   f"(dc-{SPFM_TENANT}._spfm.<domain> TXT; {URIPORTS_ACCOUNT}.uriports.com in DMARC)"),
        "candidates_probed": len(results),
        "registered": len(registered),
        "new_group1_members": sorted(r["domain"] for r in g1),
        "new_group2_members": sorted(r["domain"] for r in g2),
        "wildcard_zones_excluded": sorted(r["domain"] for r in results if r["wildcard"]),
        "registered_naming_adjacent": sorted(
            r["domain"] for r in registered if r["group"] is None),
        "detail": [r for r in registered],
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}", file=sys.stderr)
    wc = sum(1 for r in results if r["wildcard"])
    print(f"[+] registered={len(registered)} group1_new={len(g1)} group2_new={len(g2)} "
          f"wildcard_discarded={wc}", file=sys.stderr)


if __name__ == "__main__":
    main()
