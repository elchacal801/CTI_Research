#!/usr/bin/env python3
"""
Link domains into operator groups using only *account-level* selectors.

The distinction that matters: a selector is account-level when only the party
controlling the domains could have produced it (a DKIM public key, an SPF-
management tenant id, a DMARC reporting-platform account, a provider ownership
token). It is vendor-level when the hosting provider produces it for every one
of its customers -- shared MX, shared parking IPs, and shared reverse-DNS on
provider infrastructure all fall here, and clustering on them merely rediscovers
the vendor's customer base.

Connected components are computed over account-level edges only; vendor-level
facts are then attached to each group as corroboration, never as the link.

Output: output/operator_clusters.json
"""
import csv, json, os, re, sys
from collections import defaultdict, Counter
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_CSV = os.path.join(ROOT, "output", "domain_infrastructure.csv")
OUT_JSON = os.path.join(ROOT, "output", "operator_clusters.json")

# Reverse-DNS suffixes that belong to a hosting vendor's shared estate. A match
# here means "same vendor", never "same customer".
VENDOR_PTR = [
    "awsglobalaccelerator.com",   # GoDaddy parking / website-builder front end
    "1e100.net",                  # Google
    "wixsite.com", "wixdns.net",
    "protonmail.ch",
    "squarespace.com", "sqspcdn.com",
    "cloudflare.com", "cloudflare.net",
    "amazonaws.com",
    "hostinger.com", "hostinger.io",
    "outlook.com", "office365.com",
    "migadu.com",
    "messagingengine.com",
    "shopify.com",
    "vercel-dns.com",
]


def is_vendor_ptr(host):
    h = (host or "").lower()
    return any(h.endswith(s) for s in VENDOR_PTR)


class DSU:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def load_deep_dkim():
    """Second-pass DKIM sweep uses a much longer selector list; merge it in."""
    p = os.path.join(ROOT, "output", "deep_enumeration.json")
    if not os.path.exists(p):
        return {}
    deep = json.load(open(p))
    return {d["domain"]: d.get("dkim", {}) for d in deep["domains"]}


DEEP_DKIM = load_deep_dkim()


def dkim_key_selectors(dns_json, domain):
    out = []
    merged = {}
    for d in dns_json["domains"]:
        if d["domain"] == domain:
            merged.update(d["dkim"])
    merged.update(DEEP_DKIM.get(domain, {}))
    for sel, vals in merged.items():
        for v in vals:
            m = re.search(r"p=([A-Za-z0-9+/=]{40,})", v)
            if m:
                out.append(f"dkim:{sel}:{m.group(1)[:64]}")
    return out


def main():
    rows = list(csv.DictReader(open(IN_CSV, encoding="utf-8")))
    dns_json = json.load(open(os.path.join(ROOT, "output", "dns_enumeration.json")))

    # ---- account-level selectors per domain ----
    acct = {}
    for r in rows:
        s = set()
        s.update(x for x in r["spf_manager_tenant"].split(";") if x)
        s.update(x for x in r["dmarc_tenant"].split(";") if x)
        s.update(f"vtok:{x}" for x in r["verification_tokens"].split(";") if x)
        s.update(dkim_key_selectors(dns_json, r["domain"]))
        # non-vendor reverse DNS is account-level (a host the operator runs)
        s.update(f"ptr:{p}" for p in r["hosting_ptr"].split(";")
                 if p and not is_vendor_ptr(p))
        # a registrant organisation the registrar actually disclosed (never a
        # proxy service, never a redacted placeholder) is account-level
        if r.get("registrant_org"):
            s.add(f"regorg:{r['registrant_org'].strip().lower()}")
        acct[r["domain"]] = s

    # A verification token or PTR seen on exactly one domain links nothing; keep
    # only selectors shared by two or more domains as edges.
    shared = Counter()
    for s in acct.values():
        for k in s:
            shared[k] += 1
    edge_selectors = {k for k, c in shared.items() if c > 1}

    dsu = DSU()
    sel_members = defaultdict(list)
    for dom, s in acct.items():
        dsu.find(dom)
        for k in s & edge_selectors:
            sel_members[k].append(dom)
    for k, members in sel_members.items():
        for m in members[1:]:
            dsu.union(members[0], m)

    comps = defaultdict(list)
    for dom in acct:
        comps[dsu.find(dom)].append(dom)

    by_dom = {r["domain"]: r for r in rows}
    groups = []
    for members in comps.values():
        if len(members) < 2:
            continue
        members = sorted(members)
        evidence = sorted({k for m in members for k in acct[m] & edge_selectors})
        mem_rows = [by_dom[m] for m in members]
        groups.append({
            "size": len(members),
            "domains": members,
            "linking_evidence": evidence,
            "corroboration": {
                "ns_operator": Counter(r["ns_operator"] for r in mem_rows).most_common(),
                "mx_provider": Counter(r["mx_provider"] for r in mem_rows).most_common(),
                "soa_rname": Counter(r["soa_rname"] for r in mem_rows).most_common(3),
                "hosting_ips": Counter(i for r in mem_rows
                                       for i in r["hosting_ips"].split(";") if i).most_common(6),
                "dmarc_policy": Counter(r["dmarc_policy"] or "none-published"
                                        for r in mem_rows).most_common(),
                "risk_tier": Counter(r["risk_tier"] for r in mem_rows).most_common(),
                "domain_class": Counter(r["domain_class"] for r in mem_rows).most_common(),
                "registrar": Counter(r.get("registrar") or "not collected"
                                     for r in mem_rows).most_common(),
                "registrant_disclosure": Counter(
                    (r.get("registrant_proxy_service") or r.get("registrant_disclosure") or "no registrar-side record")
                    for r in mem_rows).most_common(),
                "registrant_geo": Counter(r.get("registrant_geo") for r in mem_rows
                                          if r.get("registrant_geo")).most_common(6),
                "created_range": [min((r["created_day"] for r in mem_rows if r.get("created_day")),
                                      default=None),
                                  max((r["created_day"] for r in mem_rows if r.get("created_day")),
                                      default=None)],
                "abuse_contacts": sorted({r["abuse_email"] for r in mem_rows if r.get("abuse_email")}),
            },
        })
    groups.sort(key=lambda g: -g["size"])

    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "method": ("connected components over account-level selectors only "
                   "(DKIM public key, SPF-management tenant, DMARC reporting-platform "
                   "account, provider verification token, non-vendor reverse DNS); "
                   "vendor-level facts attached as corroboration only"),
        "vendor_ptr_suffixes_excluded": VENDOR_PTR,
        "group_count": len(groups),
        "domains_in_groups": sum(g["size"] for g in groups),
        "groups": groups,
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}: {len(groups)} groups covering "
          f"{sum(g['size'] for g in groups)} domains")
    for g in groups[:10]:
        print(f"    {g['size']:3d}  {', '.join(g['linking_evidence'][:3])}")
    return out


if __name__ == "__main__":
    main()
