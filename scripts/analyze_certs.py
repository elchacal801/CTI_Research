#!/usr/bin/env python3
"""
Certificate-transparency analysis.

Reads output/cert_enumeration.json (crt.sh SANs) and links domains on shared
certificates. A certificate whose SANs span two or more different registrable
domains means one party proved control of all of them to the CA in a single
request -- an account-level link, the same strength tier as a shared DKIM key.

Two things are controlled out before a shared cert is treated as a link:

  * Multi-tenant vendor/SaaS certificates. A CDN, website builder or CRM packs
    many unrelated customers onto one certificate (GoHighLevel/LeadConnector,
    DuckDuckGo, GMX/1&1, Automattic, mail providers). These are recognised by a
    vendor host appearing in the SANs, or by an implausibly large registrable-
    domain span, and are excluded from linking.
  * Reference-set providers already in the corpus (Proton, SimpleLogin, mail.ru)
    legitimately share certs across their own estate; their clusters are labelled
    rather than reported as findings.

Output: output/cert_analysis.json
"""
import json, os, re
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")
IN_CERTS = os.path.join(OUT, "cert_enumeration.json")
IN_RDAP = os.path.join(OUT, "rdap_enumeration.json")
IN_CSV = os.path.join(OUT, "domain_infrastructure.csv")
IN_OPS = os.path.join(OUT, "operator_clusters.json")
OUT_JSON = os.path.join(OUT, "cert_analysis.json")

TWO_LABEL_SUFFIX = {"co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.in",
                    "co.za", "co.nz", "com.mx", "com.tw", "com.co", "id.vn", "name.ng"}

# A registrable domain from this set in a cert marks it as a multi-tenant vendor /
# SaaS / shared-hosting certificate: it links the vendor's customers, not a single
# operator, so it is not used to link.
VENDOR_HOSTS = {
    # website builders / CRM / marketing SaaS that pack customers onto one cert
    "invincible.design", "leadconnectorhq.com", "gohighlevel.com", "msgsndr.com",
    "chatleadspro.com", "weareflo.com", "snipdle.com", "automattic.com",
    "wordpress.com", "wpengine.com", "framer.app", "vercel.app", "netlify.app",
    "web.app", "spiffyweb.net", "squarespace.com", "wixsite.com", "cloudflaressl.com",
    # mail / privacy providers (own estate)
    "proton.me", "protonmail.ch", "protonmail.com", "pm.me", "protonvpn.ch",
    "protonvpn.com", "simplelogin.co", "simplelogin.com", "simplelogin.fr",
    "simplelogin.io", "8alias.com", "8shield.net", "aleeas.com", "dralias.com",
    "pass2mail.com", "passfwd.com", "silomails.com", "slmail.me", "slmails.com",
    "mail.ru", "mailru.com", "my.com", "list.ru", "inbox.ru", "bk.ru",
    # portal / delivery / esp platforms
    "ui-portal.de", "uimserv.net", "gmx.net", "web.de", "1und1.de", "mail.com",
    "cmp.jobs", "arcamax.com", "netcoredelivery.nobroker.in", "duckduckgo.com",
    "donttrack.us", "ddg.co", "dukgo.com",
}
# Same for a substring in the CN/subject (covers hosts we cannot enumerate fully).
VENDOR_CN_SUBSTR = ["automattic", "ui-portal", "leadconnector", "exaltsystems",
                    "weareflo", "snipdle", "cmp.jobs", "cleartrip", "makemytrip"]
MAX_REG_SPAN = 25            # more distinct registrable domains than this => multi-tenant

REFERENCE_PROVIDERS = {"proton", "simplelogin", "mail.ru", "fastmail", "tuta", "posteo",
                       "runbox", "duck"}


def reg_domain(host):
    host = (host or "").strip().lower().rstrip(".").lstrip("*.")
    p = host.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in TWO_LABEL_SUFFIX:
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else host


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


def load_flat():
    if not os.path.exists(IN_CSV):
        return {}
    import csv
    return {r["domain"]: r for r in csv.DictReader(open(IN_CSV, encoding="utf-8"))}


def main():
    data = json.load(open(IN_CERTS))
    doms = data["domains"]
    tset = {d: v["set"] for d, v in doms.items()}
    targets = set(tset)
    flat = load_flat()
    ops = json.load(open(IN_OPS)) if os.path.exists(IN_OPS) else {"groups": []}
    group_of = {}
    for i, g in enumerate(ops["groups"], 1):
        for d in g["domains"]:
            group_of[d] = i

    # ---- dedupe certs across every domain's apex+sub result ----
    certs = {}
    for d, v in doms.items():
        for c in v["certs"]:
            key = c.get("crtsh_id") or (c.get("serial"), tuple(c["sans"]))
            if key not in certs:
                certs[key] = c
    for c in certs.values():
        c["reg_domains"] = sorted({reg_domain(s) for s in c["sans"] if s})

    def is_vendor(c):
        if any(rd in VENDOR_HOSTS for rd in c["reg_domains"]):
            return True
        cn = (c.get("common_name") or "") + " " + " ".join(c["sans"][:1])
        if any(sub in cn for sub in VENDOR_CN_SUBSTR):
            return True
        if len(c["reg_domains"]) > MAX_REG_SPAN:
            return True
        return False

    # ---- shared-cert links among registrable domains (vendor certs excluded) ----
    dsu = DSU()
    link_certs = []
    for c in certs.values():
        rds = [r for r in c["reg_domains"] if r]
        touches_target = any(r in targets for r in rds)
        if len(set(rds)) < 2 or not touches_target or is_vendor(c):
            continue
        link_certs.append(c)
        for r in rds[1:]:
            dsu.union(rds[0], r)

    comp = defaultdict(set)
    for c in link_certs:
        for r in c["reg_domains"]:
            comp[dsu.find(r)].add(r)

    clusters = []
    for members in comp.values():
        if len(members) < 2:
            continue
        tgt = sorted(m for m in members if m in targets)
        ext = sorted(m for m in members if m not in targets)
        sets = Counter(tset[m] for m in tgt)
        grp = sorted({group_of[m] for m in tgt if m in group_of})
        mcerts = [c for c in link_certs if set(c["reg_domains"]) & members]
        issuers = Counter(c["issuer"].split("CN=")[-1][:20] for c in mcerts)
        nb = sorted(c["not_before"][:10] for c in mcerts if c.get("not_before"))
        # is this a reference-set provider estate?
        ref = any(any(rp in m for rp in REFERENCE_PROVIDERS) for m in members)
        corpus_touching = any(tset[m] in ("corpus", "lead", "discovered") for m in tgt)
        # one tenant among many unrelated externals = a shared-hosting reseller cert,
        # not an operator cluster
        shared_hosting = len(tgt) == 1 and len(ext) >= 2 * max(len(tgt), 1) and len(ext) >= 3
        clusters.append({
            "size": len(members), "targets": tgt, "external_siblings": ext,
            "corpus_touching": corpus_touching, "likely_shared_hosting": shared_hosting,
            "target_sets": sets.most_common(), "operator_groups": grp,
            "n_link_certs": len(mcerts), "issuers": issuers.most_common(3),
            "first_seen_cert": nb[0] if nb else None, "last_seen_cert": nb[-1] if nb else None,
            "classification": ("reference-set provider estate" if ref else
                               f"extends operator group {grp[0]}" if grp else
                               "cert-linked cluster (no group marker)"),
            "sample_san_hosts": sorted({s for c in mcerts for s in c["sans"]})[:24],
        })
    clusters.sort(key=lambda c: (-len(c["targets"]), -c["size"]))

    # ---- SAN siblings: non-target registrable domains sharing a non-vendor cert ----
    siblings = defaultdict(set)
    for c in certs.values():
        if is_vendor(c):
            continue
        tdoms = {r for r in c["reg_domains"] if r in targets and tset[r] in ("corpus", "lead", "discovered")}
        others = {r for r in c["reg_domains"] if r not in targets}
        for t in tdoms:
            siblings[t] |= others
    siblings = {k: sorted(v) for k, v in siblings.items() if v}

    # ---- do the operator-group domains get certs at all, and when? ----
    group_cert_timeline = {}
    for i, g in enumerate(ops["groups"], 1):
        rows = []
        for d in g["domains"]:
            dc = doms.get(d, {}).get("certs", [])
            nb = sorted(c["not_before"][:10] for c in dc if c.get("not_before"))
            rows.append({"domain": d, "n_certs": len(dc),
                         "first_cert": nb[0] if nb else None, "last_cert": nb[-1] if nb else None})
        with_cert = [r for r in rows if r["n_certs"]]
        gmembers = set(g["domains"])
        multi = [sorted(set(c["reg_domains"]) & gmembers) for c in certs.values()
                 if len(set(c["reg_domains"]) & gmembers) >= 2]
        group_cert_timeline[i] = {
            "members": len(g["domains"]), "with_any_cert": len(with_cert),
            "certs_spanning_two_members": len(multi),
            "spanning_examples": multi[:3],
            "note": ("members get individual per-domain certificates on shared "
                     "parking / vendor infrastructure; certificates neither merge nor "
                     "extend this group" if not multi else
                     "at least one certificate spans two members"),
        }

    # coverage
    cov = Counter()
    covc = Counter()
    for d, v in doms.items():
        cov[v["set"]] += 1
        if v["certs"]:
            covc[v["set"]] += 1

    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": data.get("source", "crt.sh"),
        "cert_enumeration_generated": data.get("generated_utc"),
        "domains_queried": len(doms),
        "distinct_certs": len(certs),
        "coverage": {s: {"domains": cov[s], "with_cert": covc[s]} for s in cov},
        "vendor_hosts_excluded": sorted(VENDOR_HOSTS),
        "max_registrable_span_for_linking": MAX_REG_SPAN,
        "cert_linked_clusters": clusters,
        "san_siblings": siblings,
        "operator_group_cert_status": group_cert_timeline,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}")
    print(f"    {len(certs)} distinct certs; {len(clusters)} cert-linked clusters; "
          f"{len(siblings)} target domains with non-vendor SAN siblings")
    for c in clusters:
        print(f"    [{c['size']:2d}] {c['classification']}: "
              f"{', '.join(c['targets'][:4])}{' …' if len(c['targets'])>4 else ''}")


if __name__ == "__main__":
    main()
