#!/usr/bin/env python3
"""Render the analyst-facing infrastructure report from the enumeration outputs."""
import json, os, sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_infra import main as analyze  # noqa: E402
from cluster_operators import main as cluster_operators  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_MD = os.path.join(ROOT, "output", "INFRASTRUCTURE_REPORT.md")


def tbl(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def main():
    rows, pivots, data = analyze()
    by_domain = {r["domain"]: r for r in rows}
    live = [r for r in rows if r["resolves"]]
    dead = [r for r in rows if not r["resolves"]]

    L = []
    A = L.append
    A("# Domain Infrastructure Enumeration")
    A("")
    A(f"**Generated:** {data['generated_utc']}  ")
    A(f"**Source list:** `{data['source']}` — {len(rows)} domains  ")
    A(f"**Collection:** live DNS over UDP/53 against {', '.join(data['resolvers'])}; "
      "ASN/BGP/country via the Team Cymru IP-to-ASN DNS service.")
    A("")

    A("## 1. Collection scope and coverage")
    A("")
    A(tbl(["Metric", "Count"], [
        ["Domains in list", len(rows)],
        ["Resolving (have NS/SOA/A/MX)", len(live)],
        ["Non-resolving / NXDOMAIN", len(dead)],
        ["With MX (mail-capable)", sum(1 for r in rows if r['mx'])],
        ["With SPF", sum(1 for r in rows if r['spf'])],
        ["With DMARC", sum(1 for r in rows if r['dmarc'])],
        ["With DKIM key found", sum(1 for r in rows if r['dkim_selectors'])],
        ["With CAA", sum(1 for r in rows if r['caa'])],
        ["Unique IPs observed", len(data['ip_intel'])],
        ["Unique ASNs", len({a for r in rows for a in r['asns'].split(';') if a})],
        ["Subdomains discovered", sum(len([x for x in r['subdomains_found'].split(';') if x]) for r in rows)],
    ]))
    A("")

    A("### RDAP / WHOIS status")
    A("")
    rdap_path = os.path.join(ROOT, "output", "rdap_enumeration.json")
    note = ("Not collected in this environment. Outbound HTTPS to RDAP endpoints "
            "(`rdap.org`, `rdap.verisign.com`, registry RDAP servers) is refused by the "
            "session's egress policy with `403 Forbidden` on CONNECT, and outbound "
            "TCP/443-to-43 WHOIS is likewise blocked. `scripts/enumerate_rdap.py` "
            "implements the full collection (registrar, IANA ID, creation/expiry/last-changed "
            "dates, status codes, abuse contact, registrant country, delegated NS, DNSSEC) "
            "and will populate `output/rdap_enumeration.json` when run from a network that "
            "permits that egress.")
    if os.path.exists(rdap_path):
        rd = json.load(open(rdap_path))
        if rd.get("succeeded"):
            note = f"Collected: {rd['succeeded']} succeeded, {rd['failed']} failed."
    A(note)
    A("")
    A("Registrar attribution below is therefore inferred from **delegated nameservers and "
      "SOA responsible-party mailboxes**, which is a reliable proxy for the DNS operator "
      "and usually the registrar, but is not a substitute for registration dates.")
    A("")

    A("## 2. Hosting and service concentration")
    A("")
    ns_op = Counter(r["ns_operator"] for r in rows if r["resolves"])
    A("**DNS operator / inferred registrar**")
    A("")
    A(tbl(["Operator", "Domains", "Share of live"],
          [[k, v, f"{100*v/max(len(live),1):.1f}%"] for k, v in ns_op.most_common(15)]))
    A("")

    mxp = Counter(r["mx_provider"] for r in rows if r["mx"])
    A("**Mail provider (from MX)**")
    A("")
    A(tbl(["Provider", "Domains"], [[k, v] for k, v in mxp.most_common(15)]))
    A("")

    asn_c = Counter()
    asn_name = {}
    for r in rows:
        for a, n in zip(r["asns"].split(";"), r["as_names"].split(";") or []):
            if a:
                asn_c[a] += 1
    for r in rows:
        for a in r["asns"].split(";"):
            if a and a not in asn_name:
                for ip in r["ips"].split(";"):
                    info = data["ip_intel"].get(ip) or {}
                    if info.get("asn") == a:
                        asn_name[a] = info.get("as_name") or ""
                        break
    host_asn = Counter(a for r in rows for a in r["hosting_asns"].split(";") if a)
    mail_asn = Counter(a for r in rows for a in r["mail_asns"].split(";") if a)
    A("**Hosting ASN** (from the domain's own A/AAAA records and discovered subdomains)")
    A("")
    A(tbl(["ASN", "AS name", "Domains"],
          [[f"AS{a}", asn_name.get(a, ""), c] for a, c in host_asn.most_common(15)]))
    A("")
    A("**Mail-path ASN** (from MX host IPs — vendor infrastructure, not attributable)")
    A("")
    A(tbl(["ASN", "AS name", "Domains"],
          [[f"AS{a}", asn_name.get(a, ""), c] for a, c in mail_asn.most_common(8)]))
    A("")

    cc = Counter(c for r in rows for c in r["geo_cc"].split(";") if c)
    A(f"**Geo (BGP registry country):** " +
      ", ".join(f"{k} ({v})" for k, v in cc.most_common(10)))
    A("")

    A("## 3. Mail authentication posture")
    A("")
    mailcap = [r for r in rows if r["mx"]]
    dm = Counter(r["dmarc_policy"] or "none-published" for r in mailcap)
    A(tbl(["DMARC policy (mail-capable domains)", "Count"],
          [[k, v] for k, v in dm.most_common()]))
    A("")
    spf_inc = Counter(i for r in rows for i in r["spf_includes"].split(";") if i)
    A("**Most common SPF includes**")
    A("")
    A(tbl(["SPF include / mechanism", "Domains"], [[k, v] for k, v in spf_inc.most_common(15)]))
    A("")

    A("## 4. Infrastructure pivot clusters")
    A("")
    A("Clusters are sets of two or more domains sharing an infrastructure selector. "
      "Selectors are ordered below from strongest to weakest attribution value: a shared "
      "DKIM public key or provider verification token implies a shared *account*, a shared "
      "IP or PTR implies shared *hosting*, and a shared ASN or provider only implies a "
      "shared *vendor* and is weak on its own.")
    A("")

    strength = [
        ("dkim_key", "Shared DKIM public key",
         "very high — the same private key signs mail for every member, so one mail account/tenant controls them"),
        ("spf_manager_tenant", "Shared SPF-management tenant",
         "very high — one account administers SPF for every member domain"),
        ("dmarc_tenant", "Shared DMARC reporting-platform account",
         "very high — DMARC failure reports for every member land in one operator's account"),
        ("verification_token", "Shared provider verification token",
         "very high — same provider tenant proved ownership of every member"),
        ("dmarc_rua", "Shared DMARC reporting address",
         "high — same reporting mailbox (weaker where it is a provider default)"),
        ("hosting_ptr", "Shared hosting reverse-DNS hostname",
         "high — same host (excludes mail-vendor IPs)"),
        ("hosting_ip", "Shared hosting IP",
         "high on dedicated hosting, low on shared/parking/CDN ranges"),
        ("cname_target", "Shared CNAME target", "medium-high"),
        ("soa_rname", "Shared SOA responsible mailbox", "medium — same DNS operator"),
        ("nameserver_host", "Shared authoritative nameserver", "medium"),
        ("hosting_bgp_prefix", "Shared hosting BGP prefix", "low"),
        ("mx_host", "Shared MX host", "low — vendor-level"),
        ("spf_include", "Shared SPF include", "low — vendor-level"),
        ("hosting_asn", "Shared hosting ASN", "very low — vendor-level only"),
    ]
    for key, title, note in strength:
        p = pivots.get(key, {})
        cl = p.get("clusters", [])
        if not cl:
            continue
        A(f"### {title}")
        A(f"*Attribution strength: {note}*")
        A("")
        shown = [c for c in cl if c["count"] > 1][:12]
        body = []
        for c in shown:
            doms = ", ".join(c["domains"][:12])
            if c["count"] > 12:
                doms += f", … (+{c['count']-12} more)"
            body.append([f"`{c['selector'][:70]}`", c["count"], doms])
        A(tbl(["Selector", "Domains", "Members"], body))
        if len(cl) > len(shown):
            A("")
            A(f"*{len(cl)-len(shown)} further clusters of this type in "
              "`output/pivot_clusters.json`.*")
        A("")

    A("## 5. Linked operator groups")
    A("")
    A("The clusters in section 4 are single selectors. This section merges them into "
      "connected components using **account-level selectors only** — a DKIM public key, "
      "an SPF-management tenant id, a DMARC reporting-platform account, a provider "
      "verification token, or reverse DNS on a host that is not a hosting vendor's "
      "shared estate. Vendor-level facts (shared MX, shared parking IPs, provider "
      "reverse DNS) are attached as corroboration but never used to link, because "
      "clustering on them only rediscovers the vendor's customer base.")
    A("")
    ops = cluster_operators()
    A(f"**{ops['group_count']} groups covering {ops['domains_in_groups']} of "
      f"{len(rows)} domains.**")
    A("")
    for i, g in enumerate(ops["groups"], 1):
        A(f"### Group {i} — {g['size']} domains")
        A("")
        A(f"**Linking evidence:** " + ", ".join(f"`{e}`" for e in g["linking_evidence"][:6]))
        A("")
        c = g["corroboration"]
        A(tbl(["Attribute", "Value"], [
            ["DNS operator", ", ".join(f"{k} ({v})" for k, v in c["ns_operator"])],
            ["Mail provider", ", ".join(f"{k} ({v})" for k, v in c["mx_provider"])],
            ["SOA responsible party", ", ".join(f"`{k}` ({v})" for k, v in c["soa_rname"] if k)],
            ["Hosting IPs", ", ".join(f"`{k}` ({v})" for k, v in c["hosting_ips"])],
            ["DMARC policy", ", ".join(f"{k} ({v})" for k, v in c["dmarc_policy"])],
            ["Risk tier", ", ".join(f"{k} ({v})" for k, v in c["risk_tier"])],
            ["Naming theme", ", ".join(f"{k} ({v})" for k, v in c["domain_class"])],
        ]))
        A("")
        A("**Members:** " + ", ".join(f"`{d}`" for d in g["domains"]))
        A("")

    A("## 6. Non-resolving domains")
    A("")
    A(f"{len(dead)} of {len(rows)} entries returned no NS/SOA/A/MX. These are either "
      "deregistered/expired, never registered, or malformed strings captured from log or "
      "header parsing (e.g. truncated or concatenated addresses).")
    A("")
    malformed = [r["domain"] for r in dead
                 if r["domain"].rsplit(".", 1)[-1] not in
                 {"com","net","org","io","co","me","us","uk","ca","in","ru","ch","no","ai",
                  "pro","careers","email","help","cloud"}]
    if malformed:
        A("**Invalid/nonexistent TLD — parsing artefacts, not real infrastructure:**")
        A("")
        A(", ".join(f"`{m}`" for m in sorted(malformed)))
        A("")
    real_dead = sorted(r["domain"] for r in dead if r["domain"] not in set(malformed))
    if real_dead:
        A("**Valid TLD but not resolving (expired, parked-without-DNS, or never registered):**")
        A("")
        A(", ".join(f"`{m}`" for m in real_dead))
        A("")

    A("## 7. Per-domain detail")
    A("")
    A("Full records are in `output/dns_enumeration.json` (raw) and "
      "`output/domain_infrastructure.csv` (flat table). Summary of the highest-risk tier:")
    A("")
    hi = [r for r in rows if r["risk_tier"] == "high"]
    A(tbl(["Domain", "Score", "NS operator", "Mail provider", "ASN", "DMARC", "IPs"],
          [[r["domain"], r["risk_score"], r["ns_operator"], r["mx_provider"],
            ";".join(f"AS{a}" for a in r["hosting_asns"].split(";") if a) or "-",
            r["dmarc_policy"] or "-", r["hosting_ips"][:44] or "-"] for r in
           sorted(hi, key=lambda x: -int(x["risk_score"] or 0))]))
    A("")

    with open(OUT_MD, "w") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"[+] wrote {OUT_MD}")


if __name__ == "__main__":
    main()
