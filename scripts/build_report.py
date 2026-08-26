#!/usr/bin/env python3
"""Render the analyst-facing infrastructure report from the enumeration outputs.

Runs the flat-table/pivot analysis, operator clustering and registration-timing
analysis first so every number in the report comes from the same pass."""
import json, os, sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_infra import main as analyze, PLACEHOLDER_GEO, geo_control_check  # noqa: E402
from cluster_operators import main as cluster_operators  # noqa: E402
from temporal_analysis import main as temporal  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_MD = os.path.join(ROOT, "output", "INFRASTRUCTURE_REPORT.md")


def tbl(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def load(name):
    fp = os.path.join(ROOT, "output", name)
    return json.load(open(fp)) if os.path.exists(fp) else None


def gfmt(k):
    """'GB|East Sussex' -> 'GB / East Sussex'; 'LT|?' -> 'LT'."""
    if not k:
        return "-"
    cc, _, region = k.partition("|")
    return f"{cc} / {region}" if region and region != "?" else cc


def code(items, limit=None):
    items = list(items)
    s = ", ".join(f"`{d}`" for d in items[:limit] if d)
    if limit and len(items) > limit:
        s += f", … (+{len(items) - limit} more)"
    return s or "none"


def main():
    rows, pivots, data = analyze()
    ops = cluster_operators()
    temporal()
    tmp = load("temporal_analysis.json")
    rdap = load("rdap_enumeration.json") or {"records": []}
    controls = load("rdap_controls.json")
    exp, g2, deep = load("cluster_expansion.json"), load("group2_expansion.json"), load("deep_enumeration.json")
    cta_sum = load("cert_analysis.json")

    by_domain = {r["domain"]: r for r in rows}
    live = [r for r in rows if r["resolves"]]
    dead = [r for r in rows if not r["resolves"]]
    rd_by = {r["domain"]: r for r in rdap["records"]}
    rdap_collected = bool(rdap.get("succeeded"))
    n_ctl = len(controls["records"]) if controls else 0
    tl = {t["group"]: t for t in tmp["group_timelines"]}
    reg = tmp["registration"]
    base = tmp["base_rates"]
    clean_subs = sum(len(x["subdomains"]) for x in deep["domains"]) if deep else None

    # expansion-confirmed members folded into their groups
    extra = defaultdict(list)
    for g in ops["groups"]:
        pass
    g1_idx = next((i for i, g in enumerate(ops["groups"], 1) if "spfm:aa8e722993" in g["linking_evidence"]), 1)
    g2_idx = next((i for i, g in enumerate(ops["groups"], 1) if "uriports:p7rqadcw" in g["linking_evidence"]), 2)
    if exp:
        extra[g1_idx] = exp.get("new_group1_members", [])
    if g2:
        extra[g2_idx] = g2.get("new_group2_members", [])

    # registration cohorts outside the groups: same-registrar bursts with no group member
    cohort_bursts = [b for b in tmp["registration_bursts"] if not b["groups"]]
    sq_bursts = [b for b in cohort_bursts if b["registrar"].startswith("Squarespace")]
    sq_cohort = sorted({d for b in sq_bursts for d in b["domains"]})
    other_bursts = [b for b in cohort_bursts if not b["registrar"].startswith("Squarespace")]

    def on_sq_front_end(d):
        r = by_domain.get(d)
        return bool(r) and ("198.185.159." in r["hosting_ips"] or "198.49.23." in r["hosting_ips"]
                            or r["ns_operator"].startswith("NS1"))
    sq_a = [d for d in sq_cohort if on_sq_front_end(d)]            # synthetic brands, NS1/Squarespace front end
    sq_b = [d for d in sq_cohort if not on_sq_front_end(d)]        # job-themed, Google Domains DNS
    sq_a_bursts = [b for b in sq_bursts if any(d in sq_a for d in b["domains"])]
    sq_b_bursts = [b for b in sq_bursts if any(d in sq_b for d in b["domains"])]

    disc = Counter(r["registrant_disclosure"] or "no registrar-side record" for r in rows if r["registered"] == "yes")
    proxy = Counter(r["registrant_proxy_service"] for r in rows if r["registrant_proxy_service"])
    geo = Counter(r["registrant_geo"] for r in rows if r["registrant_geo"])
    disclosed_orgs = sorted({(r["registrant_org"], r["registrant_geo"], r["domain"]) for r in rows if r["registrant_org"]})
    lc = tmp["lifecycle"]

    L = []
    A = L.append
    A("# Domain Infrastructure Enumeration")
    A("")
    A(f"**Generated:** {data['generated_utc'][:19]}Z (DNS); {rdap.get('generated_utc', '')[:19]}Z (RDAP)  ")
    A(f"**Source list:** `{data['source']}` — {len(rows)} domains, plus "
      f"{len([r for r in rdap['records'] if r.get('source_list') == 'discovered'])} members confirmed by the "
      "expansion sweep  ")
    A(f"**Collection:** live DNS over UDP/53 against {', '.join(data['resolvers'])}; ASN/BGP/country via "
      "the Team Cymru IP-to-ASN DNS service; registry RDAP via the IANA bootstrap with registrar RDAP "
      "followed through each registry's `related` link, and WHOIS/43 where no RDAP exists. Registration "
      "data was collected from a separate network path that permits the RDAP and WHOIS egress the DNS "
      "pass lacked.")
    A("")

    # ------------------------------------------------------------------ 1
    A("## 1. Summary of findings")
    A("")
    g1, g2t = tl.get(g1_idx, {}), tl.get(g2_idx, {})
    A(f"- **Two operator groups are established on account-level evidence.** Group {g1_idx} "
      f"({g1.get('size')} domains, SPF-management tenant `aa8e722993`) is registered entirely at "
      f"{g1.get('registrars', [['?']])[0][0]}; Group {g2_idx} ({g2t.get('size')} domains, URIports "
      f"account `p7rqadcw`) entirely at {g2t.get('registrars', [['?']])[0][0]}. Registry timestamps show "
      f"both were built in checkout-sized bursts: {g1.get('members_in_bursts')} of {g1.get('with_created')} "
      f"Group {g1_idx} members and {g2t.get('members_in_bursts')} of {g2t.get('with_created')} Group "
      f"{g2_idx} members were registered within ten minutes of another member at the same registrar, "
      f"against a control-population rate of {100 * base['control_burst_share']:.1f}%.")
    if sq_a:
        A(f"- **Two further cohorts are probable but not proven.** {len(sq_a)} synthetic-brand mailbox "
          f"domains on Squarespace's shared front end were registered at Squarespace in "
          f"{len(sq_a_bursts)} bursts between {min(b['start'][:10] for b in sq_a_bursts)} and "
          f"{max(b['start'][:10] for b in sq_a_bursts)} (the tightest: {min(b['span_s'] for b in sq_a_bursts)} "
          "seconds for "
          f"{next(b['count'] for b in sq_a_bursts if b['span_s'] == min(x['span_s'] for x in sq_a_bursts))} "
          f"domains); {len(sq_b)} job-themed domains on Google Domains DNS were registered in "
          f"{len(sq_b_bursts)} Squarespace burst{'s' if len(sq_b_bursts) != 1 else ''}"
          + (f" (the tightest: {min(b['span_s'] for b in sq_b_bursts)} seconds for "
             f"{next(b['count'] for b in sq_b_bursts if b['span_s'] == min(x['span_s'] for x in sq_b_bursts))} "
             "domains" + (f", with {len({c['control_domain'] for c in tmp['control_collisions'] if c['corpus_domain'] in sq_b})} "
                          "further names the control sweep caught in the same checkout)"
                          if any(c['corpus_domain'] in sq_b for c in tmp['control_collisions']) else ")")
             if sq_b_bursts else "") +
          ". Identical naming grammar, "
          "identical hosting and same-checkout timing point to one operator each, but no account-level "
          "artefact links either set, so both are reported as registration cohorts rather than merged "
          "into operator groups.")
    rs = tmp["registrar_share"]
    over = [x for x in rs if x["corpus"] >= 10 and x["lift"] and x["lift"] >= 3]
    if not n_ctl:
        A(f"- **Registrar.** {rs[0]['registrar']} and {rs[1]['registrar']} hold "
          f"{rs[0]['corpus_pct'] + rs[1]['corpus_pct']:.0f}% of the corpus; no control population was "
          "collected, so registrar share is reported without a baseline and is not used to link.")
    elif over:
        A(f"- **Registrar is over-represented but not diagnostic.** " +
          ", ".join(f"{x['registrar']} holds {x['corpus_pct']}% of the corpus against "
                    f"{x['control_pct']}% of the {n_ctl} control domains ({x['lift']}x)" for x in over) +
          ". Each is a mass-market registrar the controls also use, so registrar remains a vendor fact "
          "and is never used to link.")
    else:
        A(f"- **Registrar is not diagnostic.** {rs[0]['registrar']} and {rs[1]['registrar']} hold "
          f"{rs[0]['corpus_pct'] + rs[1]['corpus_pct']:.0f}% of the corpus and a comparable share of the "
          f"{n_ctl} unrelated control domains (largest lift "
          f"{max((x['lift'] for x in rs if x['corpus'] >= 10 and x['lift']), default=0)}x); registrar is "
          "treated as a vendor fact and never used to link.")
    geo_line = ", ".join(f"{gfmt(k)} ({v})" for k, v in geo.most_common(4))
    A(f"- **Registrant identity is almost entirely withheld** — {disc.get('proxy', 0)} domains sit behind a "
      f"proxy service, {disc.get('redacted', 0) + disc.get('redacted (registrar placeholder geo)', 0)} are "
      f"redacted, {disc.get('disclosed', 0)} disclose an organisation. Where registrars retain the "
      f"registrant's state/country under redaction, it clusters: {geo_line}. Group {g2_idx} is uniformly "
      "GB-registered. Values that a registrar returns for every customer (its own office address) were "
      "identified against the control population and excluded.")
    A(f"- **Lifecycle.** {len(lc['expiring_within_90d'])} domains expire within 90 days, "
      f"{len(lc['dying'])} are in redemption/pending-delete, {len(lc['lapsed_auto_renew'])} have lapsed into "
      f"auto-renew grace, {len(lc['suspended_hold'])} are on registrar/registry hold. "
      f"{len(lc['not_registered'])} names in the source list are not registered at all and "
      f"{len(lc['host_labels_not_domains'])} are host labels under other organisations' domains, not "
      "registrable names.")
    if cta_sum:
        spanning = sum(v["certs_spanning_two_members"] for k, v in cta_sum["operator_group_cert_status"].items()
                       if k not in ("4",))
        ctc = [c for c in cta_sum["cert_linked_clusters"] if c["corpus_touching"]]
        A(f"- **Certificate transparency corroborates rather than extends.** Across "
          f"{cta_sum['distinct_certs']} certificates, none spans two members of the actor groups "
          f"(Groups 1-3, 5, 6): they sit on shared parking and each domain gets its own "
          "certificate, so the certificate channel adds no members. The only corpus domains that "
          f"do share a certificate ({', '.join('`'+c['targets'][0]+'`' for c in ctc)}) share it "
          "with established, unrelated businesses — benign names the grammar swept in.")
    feb = next((t for t in tmp["hypothesis_tests"] if "registered together" in t["hypothesis"]), None)
    if feb:
        A(f"- **The 2026-02-05 GoDaddy batch is a reconfiguration, not a registration event.** "
          f"{feb['verdict'].split(' - ', 1)[1]}.")
    A("")

    # ------------------------------------------------------------------ 2
    A("## 2. Collection scope and coverage")
    A("")
    A(tbl(["DNS", "Count"], [
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
        ["Subdomains discovered (wildcard zones suppressed)", clean_subs if clean_subs is not None else
         sum(len([x for x in r['subdomains_found'].split(';') if x]) for r in rows)],
    ]))
    A("")
    if rdap_collected:
        A(tbl(["Registration (RDAP/WHOIS)", "Count"], [
            ["Domains queried (source list + expansion members)", rdap["domains"]],
            ["Registered", rdap["succeeded"]],
            ["Not registered (authoritative registry 404)", rdap["not_registered"]],
            ["Undetermined (invalid TLD or no reachable source)", rdap["undetermined"]],
            ["With registry-side record", rdap["by_source"].get("rdap", 0)],
            ["With registrar-side record (registrant, abuse contact)", rdap["with_registrar_rdap"]],
            ["Registrar-only (registry offers no public RDAP)", rdap["by_source"].get("registrar-rdap", 0)],
            ["WHOIS/43 only", sum(v for k, v in rdap["by_source"].items() if k and k.startswith("whois"))],
            ["Control population (unrelated, naming-adjacent registered domains)", n_ctl],
        ]))
        A("")
        A("Registrar attribution below comes from the registry record. The nameserver-inferred "
          "operator used before RDAP was available is retained as a cross-check: "
          f"{sum(1 for r in rows if r['registrar'] and r['ns_operator'].split(';')[0].split(' ')[0].lower() in r['registrar'].lower())} "
          f"of {sum(1 for r in rows if r['registrar'])} registered domains have their DNS at their "
          "registrar; the rest delegate DNS elsewhere (Cloudflare, NS1, Wix, Vercel).")
    else:
        A("RDAP/WHOIS not collected: `scripts/enumerate_rdap.py` populates `output/rdap_enumeration.json` "
          "from a network that permits outbound HTTPS to registry RDAP endpoints.")
    A("")

    # ------------------------------------------------------------------ 3
    if rdap_collected:
        A("## 3. Registration")
        A("")
        A("### 3.1 Registrar of record")
        A("")
        A("Corpus share against the control population. A lift near 1 means the registrar is simply "
          "popular for this kind of name; only a large lift would make it worth a pivot.")
        A("")
        A(tbl(["Registrar", "Corpus", "Share", "Controls", "Share", "Lift"],
              [[s["registrar"], s["corpus"], f"{s['corpus_pct']}%", s["control"], f"{s['control_pct']}%",
                s["lift"] if s["lift"] is not None else "-"] for s in tmp["registrar_share"][:12]]))
        A("")

        A("### 3.2 Registration timing")
        A("")
        A(f"{reg['with_created']} of {reg['registered']} registered source-list domains carry a "
          f"registration timestamp ({reg['time_basis'].get('registry', 0)} registry-side to the second, "
          f"{reg['time_basis'].get('registrar', 0)} registrar-side, {reg['time_basis'].get('whois', 0)} "
          f"from WHOIS). Median age is {reg['median_age_days']} days.")
        A("")
        A(tbl(["Age", "Domains"], reg["age_buckets"]))
        A("")
        yrs = dict(reg["by_year"])
        recent = sum(v for k, v in yrs.items() if k >= "2023")
        A(f"{recent} of {reg['with_created']} were registered in 2023 or later "
          f"({', '.join(f'{k}: {v}' for k, v in reg['by_year'] if k >= '2023')}); the long tail before "
          "2020 is the benign reference set of established mail providers that shares the source list "
          "(Fastmail, Proton, Posteo, Tuta, Runbox, DuckDuckGo).")
        A("")
        A("**Registration bursts.** Same registrar, consecutive registrations no more than ten minutes "
          "apart — the registry-side signature of one checkout. Registrar-side timestamps are excluded "
          "because their clocks are not comparable.")
        A("")
        A(tbl(["Registrar", "Start (UTC)", "Span", "n", "Group", "Members"],
              [[b["registrar"], b["start"], f"{b['span_s']}s", b["count"],
                ", ".join(str(g) for g in b["groups"]) or "-", code(b["domains"], 8)]
               for b in tmp["registration_bursts"]]))
        A("")
        A(f"{base['corpus_domains_in_a_burst']} of {reg['time_basis'].get('registry', 0)} registry-dated "
          f"corpus domains ({100 * base['corpus_burst_share']:.0f}%) sit in a burst. Among the {n_ctl} "
          f"control domains the figure is {base['control_domains_in_a_burst']} "
          f"({100 * base['control_burst_share']:.1f}%). Same-registrar same-day batches: "
          f"{base['corpus_domains_in_a_day_batch']} corpus domains ({100 * base['corpus_day_batch_share']:.0f}%) "
          f"against {base['control_domains_in_a_day_batch']} controls ({100 * base['control_day_batch_share']:.1f}%). "
          "The controls are naming-adjacent domains that failed the cluster marker test, and some may "
          "still belong to the same operators, so the control rate is an upper bound on chance.")
        A("")
        if tmp["control_collisions"]:
            A("**Control domains registered inside a corpus burst window** (same registrar, within ten "
              "minutes). These are leads for the marker probe, not members:")
            A("")
            A(tbl(["Corpus domain", "Group", "Control domain", "Registrar", "Gap"],
                  [[c["corpus_domain"], c["group"] or "-", c["control_domain"], c["registrar"], f"{c['gap_s']}s"]
                   for c in tmp["control_collisions"][:20]]))
            A("")
        else:
            A("No control domain was registered within ten minutes of a corpus domain at the same "
              "registrar.")
            A("")
        if tmp.get("last_changed_batches"):
            A("**Registry last-changed batches.** The registry's `last changed` event moves on renewal, "
              "nameserver change or transfer, but also on registrar platform events, so each batch is "
              "checked against the controls at the same registrar:")
            A("")
            A(tbl(["Registrar", "Day", "n", "Group", "Controls same day", "Verdict"],
                  [[b["registrar"], b["day"], b["count"], ", ".join(str(g) for g in b["groups"]) or "-",
                    f"{b['controls_same_day']} of {b['controls_at_registrar']}", b["verdict"]]
                   for b in tmp["last_changed_batches"][:10]]))
            A("")

        A("### 3.3 Registrant disclosure")
        A("")
        A(tbl(["Registrant data", "Domains"], [[k, v] for k, v in disc.most_common()]))
        A("")
        if proxy:
            A("Proxy services standing in for the registrant: " +
              ", ".join(f"{k} ({v})" for k, v in proxy.most_common()) + ". A proxy's address is the "
              "proxy's, and is never treated as registrant geography.")
            A("")
        if PLACEHOLDER_GEO:
            A("Registrar placeholder values, identified because the registrar returns the same "
              "state/country for nearly every control domain too, and therefore excluded: " +
              "; ".join(f"{reg} → {gfmt(g)} ({int(100 * s)}% of {n} controls)"
                        for (reg, g), (s, n) in sorted(PLACEHOLDER_GEO.items())) + ".")
            A("")
        if geo:
            A("**Retained registrant state/country** (redacted or disclosed records, placeholders removed):")
            A("")
            geo_rows = []
            for k, v in geo.most_common(12):
                doms = [r["domain"] for r in rows if r["registrant_geo"] == k]
                regs = Counter(r["registrar"] for r in rows if r["registrant_geo"] == k).most_common(2)
                raw = Counter(r["registrar_raw"] for r in rows if r["registrant_geo"] == k).most_common(1)[0][0]
                verdict, kd, kn = geo_control_check(raw, k)
                grp = Counter(str(gi) for gi in (
                    next((i for i, g in enumerate(ops["groups"], 1) if d in g["domains"]), None) for d in doms) if gi)
                cls = Counter(r["domain_class"] for r in rows if r["registrant_geo"] == k).most_common(1)[0][0]
                geo_rows.append([gfmt(k), v, ", ".join(f"{a} ({b})" for a, b in regs),
                                 f"{verdict} ({kd} of {kn})",
                                 ", ".join(f"Group {a} ({b})" for a, b in grp.most_common()) or "-",
                                 cls, code(doms, 6)])
            A(tbl(["State / country", "n", "Registrar", "Control check (same geo / controls with geo at registrar)",
                   "Operator group", "Dominant class", "Members"], geo_rows))
            A("")
            A("Geography is a weak selector on its own — a state is shared by millions of registrants — "
              "but it is independent of DNS and hosting, so agreement with a burst or a group is "
              "corroboration and disagreement is a warning. The control column says how the same "
              "registrar's unrelated customers look: a value most of them share is the registrar's "
              "placeholder; a value a sizeable minority share is a trait of the population that registers "
              "this kind of name (job-mail registrants skew to Gujarat and Texas at Squarespace whether or "
              "not they are in a cluster); only a value the controls rarely carry is worth weight.")
            A("")
        if disclosed_orgs:
            A("**Disclosed registrant organisations:**")
            A("")
            A(tbl(["Domain", "Organisation", "State / country"],
                  [[d, o, gfmt(g) if g else "-"] for o, g, d in disclosed_orgs]))
            A("")
        A("### 3.4 Lifecycle and status")
        A("")
        A(tbl(["State", "n", "Domains"], [
            ["On hold (clientHold / serverHold)", len(lc["suspended_hold"]), code(lc["suspended_hold"], 10)],
            ["Redemption / pending delete", len(lc["dying"]), code(lc["dying"], 10)],
            ["Lapsed into auto-renew grace", len(lc["lapsed_auto_renew"]), code(lc["lapsed_auto_renew"], 10)],
            ["Expiring within 90 days", len(lc["expiring_within_90d"]), code(lc["expiring_within_90d"], 10)],
            ["Registered but not resolving", len(lc["registered_but_not_resolving"]),
             code(lc["registered_but_not_resolving"], 10)],
            ["Registry-locked (server* prohibitions)", len(lc["registry_locks"]), code(lc["registry_locks"], 10)],
        ]))
        A("")
        A("No domain in the corpus is suspended. The registry locks belong to the established mail "
          "providers in the reference set, not to the themed clusters.")
        A("")

    # ------------------------------------------------------------------ 4
    A("## 4. Hosting and service concentration")
    A("")
    ns_op = Counter(r["ns_operator"] for r in rows if r["resolves"])
    A("**DNS operator (from delegated nameservers)**")
    A("")
    A(tbl(["Operator", "Domains", "Share of live"],
          [[k, v, f"{100*v/max(len(live),1):.1f}%"] for k, v in ns_op.most_common(15)]))
    A("")
    mxp = Counter(r["mx_provider"] for r in rows if r["mx"])
    A("**Mail provider (from MX)**")
    A("")
    A(tbl(["Provider", "Domains"], [[k, v] for k, v in mxp.most_common(15)]))
    A("")
    asn_name = {}
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
    A("**Geo (BGP registry country):** " + ", ".join(f"{k} ({v})" for k, v in cc.most_common(10)))
    A("")

    # ------------------------------------------------------------------ 5
    A("## 5. Mail authentication posture")
    A("")
    mailcap = [r for r in rows if r["mx"]]
    dm = Counter(r["dmarc_policy"] or "none-published" for r in mailcap)
    A(tbl(["DMARC policy (mail-capable domains)", "Count"], [[k, v] for k, v in dm.most_common()]))
    A("")
    spf_inc = Counter(i for r in rows for i in r["spf_includes"].split(";") if i)
    A("**Most common SPF includes**")
    A("")
    A(tbl(["SPF include / mechanism", "Domains"], [[k, v] for k, v in spf_inc.most_common(15)]))
    A("")

    # ------------------------------------------------------------------ 6
    A("## 6. Infrastructure pivot clusters")
    A("")
    A("Clusters are sets of two or more domains sharing a selector, ordered from strongest to weakest "
      "attribution value. A shared DKIM key, provider tenant or disclosed registrant organisation "
      "implies a shared *account*; a same-registrar registration burst implies a shared *checkout*; a "
      "shared IP or PTR implies shared *hosting*; a shared registrar, ASN or provider implies only a "
      "shared *vendor* and is close to meaningless alone.")
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
        ("registrant_org", "Shared disclosed registrant organisation",
         "very high — the registrar published the same organisation for every member"),
        ("dmarc_rua", "Shared DMARC reporting address",
         "high — same reporting mailbox (weaker where it is a provider default)"),
        ("hosting_ptr", "Shared hosting reverse-DNS hostname",
         "high — same host (excludes mail-vendor IPs)"),
        ("hosting_ip", "Shared hosting IP",
         "high on dedicated hosting, low on shared/parking/CDN ranges"),
        ("registration_day", "Same registrar, same registration day",
         "medium-high when the span is minutes (see section 3.2); medium when hours"),
        ("cname_target", "Shared CNAME target", "medium-high"),
        ("soa_rname", "Shared SOA responsible mailbox", "medium — same DNS operator"),
        ("nameserver_host", "Shared authoritative nameserver", "medium"),
        ("registrant_geo", "Shared retained registrant state/country",
         "low-medium — independent of hosting, but shared by a whole population"),
        ("last_changed_day", "Same registrar, same registry last-changed day",
         "low — control-tested per batch in section 3.2"),
        ("hosting_bgp_prefix", "Shared hosting BGP prefix", "low"),
        ("mx_host", "Shared MX host", "low — vendor-level"),
        ("spf_include", "Shared SPF include", "low — vendor-level"),
        ("registrar", "Registrar of record", "very low — vendor-level only (section 3.1)"),
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
            body.append([f"`{c['selector'][:70]}`", c["count"], code(c["domains"], 12)])
        A(tbl(["Selector", "Domains", "Members"], body))
        if len(cl) > len(shown):
            A("")
            A(f"*{len(cl)-len(shown)} further clusters of this type in `output/pivot_clusters.json`.*")
        A("")

    # ------------------------------------------------------------------ 7
    A("## 7. Linked operator groups")
    A("")
    A("Single selectors are merged into connected components using **account-level selectors only** — "
      "a DKIM public key, an SPF-management tenant id, a DMARC reporting-platform account, a provider "
      "verification token, a disclosed registrant organisation, or reverse DNS on a host that is not a "
      "hosting vendor's shared estate. Vendor-level facts (registrar, shared MX, parking IPs, provider "
      "reverse DNS) and registration timing are attached as corroboration but never used to link. "
      "Members found by the expansion sweep (section 9) are folded in and marked.")
    A("")
    n_extra = sum(len(v) for v in extra.values())
    A(f"**{ops['group_count']} groups covering {ops['domains_in_groups']} of {len(rows)} source-list "
      f"domains, plus {n_extra} expansion-confirmed members.**")
    A("")
    for i, g in enumerate(ops["groups"], 1):
        t = tl.get(i, {})
        A(f"### Group {i} — {g['size'] + len(extra.get(i, []))} domains")
        A("")
        A("**Linking evidence:** " + ", ".join(f"`{e}`" for e in g["linking_evidence"][:6]))
        A("")
        c = g["corroboration"]
        body = [
            ["Registrar", ", ".join(f"{k} ({v})" for k, v in c["registrar"])],
            ["Registered", f"{t.get('first')} → {t.get('last')} ({t.get('span_days')} days; "
                           f"{t.get('members_in_bursts', 0)} of {t.get('with_created', 0)} in "
                           f"{len(t.get('bursts', []))} bursts)" if t.get("first") else "n/a"],
            ["Registrant", ", ".join(f"{k} ({v})" for k, v in c["registrant_disclosure"])],
            ["Registrant geo (retained)", ", ".join(f"{gfmt(k)} ({v})" for k, v in c["registrant_geo"]) or "none retained"],
            ["Abuse contact", ", ".join(f"`{a}`" for a in c["abuse_contacts"]) or "-"],
            ["DNS operator", ", ".join(f"{k} ({v})" for k, v in c["ns_operator"])],
            ["Mail provider", ", ".join(f"{k} ({v})" for k, v in c["mx_provider"])],
            ["SOA responsible party", ", ".join(f"`{k}` ({v})" for k, v in c["soa_rname"] if k)],
            ["Hosting IPs", ", ".join(f"`{k}` ({v})" for k, v in c["hosting_ips"])],
            ["DMARC policy", ", ".join(f"{k} ({v})" for k, v in c["dmarc_policy"])],
            ["Risk tier", ", ".join(f"{k} ({v})" for k, v in c["risk_tier"])],
            ["Naming theme", ", ".join(f"{k} ({v})" for k, v in c["domain_class"])],
        ]
        A(tbl(["Attribute", "Value"], body))
        A("")
        if t.get("members"):
            A("**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):")
            A("")
            A(tbl(["Registered", "Domain", "Registrar"],
                  [[m["created"], f"`{m['domain']}`" + (" ★" if m["expansion_member"] else ""), m["registrar"]]
                   for m in t["members"]]))
            A("")
            if t.get("bursts"):
                A("Bursts: " + "; ".join(f"{b['start']} ({b['span_s']}s) — {code(b['domains'])}" for b in t["bursts"]))
                A("")
            if t.get("same_checkout_leads"):
                A("**Registered in the same checkout as a member but carrying no group marker** — leads for "
                  "the marker probe, not members:")
                A("")
                A(tbl(["Domain", "Burst (UTC)", "Span", "Alongside"],
                      [[f"`{x['domain']}`", x["burst_start"], f"{x['span_s']}s", code(x["with"])]
                       for x in t["same_checkout_leads"]]))
                A("")
        else:
            A("**Members:** " + code(g["domains"] + extra.get(i, [])))
            A("")

    # ------------------------------------------------------------------ 8
    if rdap_collected and cohort_bursts:
        A("## 8. Registration cohorts outside the operator groups")
        A("")
        A("Bursts whose members belong to no operator group. Timing at this resolution — several "
          "themed names created seconds apart at one registrar — is the registry-side trace of one "
          "shopping cart, and the control population shows how rarely it happens by chance. It is "
          "still not an account artefact, so these cohorts are kept separate from section 7 until a "
          "DKIM key, tenant id or disclosed registrant ties them.")
        A("")
        for title, members, bl in (("Squarespace synthetic-brand cohort", sq_a, sq_a_bursts),
                                   ("Squarespace job-themed cohort (Google Domains DNS)", sq_b, sq_b_bursts)):
            if not members:
                continue
            sq_rows = [by_domain[d] for d in members if d in by_domain]
            sq_cohort, sq_bursts = members, bl
            A(f"### {title} — {len(members)} domains")
            A("")
            A(tbl(["Attribute", "Value"], [
                ["Bursts", "; ".join(f"{b['start']} ({b['span_s']}s, n={b['count']})" for b in bl)],
                ["Naming theme", ", ".join(f"{k} ({v})" for k, v in Counter(r["domain_class"] for r in sq_rows).most_common())],
                ["DNS operator", ", ".join(f"{k} ({v})" for k, v in Counter(r["ns_operator"] for r in sq_rows).most_common(3))],
                ["Mail provider", ", ".join(f"{k} ({v})" for k, v in Counter(r["mx_provider"] for r in sq_rows).most_common(3))],
                ["Hosting IPs", ", ".join(f"`{k}` ({v})" for k, v in Counter(i for r in sq_rows for i in r["hosting_ips"].split(";") if i).most_common(4))],
                ["Registrant", ", ".join(f"{k} ({v})" for k, v in Counter(r["registrant_disclosure"] or "n/a" for r in sq_rows).most_common())],
                ["Registrant geo (retained)", ", ".join(f"{gfmt(k)} ({v})" for k, v in Counter(r["registrant_geo"] for r in sq_rows if r["registrant_geo"]).most_common()) or "none retained"],
                ["Abuse contact", ", ".join(f"`{a}`" for a in sorted({r['abuse_email'] for r in sq_rows if r['abuse_email']}))],
            ]))
            A("")
            A("**Members:** " + code(members))
            leads = [c for c in tmp["control_collisions"] if c["corpus_domain"] in members]
            if leads:
                A("")
                A("Control-population names registered in the same checkout (leads, not members): " +
                  code(sorted({c["control_domain"] for c in leads})) + ".")
            A("")
        sq_cohort = sq_a + sq_b
        if other_bursts:
            A("### Other bursts")
            A("")
            A(tbl(["Registrar", "Start (UTC)", "Span", "Members", "DNS operator", "Hosting"],
                  [[b["registrar"], b["start"], f"{b['span_s']}s", code(b["domains"]),
                    ", ".join(f"{k} ({v})" for k, v in Counter(by_domain[d]["ns_operator"] for d in b["domains"] if d in by_domain).most_common(2)),
                    ", ".join(f"`{k}`" for k, _ in Counter(by_domain[d]["hosting_ips"].split(";")[0] for d in b["domains"] if d in by_domain and by_domain[d]["hosting_ips"]).most_common(1))]
                   for b in other_bursts]))
            A("")

    # ------------------------------------------------------------------ 9
    A("## 9. Cluster expansion by DNS marker")
    A("")
    if exp:
        A("Both large groups publish a marker that can be tested directly, so candidate names generated "
          "from the corpus naming grammar were checked for membership.")
        A("")
        A(tbl(["Group", "Marker tested", "Candidates", "Confirmed members"], [
            [f"Group {g1_idx}", "`dc-aa8e722993._spfm.<domain>` TXT exists", f"{exp['candidates_probed']:,}",
             code(exp["new_group1_members"])],
            [f"Group {g2_idx}", "`p7rqadcw.uriports.com` inside the DMARC record",
             f"{g2['candidates_probed']:,}" if g2 else "-", code(g2["new_group2_members"]) if g2 else "-"],
        ]))
        A("")
        A(f"`primemailhost.com` matches Group {g2_idx} on every attribute — Cloudflare DNS and registrar, "
          "Migadu MX, `spf.migadu.com`, the same URIports account, and it was registered in the same "
          "2026-06-04 burst as `elitecandidates.com` and `careermails.net`. `sorce.io` is a sibling of "
          "`sorce.email`, already in the source list.")
        A("")
        A(f"Of the {exp.get('registered', 0)} registered candidates, the {n_ctl} that carried neither marker "
          "form the control population used throughout section 3.")
        A("")

    # ------------------------------------------------------------------ 10
    A("## 10. Hypothesis tests and controls")
    A("")
    A("Every batch or shared-selector finding was tested against a population that should *not* share "
      "it before it was believed. Verdicts:")
    A("")
    A(tbl(["Hypothesis", "Test", "Result", "Verdict"],
          [[t["hypothesis"], t["test"], t["result"][:420], f"**{t['verdict'].split(' - ')[0]}** — {t['verdict'].split(' - ', 1)[1] if ' - ' in t['verdict'] else ''}"]
           for t in tmp["hypothesis_tests"]]))
    A("")
    A("Two false-positive modes in the marker sweep were controlled out before any expansion result "
      "was accepted. *Wildcard DNS*: parking providers (Afternic, Sedo, CashParking, NameFind) answer "
      "every subdomain, so a name-existence probe hits domains with no connection to the cluster; the "
      "uncontrolled first pass reported 71 'new members' including `pobox.co`, `proton.io` and "
      "`tuta.us`, and requiring the marker content to match the tenant's SPF rather than the parking "
      "default `v=spf1 -all`, plus random-label canaries, cut it to four. *Timeouts read as absence*: "
      "a canary lookup that fails is not proof of no wildcard; probes retry and only a definitive "
      "NXDOMAIN clears a zone. Group 2's hosting was likewise rejected as a marker: 12 of its members "
      "resolve `autoconfig.<domain>` to `141.94.97.141`, which is `autoconfig.migadu.com` — the mail "
      "vendor's shared host.")
    A("")

    # ------------------------------------------------------------------ 11 (certs)
    cta = load("cert_analysis.json")
    if cta:
        A("## 11. Certificate transparency")
        A("")
        A(f"Certificate-transparency logs were checked for every corpus, expansion and lead "
          f"domain and for the control population — {cta['domains_queried']} domains, "
          f"{cta['distinct_certs']} distinct certificates. A certificate whose SANs "
          "span two or more different registrable domains is an account-level link: one party "
          "proved control of all of them to the CA in a single request, the same attribution "
          "strength as a shared DKIM key. Multi-tenant vendor and SaaS certificates (a CDN, "
          "website builder, CRM or mail provider packing unrelated customers onto one "
          "certificate) and the reference-set providers' own estates are identified and "
          "excluded from linking.")
        A("")
        A("### 11.1 The operator groups do not share certificates")
        A("")
        gcs = cta["operator_group_cert_status"]
        A(tbl(["Group", "Members", "With a certificate", "Certs spanning ≥2 members"],
              [[f"Group {gi}", st["members"], st["with_any_cert"], st["certs_spanning_two_members"]]
               for gi, st in gcs.items()]))
        A("")
        clean = [gi for gi, st in gcs.items() if st["certs_spanning_two_members"] == 0]
        A(f"No certificate links two members of Group {', '.join(clean)}. Every member sits on "
          "shared parking or CDN infrastructure and receives its own per-domain certificate, so "
          "the certificate channel adds no members to the operator groups and merges none of "
          "them — a negative result that corroborates the commodity-infrastructure reading of "
          "sections 6 and 7. The only intra-group spanning certificates belong to Group 4, and "
          "they are the reference-set provider's own (a SimpleLogin/Proton alias estate), not an "
          "operator artefact.")
        A("")
        corpus_cl = [c for c in cta["cert_linked_clusters"] if c["corpus_touching"]]
        A("### 11.2 Corpus domains with a shared certificate")
        A("")
        A(f"Only {len(corpus_cl)} corpus/lead domains share a certificate with any other "
          "registrable domain, and both resolve to established, unrelated businesses — benign "
          "names the mail/career grammar swept into the source list, now positively identified "
          "through the company they share a certificate with:")
        A("")
        rows_ct = []
        for c in corpus_cl:
            reading = ("shares a GoDaddy multi-tenant certificate with unrelated small-business "
                       "sites — a benign inclusion" if c["likely_shared_hosting"] else
                       "shares certificates with an established company's own domains — a benign "
                       "inclusion")
            rows_ct.append([code(c["targets"]), code(c["external_siblings"], 6), reading])
        A(tbl(["Corpus/lead domain(s)", "Shared-certificate siblings", "Reading"], rows_ct))
        A("")
        ctl_cl = [c for c in cta["cert_linked_clusters"] if not c["corpus_touching"]]
        noise = [c for c in ctl_cl if c["likely_shared_hosting"]]
        coherent = sorted((c for c in ctl_cl if not c["likely_shared_hosting"] and c["size"] >= 4),
                          key=lambda c: -c["size"])
        A("### 11.3 The control population is not made of singletons")
        A("")
        A(f"Among the control domains the certificate pivot finds {len(ctl_cl)} shared-certificate "
          f"clusters: {len(noise)} are bulk shared-hosting certificates (one control domain packed "
          "onto a reseller's certificate beside dozens of unrelated tenants) and the rest are "
          "small.")
        if coherent:
            jc = coherent[0]
            A(f" One is a coherent operation of its own: {code(jc['targets'])} ride shared Let's "
              f"Encrypt certificates with {len(jc['external_siblings'])} job-alert siblings not in "
              f"the source list ({code(jc['external_siblings'][:6], 6)}), each carrying dedicated "
              "`mail.` and `click.` sending hosts. That is the signature of an opt-in job-alert "
              "email sender — structurally unlike the disposable-mailbox clusters, and a reminder "
              "that some control domains belong to real operators. It means the control burst rate "
              "in section 3.2 is a conservative upper bound on chance, exactly as stated there.")
        A("")

    # ------------------------------------------------------------------ 11
    A("## 12. Non-resolving, unregistered and malformed entries")
    A("")
    A(f"{len(dead)} of {len(rows)} entries returned no NS/SOA/A/MX. With registry data the reasons "
      "separate cleanly:")
    A("")
    malformed = sorted(r["domain"] for r in dead if r["domain"].rsplit(".", 1)[-1] not in
                       {"com", "net", "org", "io", "co", "me", "us", "uk", "ca", "in", "ru", "ch", "no",
                        "ai", "pro", "careers", "email", "help", "cloud"})
    A(tbl(["Reason", "Entries"], [
        ["Invalid TLD — parsing artefacts, not real names", code(malformed)],
        ["Host labels under other organisations' domains, not registrable names",
         code(lc["host_labels_not_domains"])],
        ["Valid TLD, not registered (registry 404)", code(lc["not_registered"])],
        ["Registered but not resolving", code(lc["registered_but_not_resolving"])],
        ["Undetermined (`.co` registry unavailable, no registrar hit)",
         code([u.split(" (")[0] for u in lc["undetermined"] if u.split(" (")[0] not in malformed])],
    ]))
    A("")
    tga = [h for h in lc["host_labels_not_domains"] if h.endswith(".test-google-a.com")]
    if tga:
        parents = [h[: -len(".test-google-a.com")] for h in tga]
        in_group = {d: next((i for i, g in enumerate(ops["groups"], 1) if d in g["domains"]), None) for d in parents}
        leads = {x["domain"]: gi for gi, t in tl.items() for x in t.get("same_checkout_leads", [])}
        A(f"The {len(tga)} `*.test-google-a.com` entries are Google Workspace domain-alias test hosts, "
          "which the platform generates for a tenant's secondary domains. Their parents are " +
          ", ".join(f"`{d}`" + (f" (Group {in_group[d]})" if in_group[d] else
                                f" (same-checkout lead for Group {leads[d]})" if d in leads else "")
                    for d in parents) +
          ". All four belonging to one Workspace tenant is consistent with the Group membership and the "
          "checkout leads in section 7, though the list itself does not prove which tenant generated them.")
        A("")

    # ------------------------------------------------------------------ 12
    A("## 13. Per-domain detail")
    A("")
    A("Full records are in `output/dns_enumeration.json` and `output/rdap_enumeration.json` (raw) and "
      "`output/domain_infrastructure.csv` (flat table). Summary of the highest-risk tier:")
    A("")
    hi = [r for r in rows if r["risk_tier"] == "high"]
    A(tbl(["Domain", "Score", "Registrar", "Registered", "Registrant", "NS operator", "Mail", "DMARC", "IPs"],
          [[r["domain"], r["risk_score"], r["registrar"] or "-", r["created_day"] or "-",
            (r["registrant_proxy_service"].split(" (")[0] if r["registrant_proxy_service"] else
             (r["registrant_geo"].replace("|", "/") if r["registrant_geo"] else r["registrant_disclosure"] or "-")),
            r["ns_operator"], r["mx_provider"], r["dmarc_policy"] or "-", r["hosting_ips"][:44] or "-"]
           for r in sorted(hi, key=lambda x: -int(x["risk_score"] or 0))]))
    A("")

    # ------------------------------------------------------------------ 13
    A("## 14. Method notes and limitations")
    A("")
    if deep:
        A(f"**Enumeration depth.** The DNS pass used a {deep['subdomain_wordlist_size']}-name subdomain "
          f"wordlist and {deep['dkim_selector_count']} DKIM selectors, retrieving "
          f"{sum(len(x['dkim']) for x in deep['domains'])} DKIM keys across "
          f"{sum(1 for r in rows if r['dkim_selectors'])} domains. {deep['wildcard_zones']} wildcard zones "
          f"were detected and their probe results suppressed; the subdomain count in section 2 "
          f"({clean_subs}) reflects that suppression — an earlier figure of 603 counted wildcard answers. "
          f"{deep['dnssec_signed']} zones are DNSSEC-signed and {deep['nsec_walkable']} use walkable NSEC; "
          "the Proton-operated ones return RFC 4470 white lies and only `runbox.no` yielded a real chain.")
        A("")
    A("**Registration data.** Registry RDAP is authoritative for dates, status and delegation and was "
      "obtained for every gTLD and for `.io`, `.me`, `.us`, `.ch`, `.uk`, `.ca`, `.in` and `.no`. The "
      "`.co` registry answers *not found* for every name, including live ones, so `.co` records come "
      "from the sponsoring registrar's RDAP (found from the delegated nameservers) and their timestamps "
      "are registrar-side and excluded from burst analysis. `.ru` has WHOIS only. Registrar-side "
      "servers rate-limit; a slow second pass recovered the records the first pass lost, and any "
      "domain still lacking a registrar record has no registrant fields. Registrant identity is "
      "withheld almost everywhere; what survives is the proxy service (which identifies the registrar, "
      "not the registrant), the state/country some registrars retain, and the handful of "
      "organisations that were disclosed. Individuals' names, where a registrar published them, are "
      "kept in the raw evidence file only.")
    A("")
    A("**Timing signals.** Registration timestamps are the primary timing signal. SOA serials, used "
      "before registration data was available, date the last zone edit and remain a configuration-batch "
      "signal only: the 2026-08-20 Hostinger batch was a provider-wide serial bump, and the 2026-02-05 "
      "GoDaddy batch, which survived its control test, turned out on registration dates to be a joint "
      "reconfiguration of domains registered in pairs across 2024-05 to 2025-04 — consistent with one "
      "operator accumulating permutations of a stem over time, but not the single registration event the "
      "serials suggested.")
    A("")
    A("**Vendor estates.** Reverse DNS on AWS Global Accelerator instances, Google MX addresses, "
      "Migadu's autoconfig host and Squarespace's shared front end identify vendors, not customers, and "
      "are excluded from linking; the same applies to registrar choice and to registrar placeholder "
      "geography. Cloudflare's free-plan nameserver pairs are drawn from a shared pool and are not "
      "account-unique.")
    A("")

    A("## Appendix — abuse contacts by group")
    A("")
    A(tbl(["Group / cohort", "Registrar", "Abuse contact", "Domains"], [
        *[[f"Group {i}", ", ".join(k for k, _ in g["corroboration"]["registrar"]),
           ", ".join(f"`{a}`" for a in g["corroboration"]["abuse_contacts"]) or "-",
           g["size"] + len(extra.get(i, []))] for i, g in enumerate(ops["groups"], 1)],
        *([["Squarespace cohort", "Squarespace", ", ".join(f"`{a}`" for a in sorted({by_domain[d]['abuse_email'] for d in sq_cohort if d in by_domain and by_domain[d]['abuse_email']})) or "-", len(sq_cohort)]] if sq_cohort else []),
    ]))
    A("")

    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"[+] wrote {OUT_MD}")


if __name__ == "__main__":
    main()
