#!/usr/bin/env python3
"""
Registration-timing and lifecycle analysis.

Primary signal: RDAP registration timestamps. Two derived structures matter:

  * same-registrar, same-day *batches* -- several themed domains registered on
    one day at one registrar;
  * same-registrar *bursts* -- registrations at the same registrar within ten
    minutes of one another, which is what one shopping cart looks like at the
    registry (timestamps are registry-side and to the second).

Neither is proof of common control on its own. Both are measured against the
control population (registered, naming-adjacent domains from the expansion sweep
that matched no cluster marker) so that a base rate is stated next to every
figure, and any control domain that lands inside a corpus burst window is
reported as a lead, never as a member.

Secondary signal: SOA serials, which most operators write as YYYYMMDDnn. They
date the last zone edit, never registration, so they only detect configuration
batches and only after a control sample on the same provider. The two control
tests run on that signal are kept here alongside the registration results.

Output: output/temporal_analysis.json
"""
import csv, json, os, re
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")
IN_CSV = os.path.join(OUT, "domain_infrastructure.csv")
OUT_JSON = os.path.join(OUT, "temporal_analysis.json")

BURST_GAP_S = 600
SERIAL_DATE = re.compile(r"^(20\d{2})(\d{2})(\d{2})\d{0,4}$")


def load(name):
    p = os.path.join(OUT, name)
    return json.load(open(p)) if os.path.exists(p) else None


def serial_date(serial):
    m = SERIAL_DATE.match(serial or "")
    if not m:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= mo <= 12 and 1 <= d <= 31):
        return None
    return f"{y:04d}-{mo:02d}-{d:02d}"


def ts(s):
    """ISO timestamp -> epoch seconds (None if absent/unparseable)."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s[:19]).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def registrar_label(name):
    # keep in step with analyze_infra.registrar_label without importing (controls
    # are raw RDAP records, not flat rows)
    from analyze_infra import registrar_label as rl  # noqa: E402
    return rl(name)


def reg_points(records, label_fn):
    """(domain, registrar_label, created_epoch, created_day, time_basis) per record."""
    pts = []
    for r in records:
        m = r.get("rdap") or {}
        if not r.get("ok") or not m.get("created"):
            continue
        pts.append({"domain": r["domain"], "registrar": label_fn(m.get("registrar")),
                    "t": ts(m["created"]), "day": m["created"][:10],
                    "basis": m.get("time_basis") or "registry"})
    return [p for p in pts if p["t"] is not None]


def bursts(points, gap=BURST_GAP_S):
    """Chains of same-registrar registrations with consecutive gaps <= gap seconds.
    Registry-basis timestamps only: registrar-side clocks are not comparable."""
    by_reg = defaultdict(list)
    for p in points:
        if p["basis"] == "registry":
            by_reg[p["registrar"]].append(p)
    out = []
    for reg, pts in by_reg.items():
        pts.sort(key=lambda p: p["t"])
        chain = [pts[0]] if pts else []
        for prev, cur in zip(pts, pts[1:]):
            if cur["t"] - prev["t"] <= gap:
                chain.append(cur)
            else:
                if len(chain) > 1:
                    out.append(chain)
                chain = [cur]
        if len(chain) > 1:
            out.append(chain)
    res = []
    for chain in out:
        res.append({"registrar": chain[0]["registrar"],
                    "start": datetime.fromtimestamp(chain[0]["t"], timezone.utc).isoformat()[:19] + "Z",
                    "span_s": int(chain[-1]["t"] - chain[0]["t"]),
                    "count": len(chain),
                    "domains": [c["domain"] for c in chain]})
    return sorted(res, key=lambda b: (-b["count"], b["start"]))


def day_batches(points):
    b = defaultdict(list)
    for p in points:
        b[(p["registrar"], p["day"])].append(p)
    out = []
    for (reg, day), pts in b.items():
        if len(pts) < 2:
            continue
        pts.sort(key=lambda p: p["t"])
        out.append({"registrar": reg, "day": day, "count": len(pts),
                    "span_s": int(pts[-1]["t"] - pts[0]["t"]),
                    "domains": [p["domain"] for p in pts]})
    return sorted(out, key=lambda x: (-x["count"], x["day"]))


def main():
    rows = list(csv.DictReader(open(IN_CSV, encoding="utf-8")))
    by_dom = {r["domain"]: r for r in rows}
    rdap = load("rdap_enumeration.json") or {"records": []}
    controls = load("rdap_controls.json") or {"records": []}
    ops = load("operator_clusters.json") or {"groups": []}
    exp = load("cluster_expansion.json") or {}
    g2 = load("group2_expansion.json") or {}
    today = datetime.now(timezone.utc)

    from analyze_infra import registrar_label as rl  # noqa: E402

    corpus_recs = [r for r in rdap["records"] if r.get("source_list") == "corpus"]
    disc_recs = [r for r in rdap["records"] if r.get("source_list") == "discovered"]
    corpus_pts = reg_points(corpus_recs, rl)
    all_pts = reg_points(rdap["records"], rl)
    ctl_pts = reg_points(controls["records"], rl)
    pt_by_dom = {p["domain"]: p for p in all_pts}

    # ---- group membership (source list + expansion-confirmed members) ----
    group_of = {}
    group_names = {}
    for i, g in enumerate(ops["groups"], 1):
        group_names[i] = g["linking_evidence"][0] if g["linking_evidence"] else f"group{i}"
        for d in g["domains"]:
            group_of[d] = i
    evid_to_idx = {}
    for i, g in enumerate(ops["groups"], 1):
        for e in g["linking_evidence"]:
            evid_to_idx[e] = i
    for d in exp.get("new_group1_members", []):
        group_of[d] = evid_to_idx.get("spfm:aa8e722993", 1)
    for d in (g2 or {}).get("new_group2_members", []):
        group_of[d] = evid_to_idx.get("uriports:p7rqadcw", 2)

    # ---- registration coverage / age ----
    ages = [(today - datetime.fromtimestamp(p["t"], timezone.utc)).days for p in corpus_pts]
    buckets = Counter()
    for a in ages:
        buckets["< 90 days" if a < 90 else "90 days - 1 year" if a < 365 else
                "1 - 2 years" if a < 730 else "2 - 5 years" if a < 1826 else "> 5 years"] += 1
    by_year = Counter(p["day"][:4] for p in corpus_pts)
    by_month = Counter(p["day"][:7] for p in corpus_pts if p["day"] >= "2023")
    registration = {
        "corpus_domains": len(corpus_recs),
        "registered": sum(1 for r in corpus_recs if r.get("registered")),
        "not_registered": sum(1 for r in corpus_recs if r.get("registered") is False),
        "undetermined": sum(1 for r in corpus_recs if r.get("registered") is None),
        "with_created": len(corpus_pts),
        "time_basis": dict(Counter(p["basis"] for p in corpus_pts)),
        "age_buckets": [[k, buckets[k]] for k in ("< 90 days", "90 days - 1 year", "1 - 2 years",
                                                  "2 - 5 years", "> 5 years")],
        "by_year": sorted(by_year.items()),
        "by_month_since_2023": sorted(by_month.items()),
        "median_age_days": sorted(ages)[len(ages) // 2] if ages else None,
    }

    # ---- registrar share: corpus vs controls ----
    c_reg = Counter(p["registrar"] for p in corpus_pts)
    k_reg = Counter(p["registrar"] for p in ctl_pts)
    share = []
    for reg in sorted(set(c_reg) | set(k_reg), key=lambda r: -c_reg[r]):
        cp = c_reg[reg] / max(len(corpus_pts), 1)
        kp = k_reg[reg] / max(len(ctl_pts), 1)
        share.append({"registrar": reg, "corpus": c_reg[reg], "corpus_pct": round(100 * cp, 1),
                      "control": k_reg[reg], "control_pct": round(100 * kp, 1),
                      "lift": round(cp / kp, 2) if kp else None})

    # ---- batches and bursts, with control base rates ----
    corpus_bursts = bursts(all_pts)
    corpus_batches = day_batches(all_pts)
    ctl_bursts = bursts(ctl_pts)
    ctl_batches = day_batches(ctl_pts)
    for b in corpus_bursts + corpus_batches:
        b["groups"] = sorted({group_of[d] for d in b["domains"] if d in group_of})
        b["classes"] = Counter(by_dom[d]["domain_class"] for d in b["domains"]
                               if d in by_dom).most_common(3)
    in_burst = {d for b in corpus_bursts for d in b["domains"]}
    in_batch = {d for b in corpus_batches for d in b["domains"]}
    ctl_in_burst = {d for b in ctl_bursts for d in b["domains"]}
    ctl_in_batch = {d for b in ctl_batches for d in b["domains"]}
    registry_pts = [p for p in all_pts if p["basis"] == "registry"]
    ctl_registry_pts = [p for p in ctl_pts if p["basis"] == "registry"]
    base_rates = {
        "corpus_domains_in_a_burst": len(in_burst),
        "corpus_burst_share": round(len(in_burst) / max(len(registry_pts), 1), 3),
        "control_domains_in_a_burst": len(ctl_in_burst),
        "control_burst_share": round(len(ctl_in_burst) / max(len(ctl_registry_pts), 1), 3),
        "corpus_domains_in_a_day_batch": len(in_batch),
        "corpus_day_batch_share": round(len(in_batch) / max(len(all_pts), 1), 3),
        "control_domains_in_a_day_batch": len(ctl_in_batch),
        "control_day_batch_share": round(len(ctl_in_batch) / max(len(ctl_pts), 1), 3),
        "note": ("controls are naming-adjacent registered domains that failed the cluster "
                 "marker test; some may still belong to the same operators, so the control "
                 "rates are an upper bound on chance co-registration"),
    }

    # registry "last changed" day batches: renewals, NS changes and transfers land here,
    # but so do registrar platform events. Each corpus batch is checked against the
    # share of controls at the same registrar carrying the same day.
    def lc_points(records):
        out = []
        for r in records:
            m = r.get("rdap") or {}
            if r.get("ok") and m.get("last_changed"):
                out.append((r["domain"], rl(m.get("registrar")), m["last_changed"][:10]))
        return out
    c_lc, k_lc = lc_points(rdap["records"]), lc_points(controls["records"])
    k_lc_by_reg = defaultdict(Counter)
    k_lc_n = Counter()
    for _, reg, day in k_lc:
        k_lc_by_reg[reg][day] += 1
        k_lc_n[reg] += 1
    lc_b = defaultdict(list)
    for d, reg, day in c_lc:
        lc_b[(reg, day)].append(d)
    last_changed_batches = []
    for (reg, day), doms in sorted(lc_b.items(), key=lambda kv: -len(kv[1])):
        if len(doms) < 3:
            continue
        kn, kd = k_lc_n[reg], k_lc_by_reg[reg][day]
        share_k = kd / kn if kn else None
        last_changed_batches.append({
            "registrar": reg, "day": day, "count": len(doms), "domains": sorted(doms),
            "groups": sorted({group_of[x] for x in doms if x in group_of}),
            "controls_same_day": kd, "controls_at_registrar": kn,
            "control_share": round(share_k, 3) if share_k is not None else None,
            "verdict": ("provider-wide event (controls share it)" if share_k and share_k >= 0.2
                        else "no control sample at this registrar" if not kn
                        else f"also seen in {kd} controls — weak" if kd >= 2
                        else "operator-specific (controls do not share it)"),
        })

    # controls that fall inside a corpus burst window at the same registrar: leads only
    collisions = []
    ctl_by_reg = defaultdict(list)
    for p in ctl_registry_pts:
        ctl_by_reg[p["registrar"]].append(p)
    for p in registry_pts:
        for q in ctl_by_reg.get(p["registrar"], []):
            gap = abs(q["t"] - p["t"])
            if gap <= BURST_GAP_S:
                collisions.append({"corpus_domain": p["domain"], "group": group_of.get(p["domain"]),
                                   "control_domain": q["domain"], "registrar": p["registrar"],
                                   "gap_s": int(gap)})
    collisions.sort(key=lambda c: (c["gap_s"], c["corpus_domain"]))

    # domains registered in the same checkout as a group member but carrying no
    # group marker: leads for the marker probe, never members
    leads_by_group = defaultdict(list)
    for b in corpus_bursts:
        if not b["groups"]:
            continue
        for d in b["domains"]:
            if d not in group_of:
                for gi in b["groups"]:
                    leads_by_group[gi].append({
                        "domain": d, "burst_start": b["start"], "span_s": b["span_s"],
                        "with": [x for x in b["domains"] if group_of.get(x) == gi]})

    # ---- group timelines ----
    timelines = []
    for i, g in enumerate(ops["groups"], 1):
        members = sorted(set(g["domains"]) | {d for d, gi in group_of.items() if gi == i})
        pts = [pt_by_dom[d] for d in members if d in pt_by_dom]
        pts.sort(key=lambda p: p["t"])
        gb = bursts(pts)
        gbatches = day_batches(pts)
        regs = Counter(p["registrar"] for p in pts)
        timelines.append({
            "same_checkout_leads": sorted(leads_by_group.get(i, []), key=lambda x: x["burst_start"]),
            "group": i, "linking_evidence": g["linking_evidence"][:3], "size": len(members),
            "with_created": len(pts),
            "first": pts[0]["day"] if pts else None, "last": pts[-1]["day"] if pts else None,
            "span_days": int((pts[-1]["t"] - pts[0]["t"]) / 86400) if len(pts) > 1 else 0,
            "registrars": regs.most_common(),
            "members_in_bursts": sum(b["count"] for b in gb),
            "bursts": gb, "day_batches": gbatches,
            "members": [{"domain": p["domain"], "created": p["day"], "registrar": p["registrar"],
                         "expansion_member": p["domain"] not in set(g["domains"])} for p in pts],
        })

    # ---- lifecycle / status ----
    def st(r):
        return set(((r.get("rdap") or {}).get("status")) or [])
    lifecycle = {
        "suspended_hold": sorted(r["domain"] for r in rdap["records"]
                                 if st(r) & {"clientHold", "serverHold"}),
        "dying": sorted(f"{r['domain']} ({','.join(sorted(st(r) & {'pendingDelete', 'redemptionPeriod'}))})"
                        for r in rdap["records"] if st(r) & {"pendingDelete", "redemptionPeriod"}),
        "lapsed_auto_renew": sorted(r["domain"] for r in rdap["records"] if "autoRenewPeriod" in st(r)),
        "expiring_within_90d": sorted(
            f"{r['domain']} ({(r['rdap'].get('expires') or '')[:10]})" for r in rdap["records"]
            if r.get("ok") and ts(r["rdap"].get("expires")) and
            0 <= (ts(r["rdap"]["expires"]) - today.timestamp()) / 86400 <= 90),
        "already_expired": sorted(
            f"{r['domain']} ({(r['rdap'].get('expires') or '')[:10]})" for r in rdap["records"]
            if r.get("ok") and ts(r["rdap"].get("expires")) and
            ts(r["rdap"]["expires"]) < today.timestamp()),
        "registered_but_not_resolving": sorted(
            r["domain"] for r in corpus_recs if r.get("registered") and
            by_dom.get(r["domain"], {}).get("resolves", "True") == "False"),
        "not_registered": sorted(r["domain"] for r in corpus_recs if r.get("registered") is False
                                 and r["domain"].count(".") == 1),
        "host_labels_not_domains": sorted(r["domain"] for r in corpus_recs
                                          if r.get("registered") is False and r["domain"].count(".") > 1),
        "undetermined": sorted(f"{r['domain']} ({'; '.join(r['errors'][-1:])})"
                               for r in corpus_recs if r.get("registered") is None),
        "registry_locks": sorted(r["domain"] for r in rdap["records"]
                                 if st(r) & {"serverDeleteProhibited", "serverTransferProhibited",
                                             "serverUpdateProhibited"}),
    }

    # ---- SOA serial analysis (secondary signal, unchanged method) ----
    dated = [(r, serial_date(r["soa_serial"])) for r in rows]
    decodable = [(r, d) for r, d in dated if d]
    by_day = defaultdict(list)
    for r, d in decodable:
        by_day[d].append(r)
    soa_batches = []
    for day, members in sorted(by_day.items(), key=lambda kv: -len(kv[1])):
        if len(members) < 3:
            continue
        opsc = Counter(r["ns_operator"] for r in members)
        dominant, dom_n = opsc.most_common(1)[0]
        soa_batches.append({
            "zone_edit_date": day, "domains": sorted(r["domain"] for r in members),
            "count": len(members), "ns_operator": opsc.most_common(),
            "single_provider": dom_n == len(members),
            "falsified_by_control": (day == "2026-08-20" and dominant == "Hostinger"),
            "confirmed_by_control": (day == "2026-02-05" and dominant == "GoDaddy"),
        })
    soa_tests = [{
        "hypothesis": ("the 21 domains sharing zone-edit date 2026-08-20 were registered or "
                       "configured as one batch"),
        "test": ("sampled 12 Hostinger-nameserver domains discovered by the expansion sweep "
                 "that are unrelated to any cluster, and read their SOA serials"),
        "result": "12 of 12 controls carry the same 2026-08-20 serial",
        "verdict": "FALSIFIED - provider-wide serial bump, not operator activity",
    }, {
        "hypothesis": ("the 8 GoDaddy domains sharing zone-edit date 2026-02-05 were "
                       "configured as one batch"),
        "test": ("sampled 79 GoDaddy-nameserver domains discovered by the expansion sweep "
                 "that belong to no cluster, and read their SOA serials"),
        "result": ("0 of 79 controls carry the 2026-02-05 serial; control dates are widely "
                   "dispersed (most common is 2023-09-19 at 8 of 79)"),
        "verdict": ("SURVIVES - 2026-02-05 is not a GoDaddy-wide event, so the 8 domains "
                    "share a genuine same-day configuration event"),
    }]

    # ---- hypothesis tests on the registration data ----
    tests = list(soa_tests)
    feb = next((b for b in soa_batches if b["confirmed_by_control"]), None)
    if feb:
        created = sorted((pt_by_dom[d]["day"], d) for d in feb["domains"] if d in pt_by_dom)
        days = Counter(c for c, _ in created)
        same = days.most_common(1)[0] if days else (None, 0)
        detail = ", ".join(f"`{d}` {c}" for c, d in created)
        if same[1] == len(feb["domains"]):
            verdict = (f"CONFIRMED - all {len(feb['domains'])} were registered on {same[0]}; the "
                       "zone-edit date is the registration date")
        elif same[1] >= 2:
            verdict = (f"PARTIAL - {same[1]} of {len(feb['domains'])} registered on {same[0]}; "
                       "the rest were registered on other days and only reconfigured together "
                       "on 2026-02-05")
        else:
            verdict = ("REFUTED - registration dates are dispersed; 2026-02-05 was a joint "
                       "reconfiguration, not a joint registration")
        tests.append({
            "hypothesis": ("the 8 GoDaddy domains that share zone-edit date 2026-02-05 were "
                           "registered together"),
            "test": "read the RDAP registration date of each member",
            "result": f"registration dates: {detail}",
            "verdict": verdict,
        })

    for tl in timelines[:2]:
        n, k = tl["with_created"], tl["members_in_bursts"]
        share_g = k / n if n else 0
        tests.append({
            "hypothesis": (f"Group {tl['group']} members were registered in bursts "
                           f"(same registrar, <= {BURST_GAP_S // 60} min apart)"),
            "test": ("chain each member's registry registration timestamp with the group's "
                     "other members at the same registrar; compare with the control-population "
                     "burst share"),
            "result": (f"{k} of {n} members sit in {len(tl['bursts'])} intra-group burst(s); "
                       f"control-population burst share is "
                       f"{100 * base_rates['control_burst_share']:.1f}%"),
            "verdict": (f"{'SUPPORTED' if share_g > 2 * base_rates['control_burst_share'] and k >= 4 else 'NOT SUPPORTED'}"
                        f" - {100 * share_g:.0f}% of the group vs "
                        f"{100 * base_rates['control_burst_share']:.1f}% baseline"),
        })

    big = [s for s in share if s["corpus"] >= 10 and s["lift"] is not None]
    over = [s for s in big if s["lift"] >= 3]
    if not ctl_pts:
        reg_verdict = "UNTESTED - no control population collected"
    elif over:
        reg_verdict = ("PARTIAL - " + ", ".join(f"{s['registrar']} is {s['lift']}x over-represented"
                                                 for s in over) +
                       "; still a mass-market registrar shared with the controls, so vendor-level "
                       "and not used for linking")
    else:
        reg_verdict = ("NOT SUPPORTED - the same mass-market registrars dominate both populations "
                       f"(largest lift {max((s['lift'] for s in big), default=0)}x); registrar is a "
                       "vendor-level fact and is not used for linking")
    tests.append({
        "hypothesis": "registrar choice alone separates the corpus from unrelated themed domains",
        "test": "registrar share of the corpus against the control population",
        "result": "; ".join(f"{s['registrar']} {s['corpus_pct']}% vs {s['control_pct']}% "
                            f"(lift {s['lift']})" for s in share[:5]),
        "verdict": reg_verdict,
    })

    out = {
        "generated_utc": today.isoformat(),
        "burst_gap_seconds": BURST_GAP_S,
        "registration": registration,
        "registrar_share": share,
        "registration_bursts": corpus_bursts,
        "registration_day_batches": corpus_batches,
        "last_changed_batches": last_changed_batches,
        "base_rates": base_rates,
        "control_collisions": collisions,
        "group_timelines": timelines,
        "lifecycle": lifecycle,
        "hypothesis_tests": tests,
        "soa_serial": {
            "caveat": ("SOA serial dates the last zone edit, not registration. It is a "
                       "batch-detection signal only, never an age estimate."),
            "serial_decodable": len(decodable),
            "serial_total": len(rows),
            "candidate_batches": soa_batches,
        },
        "control_tests": soa_tests,     # kept under the old key for the report builder
        "candidate_batches": soa_batches,
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}")
    print(f"    {len(corpus_pts)}/{len(corpus_recs)} corpus domains dated; "
          f"{len(corpus_bursts)} bursts ({len(in_burst)} domains), "
          f"{len(corpus_batches)} day-batches; control burst share "
          f"{100 * base_rates['control_burst_share']:.1f}%; {len(collisions)} control collisions")
    for t in tests[2:]:
        print(f"    {t['verdict'][:110]}")


if __name__ == "__main__":
    main()
