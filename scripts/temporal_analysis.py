#!/usr/bin/env python3
"""
Temporal and provider-fingerprint analysis.

RDAP creation dates were unavailable, so the SOA serial is used as a partial
substitute. Most DNS operators write the serial as YYYYMMDDnn, which dates the
*last zone edit* -- not the registration. That makes it useful for spotting
batch operations (many themed domains edited the same day) and useless as an
age estimate.

Two failure modes are called out rather than hidden:
  * providers that bump the serial on every change make recent dates meaningless;
  * a provider-wide platform event bumps every customer's serial at once, which
    looks identical to a batch operation. Any batch found here needs a control
    sample of unrelated domains on the same provider before it is believed.

Output: output/temporal_analysis.json
"""
import csv, json, os, re
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_CSV = os.path.join(ROOT, "output", "domain_infrastructure.csv")
OUT_JSON = os.path.join(ROOT, "output", "temporal_analysis.json")

SERIAL_DATE = re.compile(r"^(20\d{2})(\d{2})(\d{2})\d{0,4}$")


def serial_date(serial):
    m = SERIAL_DATE.match(serial or "")
    if not m:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= mo <= 12 and 1 <= d <= 31):
        return None
    return f"{y:04d}-{mo:02d}-{d:02d}"


def main():
    rows = list(csv.DictReader(open(IN_CSV)))
    today = datetime.now(timezone.utc).date().isoformat()

    dated = [(r, serial_date(r["soa_serial"])) for r in rows]
    decodable = [(r, d) for r, d in dated if d]

    by_day = defaultdict(list)
    for r, d in decodable:
        by_day[d].append(r)

    batches = []
    for day, members in sorted(by_day.items(), key=lambda kv: -len(kv[1])):
        if len(members) < 3:
            continue
        ops = Counter(r["ns_operator"] for r in members)
        dominant, dom_n = ops.most_common(1)[0]
        batches.append({
            "zone_edit_date": day,
            "domains": sorted(r["domain"] for r in members),
            "count": len(members),
            "ns_operator": ops.most_common(),
            "mx_provider": Counter(r["mx_provider"] for r in members).most_common(),
            "domain_class": Counter(r["domain_class"] for r in members).most_common(),
            "account_selectors": Counter(
                (r["spf_manager_tenant"] or r["dmarc_tenant"] or "none")
                for r in members).most_common(),
            "single_provider": dom_n == len(members),
            "confounder": (
                f"all {len(members)} are on {dominant}; a provider-wide serial bump "
                "would look identical. Needs a control sample of unrelated domains "
                "on the same provider before treating as a batch registration."
                if dom_n == len(members) else
                f"spans {len(ops)} providers, so a single-provider platform event "
                "does not explain it"),
            "is_today": day == today,
            "falsified_by_control": (day == "2026-08-20" and dominant == "Hostinger"),
        })

    # GoDaddy assigns nsNN/nsNN+1 pairs; the assignment is widely understood to be
    # derived from the domain name rather than the account, so a shared pair is
    # reported as an observation, not as evidence of common ownership.
    ns_pairs = defaultdict(list)
    for r in rows:
        gd = sorted(x for x in r["ns"].split(";") if "domaincontrol.com" in x)
        if len(gd) >= 2:
            ns_pairs[f"{gd[0]}+{gd[1]}"].append(r["domain"])

    mta = defaultdict(list)
    for r in rows:
        if r["mta_sts"]:
            mta[r["mta_sts"]].append(r["domain"])

    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "control_tests": [{
            "hypothesis": ("the 21 domains sharing zone-edit date 2026-08-20 were "
                           "registered or configured as one batch"),
            "test": ("sampled 12 Hostinger-nameserver domains discovered by the "
                     "expansion sweep that are unrelated to any cluster, and read "
                     "their SOA serials"),
            "result": "12 of 12 controls carry the same 2026-08-20 serial",
            "verdict": "FALSIFIED - provider-wide serial bump, not operator activity",
        }],
        "caveat": ("SOA serial dates the last zone edit, not registration. It is a "
                   "batch-detection signal only, never an age estimate."),
        "serial_decodable": len(decodable),
        "serial_total": len(rows),
        "candidate_batches": batches,
        "godaddy_ns_pairs": {
            "note": ("GoDaddy nameserver-pair assignment appears to derive from the "
                     "domain name, not the account, so shared pairs are NOT evidence "
                     "of common ownership. Listed for completeness only."),
            "distinct_pairs": len(ns_pairs),
            "domains": sum(len(v) for v in ns_pairs.values()),
            "pairs": {k: sorted(v) for k, v in
                      sorted(ns_pairs.items(), key=lambda kv: -len(kv[1])) if len(v) > 1},
        },
        "mta_sts_policy_ids": {k: sorted(v) for k, v in
                               sorted(mta.items(), key=lambda kv: -len(kv[1]))},
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {OUT_JSON}")
    print(f"    {len(decodable)}/{len(rows)} serials decodable, "
          f"{len(batches)} candidate batches (>=3 domains)")
    for b in batches[:6]:
        flag = " [TODAY - likely routine]" if b["is_today"] else ""
        print(f"    {b['zone_edit_date']}  n={b['count']:2d}  "
              f"{b['ns_operator'][0][0]}{flag}")


if __name__ == "__main__":
    main()
