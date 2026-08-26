#!/usr/bin/env python3
"""
Certificate-transparency enumeration for the CTI domain set via crt.sh.

For every corpus, expansion-confirmed and lead domain (the control population is
skipped by default to bound the request count), fetch the CT-logged certificates
for the apex and for `%.<domain>` from crt.sh. The value is the SAN list: a single
certificate whose SANs span two or more *different* registrable domains is an
account-level link, because one party proved control of all of them to the CA in
one request -- the same attribution strength as a shared DKIM key.

crt.sh is a public CT aggregate; querying it reveals only that these domains were
looked up, and it returns historical certificates that a live DNS probe cannot
(expired, or for hosts no longer resolving). It rate-limits and drip-feeds under
load, so requests carry a wall-clock deadline and back off on failure.

Output: output/cert_enumeration.json

Usage:
  enumerate_certs.py                     # corpus + expansion + leads
  enumerate_certs.py --include-controls  # add the control population
  enumerate_certs.py --domains-file x.txt
"""
import csv, json, os, sys, time, argparse
import urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_CSV = os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv")
IN_DISCOVERED = os.path.join(ROOT, "data", "Discovered_Domains.csv")
IN_EXPANSION = os.path.join(ROOT, "output", "cluster_expansion.json")
IN_TEMPORAL = os.path.join(ROOT, "output", "temporal_analysis.json")
IN_CONTROLS = os.path.join(ROOT, "output", "rdap_controls.json")
OUT_JSON = os.path.join(ROOT, "output", "cert_enumeration.json")
UA = "Mozilla/5.0 (compatible; cert-enum/1.0)"


def crtsh(query, timeout=45, tries=3):
    url = f"https://crt.sh/?q={query}&output=json"
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                       "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace").strip()
            if not body:
                return [], None
            j = json.loads(body)
            return (j if isinstance(j, list) else []), None
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in (429, 500, 502, 503, 504) and attempt < tries - 1:
                time.sleep(6 * (attempt + 1))
                continue
            return None, last
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"[:100]
            if attempt < tries - 1:
                time.sleep(5 * (attempt + 1))
                continue
    return None, last


def slim(rec):
    """Keep the fields that matter; crt.sh name_value is newline-separated SANs."""
    return {"issuer": rec.get("issuer_name", ""), "common_name": rec.get("common_name"),
            "sans": sorted({s.strip().lower() for s in (rec.get("name_value") or "").split("\n") if s.strip()}),
            "not_before": rec.get("not_before"), "not_after": rec.get("not_after"),
            "entry_timestamp": rec.get("entry_timestamp"), "serial": rec.get("serial_number"),
            "crtsh_id": rec.get("id")}


def load_targets(include_controls):
    seen, items = set(), []

    def add(d, s):
        d = d.strip().lower()
        if d and d not in seen and d.count(".") >= 1 and not d.endswith(".test-google-a.com"):
            seen.add(d)
            items.append((d, s))

    for path, s in ((IN_CSV, "corpus"), (IN_DISCOVERED, "discovered")):
        if os.path.exists(path):
            for row in csv.DictReader(open(path)):
                add(row["Domain"], s)
    if os.path.exists(IN_TEMPORAL):
        tmp = json.load(open(IN_TEMPORAL))
        for tl in tmp.get("group_timelines", []):
            for x in tl.get("same_checkout_leads", []):
                add(x["domain"], "lead")
        for c in tmp.get("control_collisions", []):
            add(c["control_domain"], "lead")
    if include_controls and os.path.exists(IN_CONTROLS):
        for r in json.load(open(IN_CONTROLS)).get("records", []):
            add(r["domain"], "control")
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-controls", action="store_true")
    ap.add_argument("--domains-file")
    ap.add_argument("--targets-csv", help="CSV with domain,set columns")
    ap.add_argument("--out", default=OUT_JSON)
    ap.add_argument("--pause", type=float, default=1.5)
    args = ap.parse_args()

    if args.targets_csv:
        items = [(r["domain"].strip().lower(), r.get("set", "file"))
                 for r in csv.DictReader(open(args.targets_csv)) if r["domain"].strip()]
    elif args.domains_file:
        items = [(l.strip().lower(), "file") for l in open(args.domains_file)
                 if l.strip() and not l.startswith("#")]
    else:
        items = load_targets(args.include_controls)

    out = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "source": "crt.sh", "count": len(items), "domains": {}}
    t0 = time.time()
    for i, (d, s) in enumerate(items, 1):
        rec = {"set": s, "certs": [], "errors": []}
        seen_ids = set()
        for q in (d, "%25." + d):
            rows, err = crtsh(q)
            if err:
                rec["errors"].append(f"{q}: {err}")
                continue
            for r in rows or []:
                cid = r.get("id")
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                rec["certs"].append(slim(r))
            time.sleep(args.pause)
        out["domains"][d] = rec
        if i % 20 == 0 or i == len(items):
            print(f"  {i}/{len(items)} ({sum(len(v['certs']) for v in out['domains'].values())} certs)",
                  file=sys.stderr, flush=True)
            json.dump(out, open(args.out, "w"), indent=1)
    out["elapsed_s"] = round(time.time() - t0, 1)
    json.dump(out, open(args.out, "w"), indent=1)
    print(f"[+] wrote {args.out}: {len(items)} domains, "
          f"{sum(len(v['certs']) for v in out['domains'].values())} certs, {out['elapsed_s']}s",
          file=sys.stderr)


if __name__ == "__main__":
    main()
