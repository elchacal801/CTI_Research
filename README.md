# CTI_Research — Domain Infrastructure Enumeration

Infrastructure enumeration and pivot analysis over a set of 263 domains observed in
job/career/recruitment-themed and disposable-mailbox activity.

## Layout

```
data/     source domain list (xlsx + csv): domain, class, risk score, risk tier
scripts/  collection and analysis tooling
output/   generated results (raw JSON, flat CSV, analyst report)
```

## Scripts

| Script | Purpose |
|---|---|
| `scripts/enumerate_dns.py` | Live DNS collection: `A`, `AAAA`, `MX`, `TXT`, `SOA`, `NS`, `CNAME`, `CAA`, plus `_dmarc`, DKIM selector sweep, `_mta-sts`, `_smtp._tls`, a 28-name subdomain probe, MX/NS host resolution, reverse DNS, and ASN/BGP-prefix/country enrichment via the Team Cymru IP-to-ASN DNS service. |
| `scripts/enumerate_rdap.py` | RDAP collection (registrar, IANA ID, registration/expiry/last-changed dates, status codes, abuse contact, registrant country, delegated NS, DNSSEC) with a WHOIS port-43 fallback. |
| `scripts/analyze_infra.py` | Normalises records into a flat table and clusters domains on 16 shared infrastructure selectors. |
| `scripts/cluster_operators.py` | Merges single-selector clusters into operator groups using account-level evidence only. |
| `scripts/build_report.py` | Renders the analyst-facing markdown report. |

## Running

```bash
pip install dnspython
python3 scripts/enumerate_dns.py --workers 24     # -> output/dns_enumeration.json
python3 scripts/enumerate_rdap.py --workers 8     # -> output/rdap_enumeration.json
python3 scripts/build_report.py                   # -> CSV, clusters, operator groups, report
```

## Outputs

| File | Contents |
|---|---|
| `output/dns_enumeration.json` | Raw per-domain records plus a per-IP intel map (PTR, ASN, AS name, BGP prefix, registry, allocation date, country). |
| `output/rdap_enumeration.json` | RDAP/WHOIS registration data. |
| `output/domain_infrastructure.csv` | One row per domain, flattened for spreadsheet triage. |
| `output/pivot_clusters.json` | Domains grouped by shared selector, across 16 pivot types. |
| `output/operator_clusters.json` | Connected components over account-level selectors, with vendor-level corroboration. |
| `output/INFRASTRUCTURE_REPORT.md` | Coverage, provider/ASN concentration, mail-auth posture, ranked pivot clusters, linked operator groups. |

## Note on network egress

DNS collection needs outbound UDP/53. RDAP needs outbound HTTPS to registry RDAP
endpoints; the WHOIS fallback needs outbound TCP/43. Restricted environments commonly
permit the first and block the latter two — `enumerate_rdap.py` records the block
per-domain rather than failing, so the run is replayable elsewhere.

## Analytic caveat

Pivot selectors are not equally strong. A shared DKIM public key or provider
verification token implies a shared *account*; a shared IP or PTR implies shared
*hosting*; a shared ASN or mail provider implies only a shared *vendor* and is close to
meaningless on its own for attribution. The report orders clusters accordingly.

Vendor-level selectors are actively filtered out of the operator clustering. Two
examples from this dataset show why: 59 domains share reverse DNS on two AWS Global
Accelerator instances, but every member is a GoDaddy-nameserver domain sitting on
GoDaddy's shared parking front end — the accelerator is the vendor's, not a customer's.
Likewise ~130 domains share Google MX IPs, which says only that they use Google
Workspace. `scripts/cluster_operators.py` keeps a suffix list of such vendor estates
and links solely on selectors the domain controller had to create.
