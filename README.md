# CTI_Research — Domain Infrastructure Enumeration

Infrastructure and registration enumeration, with pivot analysis, over a set of 263
domains observed in job/career/recruitment-themed and disposable-mailbox activity.

The analyst-facing product is `output/INFRASTRUCTURE_REPORT.md`.

## Layout

```
data/     source domain list (xlsx + csv): domain, class, risk score, risk tier;
          plus the members confirmed by the expansion sweep
scripts/  collection and analysis tooling
output/   generated results (raw JSON, flat CSV, analyst report)
```

## Scripts

| Script | Purpose |
|---|---|
| `scripts/enumerate_dns.py` | Live DNS collection: `A`, `AAAA`, `MX`, `TXT`, `SOA`, `NS`, `CNAME`, `CAA`, plus `_dmarc`, DKIM selector sweep, `_mta-sts`, `_smtp._tls`, a subdomain probe, MX/NS host resolution, reverse DNS, and ASN/BGP-prefix/country enrichment via the Team Cymru IP-to-ASN DNS service. |
| `scripts/deep_enumerate.py` | Second DNS pass: 133-name subdomain wordlist, 55 DKIM selectors, wildcard-zone detection (probes suppressed, canaries retried), DNSSEC status and NSEC walking. |
| `scripts/enumerate_rdap.py` | Registration collection. Registry RDAP via the IANA bootstrap (ccTLD overrides for `.io/.me/.us/.ch`), registrar RDAP followed through the registry's `related` link; where a registry offers no public RDAP (`.co`) the registrar is guessed from delegated nameservers and queried directly using the IANA registrar-ID list; WHOIS/43 where no RDAP exists (`.ru`). Classifies registrant data as `proxy:<service>` / `redacted` / `disclosed` / `absent`. `--controls` enumerates the expansion-sweep control population; `--retry <json>` is a slow single-threaded pass that recovers records lost to registrar rate limiting. |
| `scripts/enumerate_certs.py` | Certificate-transparency collection via crt.sh: for each corpus/lead/discovered domain (and, with `--include-controls` or `--targets-csv`, the control population), the CT-logged certificates for the apex and `%.<domain>`. A certificate whose SANs span two or more different registrable domains is an account-level link. crt.sh returns historical certificates a live DNS probe cannot. |
| `scripts/analyze_certs.py` | Links domains on shared certificates, excluding multi-tenant vendor/SaaS certificates and reference-provider estates; reports whether any certificate spans two members of an operator group (it does not), corpus domains with a shared certificate, SAN siblings, and control-population clusters. |
| `scripts/expand_clusters.py`, `scripts/expand_group2.py` | Cluster expansion: candidate names from the corpus naming grammar tested against each group's DNS marker (SPF-management tenant TXT; URIports account in DMARC), with wildcard and parking-default false positives controlled out. Registered candidates carrying no marker become the control population. |
| `scripts/analyze_infra.py` | Normalises DNS and registration records into a flat table and clusters domains on shared infrastructure and registration selectors. Registrant geography is kept only where it is the registrant's own (never a proxy's address, never a registrar placeholder value identified against the controls). |
| `scripts/cluster_operators.py` | Merges single-selector clusters into operator groups using account-level evidence only (DKIM key, SPF-management tenant, DMARC-platform account, verification token, disclosed registrant organisation, non-vendor reverse DNS); registrar, timing and hosting are attached as corroboration. |
| `scripts/temporal_analysis.py` | Registration-timing analysis: same-registrar bursts (≤10 min) and day batches with control base rates, control collisions (leads), per-group registration timelines, same-checkout leads, registry last-changed batches control-tested per registrar, lifecycle/EPP status, hypothesis tests; SOA-serial batch detection retained as the secondary signal. |
| `scripts/build_report.py` | Runs the analysis chain and renders the report. |

## Running

```bash
pip install dnspython
python3 scripts/enumerate_dns.py --workers 24          # -> output/dns_enumeration.json
python3 scripts/deep_enumerate.py                      # -> output/deep_enumeration.json
python3 scripts/expand_clusters.py                     # -> output/cluster_expansion.json
python3 scripts/expand_group2.py                       # -> output/group2_expansion.json
python3 scripts/enumerate_rdap.py --workers 6          # -> output/rdap_enumeration.json
python3 scripts/enumerate_rdap.py --controls           # -> output/rdap_controls.json
python3 scripts/enumerate_rdap.py --retry output/rdap_enumeration.json   # recover rate-limited records
python3 scripts/enumerate_rdap.py --retry output/rdap_controls.json
python3 scripts/enumerate_certs.py                    # -> output/cert_enumeration.json (crt.sh)
python3 scripts/analyze_certs.py                      # -> output/cert_analysis.json
python3 scripts/build_report.py                        # -> CSV, clusters, groups, timing, report
```

## Outputs

| File | Contents |
|---|---|
| `output/dns_enumeration.json` | Raw per-domain DNS records plus a per-IP intel map (PTR, ASN, AS name, BGP prefix, registry, allocation date, country). |
| `output/deep_enumeration.json` | Second-pass subdomains, DKIM keys, wildcard/DNSSEC/NSEC results. |
| `output/rdap_enumeration.json` | Registration records for the source list and expansion members: registrar, IANA ID, creation/expiry/last-changed, EPP status, delegated NS, DNSSEC, classified registrant, abuse contact, plus the raw registry object for evidence. |
| `output/rdap_controls.json` | The same for the control population. |
| `output/cluster_expansion.json`, `output/group2_expansion.json` | Expansion-sweep results, rejected candidates and the reasons. |
| `output/domain_infrastructure.csv` | One row per domain, flattened for spreadsheet triage (DNS, mail-auth, hosting, registration). |
| `output/pivot_clusters.json` | Domains grouped by shared selector, across 21 pivot types. |
| `output/operator_clusters.json` | Connected components over account-level selectors, with corroboration. |
| `output/temporal_analysis.json` | Registration timing, base rates, leads, lifecycle, hypothesis tests, SOA batches. |
| `output/cert_enumeration.json` | crt.sh certificates (issuer, SANs, validity) per queried domain. |
| `output/cert_analysis.json` | Shared-certificate clusters, operator-group certificate status, SAN siblings. |
| `output/INFRASTRUCTURE_REPORT.md` | The report. |

## Note on network egress

DNS collection needs outbound UDP/53. Registration collection needs outbound HTTPS to
registry and registrar RDAP servers, TCP/43 for the WHOIS fallback, and HTTPS to crt.sh for certificates. Restricted
environments commonly permit the first and block the rest; `enumerate_rdap.py` records
a block per-domain rather than failing, so a run is replayable from a network that
permits the egress. Registrar RDAP servers rate-limit aggressively (HTTP 429); the
`--retry` pass exists for that.

## Analytic caveats

Pivot selectors are not equally strong. A shared DKIM public key, provider tenant id
or disclosed registrant organisation implies a shared *account*; a same-registrar
registration burst implies a shared *checkout*; a shared IP or PTR implies shared
*hosting*; a shared registrar, ASN or mail provider implies only a shared *vendor* and
is close to meaningless on its own. The report orders clusters accordingly and links
operator groups on account-level selectors only.

Every batch, burst or shared-value finding is measured against a control population —
registered, naming-adjacent domains that carry no cluster marker — before it is
believed. That is what separates a registrar placeholder (Hostinger returns Lithuania
for every customer) from a registrant's retained state, a provider-wide serial bump
from an operator's batch, and a population trait (job-mail registrants at Squarespace
skew to Gujarat and Texas regardless of cluster) from a fingerprint.

Registrant identity is withheld almost everywhere. Where a registrar published an
individual's name it is retained in the raw evidence file only and is not carried into
the flat table or the report.
