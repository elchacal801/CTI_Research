# Domain Infrastructure Enumeration

**Generated:** 2026-08-25T21:17:09Z (DNS); 2026-08-26T03:54:04Z (RDAP)  
**Source list:** `data/Domain_Summary_Reconstructed.csv` — 263 domains, plus 5 members confirmed by the expansion sweep  
**Collection:** live DNS over UDP/53 against 1.1.1.1, 8.8.8.8, 9.9.9.9, 1.0.0.1, 8.8.4.4; ASN/BGP/country via the Team Cymru IP-to-ASN DNS service; registry RDAP via the IANA bootstrap with registrar RDAP followed through each registry's `related` link, and WHOIS/43 where no RDAP exists. Registration data was collected from a separate network path that permits the RDAP and WHOIS egress the DNS pass lacked.

## 1. Summary of findings

- **Two operator groups are established on account-level evidence.** Group 1 (31 domains, SPF-management tenant `aa8e722993`) is registered entirely at GoDaddy; Group 2 (16 domains, URIports account `p7rqadcw`) entirely at Cloudflare. Registry timestamps show both were built in checkout-sized bursts: 14 of 31 Group 1 members and 9 of 16 Group 2 members were registered within ten minutes of another member at the same registrar, against a control-population rate of 6.1%.
- **Two further cohorts are probable but not proven.** 32 synthetic-brand mailbox domains on Squarespace's shared front end were registered at Squarespace in 9 bursts between 2023-10-25 and 2024-04-16 (the tightest: 4 seconds for 3 domains); 5 job-themed domains on Google Domains DNS were registered in 1 Squarespace burst (the tightest: 6 seconds for 5 domains, with 3 further names the control sweep caught in the same checkout). Identical naming grammar, identical hosting and same-checkout timing point to one operator each, but no account-level artefact links either set, so both are reported as registration cohorts rather than merged into operator groups.
- **Registrar is over-represented but not diagnostic.** Squarespace (ex-Google Domains) holds 26.9% of the corpus against 4.4% of the 617 control domains (6.09x), Hostinger holds 6.9% of the corpus against 2.3% of the 617 control domains (3.02x), Wix holds 4.5% of the corpus against 0.2% of the 617 control domains (25.37x). Each is a mass-market registrar the controls also use, so registrar remains a vendor fact and is never used to link.
- **Registrant identity is almost entirely withheld** — 86 domains sit behind a proxy service, 132 are redacted, 7 disclose an organisation. Where registrars retain the registrant's state/country under redaction, it clusters: US / NY (25), US / TX (15), IN / Gujarat (14), GB / East Sussex (13). Group 2 is uniformly GB-registered. Values that a registrar returns for every customer (its own office address) were identified against the control population and excluded.
- **Lifecycle.** 63 domains expire within 90 days, 1 are in redemption/pending-delete, 2 have lapsed into auto-renew grace, 0 are on registrar/registry hold. 3 names in the source list are not registered at all and 7 are host labels under other organisations' domains, not registrable names.
- **Certificate transparency corroborates rather than extends.** Across 2096 certificates, none spans two members of the actor groups (Groups 1-3, 5, 6): they sit on shared parking and each domain gets its own certificate, so the certificate channel adds no members. The only corpus domains that do share a certificate (`oxfordnetworks.com`, `restartworks.com`) share it with established, unrelated businesses — benign names the grammar swept in.
- **The 2026-02-05 GoDaddy batch is a reconfiguration, not a registration event.** 2 of 8 registered on 2024-05-15; the rest were registered on other days and only reconfigured together on 2026-02-05.

## 2. Collection scope and coverage

| DNS | Count |
|---|---|
| Domains in list | 263 |
| Resolving (have NS/SOA/A/MX) | 253 |
| Non-resolving / NXDOMAIN | 10 |
| With MX (mail-capable) | 223 |
| With SPF | 186 |
| With DMARC | 151 |
| With DKIM key found | 171 |
| With CAA | 15 |
| Unique IPs observed | 1207 |
| Unique ASNs | 49 |
| Subdomains discovered (wildcard zones suppressed) | 364 |

| Registration (RDAP/WHOIS) | Count |
|---|---|
| Domains queried (source list + expansion members) | 268 |
| Registered | 250 |
| Not registered (authoritative registry 404) | 10 |
| Undetermined (invalid TLD or no reachable source) | 8 |
| With registry-side record | 243 |
| With registrar-side record (registrant, abuse contact) | 221 |
| Registrar-only (registry offers no public RDAP) | 6 |
| WHOIS/43 only | 1 |
| Control population (unrelated, naming-adjacent registered domains) | 617 |

Registrar attribution below comes from the registry record. The nameserver-inferred operator used before RDAP was available is retained as a cross-check: 152 of 245 registered domains have their DNS at their registrar; the rest delegate DNS elsewhere (Cloudflare, NS1, Wix, Vercel).

## 3. Registration

### 3.1 Registrar of record

Corpus share against the control population. A lift near 1 means the registrar is simply popular for this kind of name; only a large lift would make it worth a pivot.

| Registrar | Corpus | Share | Controls | Share | Lift |
|---|---|---|---|---|---|
| GoDaddy | 78 | 31.8% | 132 | 23.4% | 1.36 |
| Squarespace (ex-Google Domains) | 66 | 26.9% | 25 | 4.4% | 6.09 |
| Cloudflare | 21 | 8.6% | 22 | 3.9% | 2.2 |
| Hostinger | 17 | 6.9% | 13 | 2.3% | 3.02 |
| Wix | 11 | 4.5% | 1 | 0.2% | 25.37 |
| Namecheap | 10 | 4.1% | 64 | 11.3% | 0.36 |
| Tucows | 6 | 2.4% | 34 | 6.0% | 0.41 |
| MarkMonitor | 6 | 2.4% | 9 | 1.6% | 1.54 |
| Realtime Register B.V. | 5 | 2.0% | 1 | 0.2% | 11.53 |
| INWX GmbH | 4 | 1.6% | 9 | 1.6% | 1.02 |
| Gandi | 4 | 1.6% | 3 | 0.5% | 3.07 |
| Spaceship | 2 | 0.8% | 21 | 3.7% | 0.22 |

### 3.2 Registration timing

245 of 245 registered source-list domains carry a registration timestamp (239 registry-side to the second, 5 registrar-side, 1 from WHOIS). Median age is 706 days.

| Age | Domains |
|---|---|
| < 90 days | 9 |
| 90 days - 1 year | 57 |
| 1 - 2 years | 60 |
| 2 - 5 years | 80 |
| > 5 years | 39 |

205 of 245 were registered in 2023 or later (2023: 43, 2024: 54, 2025: 70, 2026: 38); the long tail before 2020 is the benign reference set of established mail providers that shares the source list (Fastmail, Proton, Posteo, Tuta, Runbox, DuckDuckGo).

**Registration bursts.** Same registrar, consecutive registrations no more than ten minutes apart — the registry-side signature of one checkout. Registrar-side timestamps are excluded because their clocks are not comparable.

| Registrar | Start (UTC) | Span | n | Group | Members |
|---|---|---|---|---|---|
| Squarespace (ex-Google Domains) | 2023-11-01T10:58:12Z | 137s | 6 | - | `speedmailhub.com`, `quickpostmail.com`, `swiftinboxmail.com`, `rapidmailpost.com`, `rapidinboxpro.com`, `postmailpro.com` |
| Squarespace (ex-Google Domains) | 2023-03-04T11:33:30Z | 6s | 5 | - | `careeremail.net`, `mycareermail.com`, `jobemail.net`, `techcareermail.com`, `techjobsemail.net` |
| Squarespace (ex-Google Domains) | 2023-10-25T21:24:46Z | 569s | 5 | - | `swiftcouriermail.com`, `promailcenter.com`, `messagehubplus.com`, `letterinboxpro.com`, `couriermailhub.com` |
| Squarespace (ex-Google Domains) | 2023-11-01T09:58:25Z | 110s | 5 | - | `mailzoomexpress.com`, `rapidposthub.com`, `fastmailzoom.com`, `mailflashpro.com`, `propostbox.com` |
| Squarespace (ex-Google Domains) | 2023-10-31T22:34:23Z | 94s | 4 | - | `inboxflashpro.com`, `mailblitzhub.com`, `mailjethub.com`, `cometmailhub.com` |
| GoDaddy | 2024-03-14T20:48:58Z | 5s | 4 | 1 | `worksemails.com`, `itjobmail.com`, `myemailjob.com`, `mailsworks.com` |
| Cloudflare | 2026-01-21T02:01:52Z | 197s | 4 | 2 | `rapidmailhost.com`, `mailboxcore.com`, `tivomail.com`, `smartmailhost.net` |
| Cloudflare | 2026-06-04T08:48:52Z | 425s | 4 | 2 | `elitecandidates.com`, `careermails.net`, `primemailhost.com`, `swiftmailhost.com` |
| Squarespace (ex-Google Domains) | 2024-04-08T22:34:28Z | 4s | 3 | - | `zenithstellar.com`, `celestialflare.com`, `quantumzens.com` |
| Squarespace (ex-Google Domains) | 2024-04-16T11:23:28Z | 7s | 3 | - | `blazepinnacle.com`, `pulsearcana.com`, `pulsedynamo.com` |
| GoDaddy | 2024-09-25T18:21:26Z | 5s | 3 | 1 | `mailmywork.com`, `techsmail.com`, `myjobsmails.com` |
| GoDaddy | 2025-01-06T21:41:54Z | 43s | 3 | - | `jobitwork.com`, `myjobitmail.com`, `quickitmail.com` |
| Hostinger | 2025-01-31T20:55:06Z | 238s | 3 | - | `newjobrequire.com`, `newjobdesire.com`, `newjobshunt.com` |
| GoDaddy | 2025-08-26T19:01:36Z | 32s | 3 | 1 | `mymailjob.com`, `careersmails.com`, `mycareersjobs.com` |
| GoDaddy | 2025-11-03T14:56:38Z | 4s | 3 | 1 | `myjobscouts.com`, `savemymails.com`, `mailjobhub.com` |
| Squarespace (ex-Google Domains) | 2023-10-26T11:06:06Z | 113s | 2 | - | `expressinboxmail.com`, `mailzoomhub.com` |
| Squarespace (ex-Google Domains) | 2023-10-31T21:44:48Z | 5s | 2 | - | `flashpostmail.com`, `speedymailpost.com` |
| GoDaddy | 2024-03-12T20:34:55Z | 357s | 2 | 1 | `mycvtalent.com`, `mycvhire.com` |
| Squarespace (ex-Google Domains) | 2024-04-08T19:29:59Z | 5s | 2 | - | `terraquasar.com`, `phoenixglide.com` |
| Wix | 2024-05-13T18:46:53Z | 109s | 2 | - | `careerwebmail.com`, `mywebemails.com` |
| GoDaddy | 2024-05-15T19:31:39Z | 2s | 2 | 1 | `cvtechmail.com`, `techjobmail.com` |
| GoDaddy | 2024-06-25T16:01:13Z | 39s | 2 | 1 | `mycvscout.com`, `ajobguide.com` |
| GoDaddy | 2024-07-29T21:51:20Z | 47s | 2 | 1 | `jobtechmail.com`, `careeritjob.com` |
| GoDaddy | 2024-10-23T17:30:22Z | 3s | 2 | 1 | `themailpad.com`, `mymailkeeper.com` |
| Realtime Register B.V. | 2024-11-26T15:08:58Z | 513s | 2 | - | `jobrequires.com`, `jobsdesire.com` |
| GoDaddy | 2025-02-05T16:14:06Z | 0s | 2 | 1 | `protectmymails.com`, `mymailshub.com` |
| Hostinger | 2025-02-07T20:21:38Z | 171s | 2 | - | `itresumejobs.com`, `itjobdesire.com` |
| Cloudflare | 2025-11-22T17:26:55Z | 43s | 2 | 2 | `mailactiv.com`, `activemails.net` |
| GoDaddy | 2026-04-22T20:53:08Z | 4s | 2 | 1 | `techmyjob.com`, `mailscareer.com` |
| GoDaddy | 2026-05-07T19:29:54Z | 281s | 2 | - | `jobsmailbox.com`, `jobinboxhub.com` |

88 of 239 registry-dated corpus domains (36%) sit in a burst. Among the 617 control domains the figure is 33 (6.1%). Same-registrar same-day batches: 100 corpus domains (40%) against 41 controls (7.3%). The controls are naming-adjacent domains that failed the cluster marker test, and some may still belong to the same operators, so the control rate is an upper bound on chance.

**Control domains registered inside a corpus burst window** (same registrar, within ten minutes). These are leads for the marker probe, not members:

| Corpus domain | Group | Control domain | Registrar | Gap |
|---|---|---|---|---|
| careeremail.net | - | cvemail.net | Squarespace (ex-Google Domains) | 0s |
| careeremail.net | - | workmails.net | Squarespace (ex-Google Domains) | 0s |
| careerx.us | - | careerx.io | GoDaddy | 0s |
| jobemail.net | - | cvemail.net | Squarespace (ex-Google Domains) | 0s |
| jobemail.net | - | workmails.net | Squarespace (ex-Google Domains) | 0s |
| mycareermail.com | - | cvemail.net | Squarespace (ex-Google Domains) | 0s |
| mycareermail.com | - | workmails.net | Squarespace (ex-Google Domains) | 0s |
| pxdmail.com | - | pxdmail.net | Namecheap | 0s |
| careeremail.net | - | mycvemail.com | Squarespace (ex-Google Domains) | 1s |
| jobemail.net | - | mycvemail.com | Squarespace (ex-Google Domains) | 1s |
| mycareermail.com | - | mycvemail.com | Squarespace (ex-Google Domains) | 1s |
| techcareermail.com | - | mycvemail.com | Squarespace (ex-Google Domains) | 4s |
| techcareermail.com | - | cvemail.net | Squarespace (ex-Google Domains) | 5s |
| techcareermail.com | - | workmails.net | Squarespace (ex-Google Domains) | 5s |
| techjobsemail.net | - | mycvemail.com | Squarespace (ex-Google Domains) | 5s |
| techjobsemail.net | - | cvemail.net | Squarespace (ex-Google Domains) | 6s |
| techjobsemail.net | - | workmails.net | Squarespace (ex-Google Domains) | 6s |
| keemail.me | - | keemail.org | INWX GmbH | 8s |
| keemail.me | - | keemail.net | INWX GmbH | 19s |
| oxfordnetworks.net | - | oxfordnetworks.com | Tucows | 20s |

**Registry last-changed batches.** The registry's `last changed` event moves on renewal, nameserver change or transfer, but also on registrar platform events, so each batch is checked against the controls at the same registrar:

| Registrar | Day | n | Group | Controls same day | Verdict |
|---|---|---|---|---|---|
| Squarespace (ex-Google Domains) | 2025-10-17 | 15 | - | 0 of 25 | operator-specific (controls do not share it) |
| Hostinger | 2026-02-02 | 5 | - | 0 of 13 | operator-specific (controls do not share it) |
| Squarespace (ex-Google Domains) | 2025-10-10 | 5 | - | 0 of 25 | operator-specific (controls do not share it) |
| GoDaddy | 2026-03-19 | 4 | 1 | 0 of 132 | operator-specific (controls do not share it) |
| Squarespace (ex-Google Domains) | 2026-03-04 | 4 | - | 3 of 25 | also seen in 3 controls — weak |
| Cloudflare | 2026-06-04 | 4 | 2 | 0 of 22 | operator-specific (controls do not share it) |
| GoDaddy | 2026-08-12 | 4 | 1, 5 | 8 of 132 | also seen in 8 controls — weak |
| Cloudflare | 2026-01-21 | 4 | 2 | 0 of 22 | operator-specific (controls do not share it) |
| GoDaddy | 2025-08-12 | 3 | 1 | 0 of 132 | operator-specific (controls do not share it) |
| GoDaddy | 2025-01-06 | 3 | - | 0 of 132 | operator-specific (controls do not share it) |

### 3.3 Registrant disclosure

| Registrant data | Domains |
|---|---|
| redacted | 113 |
| proxy | 86 |
| no registrar-side record | 20 |
| redacted (registrar placeholder geo) | 19 |
| disclosed | 7 |

Proxy services standing in for the registrant: Domains By Proxy (GoDaddy) (69), Withheld for Privacy (Namecheap) (11), registrar proxy (on behalf of) (2), Private by Design (Porkbun) (2), PrivacyProtect.org (Hostinger et al.) (1), Domain Protection Services (Name.com) (1). A proxy's address is the proxy's, and is never treated as registrant geography.

Registrar placeholder values, identified because the registrar returns the same state/country for nearly every control domain too, and therefore excluded: HOSTINGER operations, UAB → LT (92% of 12 controls); INWX GmbH → DE (100% of 7 controls); MarkMonitor Inc. → US (100% of 5 controls).

**Retained registrant state/country** (redacted or disclosed records, placeholders removed):

| State / country | n | Registrar | Control check (same geo / controls with geo at registrar) | Operator group | Dominant class | Members |
|---|---|---|---|---|---|---|
| US / NY | 25 | Squarespace (ex-Google Domains) (25) | unverified (too few controls at this registrar) (0 of 2) | - | synthetic_generic_mailbox_brand | `mailflashpro.com`, `mailzoomexpress.com`, `fastmailzoom.com`, `postmailpro.com`, `messagehubplus.com`, `cometmailhub.com`, … (+19 more) |
| US / TX | 15 | Squarespace (ex-Google Domains) (15) | rare among controls (1 of 23) | - | job_career_work_it_cv_themed | `workitmail.com`, `jobsitmail.com`, `workmailit.com`, `workapplyjob.com`, `myjobitapp.com`, `worktechmail.com`, … (+9 more) |
| IN / Gujarat | 14 | Squarespace (ex-Google Domains) (14) | common among controls too (population trait) (4 of 23) | - | job_career_work_it_cv_themed | `careeremail.net`, `techcareermail.com`, `jobemails24.com`, `jobtecmail.net`, `mycareermail.com`, `techjobsemail.net`, … (+8 more) |
| GB / East Sussex | 13 | Cloudflare (13) | rare among controls (0 of 16) | Group 2 (11) | synthetic_generic_mailbox_brand | `mailmessage.co`, `swiftemail.co`, `boxmailhost.com`, `pulsemailbox.com`, `activemails.net`, `mailactiv.com`, … (+7 more) |
| NL | 7 | Realtime Register B.V. (5), NameWeb BVBA (2) | unverified (too few controls at this registrar) (1 of 1) | - | job_career_work_it_cv_themed | `cvejobs.com`, `careermails.com`, `jobsdesire.com`, `career-techmail.com`, `carrermail.com`, `quopost.com`, … (+1 more) |
| US / FL | 6 | Squarespace (ex-Google Domains) (5), Cloudflare (1) | unverified (too few controls at this registrar) (0 of 2) | - | synthetic_generic_mailbox_brand | `blazepinnacle.com`, `mailbluff.com`, `terraquasar.com`, `phoenixglide.com`, `pulsearcana.com`, `pulsedynamo.com` |
| US / CA | 5 | Wix (2), Cloudflare (1) | unverified (too few controls at this registrar) (0 of 0) | Group 4 (1) | synthetic_generic_mailbox_brand | `jobhuntmails.com`, `mywebemails.com`, `mailflux.com`, `passmail.com`, `risemail.com` |
| GB / Leicestershire | 5 | Cloudflare (5) | rare among controls (0 of 16) | Group 2 (4) | job_career_work_it_cv_themed | `careermails.net`, `nextstepcareer.net`, `elitecandidates.com`, `topcandidate.co`, `swiftmailhost.com` |
| CH | 5 | MarkMonitor (5) | rare among controls (0 of 5) | Group 4 (2) | privacy_alias_mailbox | `protonmail.com`, `proton.me`, `pm.me`, `passmail.net`, `passinbox.com` |
| UY / Florida | 3 | Squarespace (ex-Google Domains) (3) | unverified (too few controls at this registrar) (0 of 2) | - | synthetic_generic_mailbox_brand | `quantumzens.com`, `zenithstellar.com`, `celestialflare.com` |
| AU / Victoria | 3 | Gandi (3) | unverified (too few controls at this registrar) (1 of 2) | Group 3 (3) | privacy_alias_mailbox | `fastmail.com`, `fastmail.net`, `pobox.com` |
| IN / Maharashtra | 2 | Cloudflare (1), Name SRS AB (1) | rare among controls (0 of 16) | - | privacy_alias_mailbox | `my-privatemail.com`, `careerwebmails.com` |

Geography is a weak selector on its own — a state is shared by millions of registrants — but it is independent of DNS and hosting, so agreement with a burst or a group is corroboration and disagreement is a warning. The control column says how the same registrar's unrelated customers look: a value most of them share is the registrar's placeholder; a value a sizeable minority share is a trait of the population that registers this kind of name (job-mail registrants skew to Gujarat and Texas at Squarespace whether or not they are in a cluster); only a value the controls rarely carry is worth weight.

**Disclosed registrant organisations:**

| Domain | Organisation | State / country |
|---|---|---|
| mycvwork.com | Connect Tech IT Inc | IN / Gujarat |
| passmail.com | DNStination Inc. | US / CA |
| duck.com | Duck Duck Go, Inc. | US / PA |
| posteo.in | Posteo e.K. | DE |
| myitemailapp.com | Zenith Technology LLC | US / TX |
| jobemails24.com | careermailbox | IN / Gujarat |

### 3.4 Lifecycle and status

| State | n | Domains |
|---|---|---|
| On hold (clientHold / serverHold) | 0 | none |
| Redemption / pending delete | 1 | `careerwebmails.com (redemptionPeriod)` |
| Lapsed into auto-renew grace | 2 | `i-mail.in`, `vegascareers.org` |
| Expiring within 90 days | 63 | `activemails.net (2026-11-22)`, `boxmailhost.com (2026-11-11)`, `career-techmail.com (2026-09-13)`, `careermailus.com (2026-11-13)`, `cometmailhub.com (2026-10-31)`, `couriermailhub.com (2026-10-25)`, `cvmailhub.com (2026-10-02)`, `eprivatemail.com (2026-09-17)`, `expressinboxmail.com (2026-10-26)`, `fastmailzoom.com (2026-11-01)`, … (+53 more) |
| Registered but not resolving | 1 | `careerwebmails.com` |
| Registry-locked (server* prohibitions) | 5 | `mailmessage.co`, `pm.me`, `proton.me`, `protonmail.com`, `swiftemail.co` |

No domain in the corpus is suspended. The registry locks belong to the established mail providers in the reference set, not to the themed clusters.

## 4. Hosting and service concentration

**DNS operator (from delegated nameservers)**

| Operator | Domains | Share of live |
|---|---|---|
| GoDaddy | 65 | 25.7% |
| Google Domains / Squarespace | 34 | 13.4% |
| Cloudflare | 31 | 12.3% |
| NS1;Squarespace | 27 | 10.7% |
| Hostinger | 21 | 8.3% |
| none | 21 | 8.3% |
| Wix | 11 | 4.3% |
| Namecheap | 4 | 1.6% |
| Squarespace | 3 | 1.2% |
| vercel-dns.com | 3 | 1.2% |
| messagingengine.com | 3 | 1.2% |
| Porkbun | 2 | 0.8% |
| awsdns-07.org;awsdns-23.co.uk;awsdns-40.com;awsdns-45.net | 1 | 0.4% |
| siteground.net | 1 | 0.4% |
| protonmail.com | 1 | 0.4% |

**Mail provider (from MX)**

| Provider | Domains |
|---|---|
| Google Workspace | 143 |
| Microsoft 365 | 25 |
| self/other (amazonaws.com) | 9 |
| Bulk/ESP | 6 |
| Proton Mail | 5 |
| Zoho Mail | 3 |
| Fastmail | 3 |
| self/other (simplelogin.co) | 3 |
| Tuta | 3 |
| self/other (icloud.com) | 2 |
| self/other (posteo.de) | 2 |
| GoDaddy Email | 1 |
| self/other (mimecast.com) | 1 |
| Cloudflare Email Routing | 1 |
| IONOS Mail | 1 |

**Hosting ASN** (from the domain's own A/AAAA records and discovered subdomains)

| ASN | AS name | Domains |
|---|---|---|
| AS16509 | AMAZON-02 - Amazon.com, Inc., US | 74 |
| AS53831 | SQUARESPACE - Squarespace, Inc., US | 57 |
| AS47583 | AS-HOSTINGER - Hostinger International Limited, CY | 21 |
| AS13335 |  | 16 |
| AS58182 | wix_com - Wix.com Ltd., IL | 10 |
| AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | 7 |
| AS62371 | PROTON - Proton AG, CH | 4 |
| AS15169 | GOOGLE - Google LLC, US | 3 |
| AS22612 | NAMECHEAP-NET - Namecheap, Inc., US | 3 |
| AS209242 |  | 3 |
| AS151847 | FASTMAILPTYLTD-AS-AP - Fastmail Pty Ltd, AU | 3 |
| AS210909 | TUTA - Tutao GmbH, DE | 3 |
| AS398787 |  | 2 |
| AS398101 | GO-DADDY-COM-LLC - GoDaddy.com, LLC, US | 2 |
| AS8495 | INTERNET_AG - INTERNET AG Global Network, DE | 2 |

**Mail-path ASN** (from MX host IPs — vendor infrastructure, not attributable)

| ASN | AS name | Domains |
|---|---|---|
| AS15169 | GOOGLE - Google LLC, US | 129 |
| AS8075 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US | 29 |
| AS16276 | OVH - OVH SAS, FR | 19 |
| AS16509 | AMAZON-02 - Amazon.com, Inc., US | 8 |
| AS62371 | PROTON - Proton AG, CH | 8 |
| AS14618 | AMAZON-AES - Amazon.com, Inc., US | 7 |
| AS13335 |  | 4 |
| AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | 4 |

**Geo (BGP registry country):** US (171), CY (21), IL (10), DE (7), CH (4), NL (3), AU (3), LT (2), GB (2), CA (2)

## 5. Mail authentication posture

| DMARC policy (mail-capable domains) | Count |
|---|---|
| none-published | 84 |
| quarantine | 78 |
| none | 56 |
| reject | 5 |

**Most common SPF includes**

| SPF include / mechanism | Domains |
|---|---|
| _spf.google.com | 82 |
| spf.protection.outlook.com | 24 |
| spf.migadu.com | 15 |
| secureserver.net | 12 |
| amazonses.com | 7 |
| mailgun.org | 6 |
| _spf.mx.cloudflare.net | 3 |
| _spf.protonmail.ch | 3 |
| spf.messagingengine.com | 3 |
| simplelogin.co | 3 |
| spf.tutanota.de | 3 |
| 162.0.237.182 | 2 |
| dc-aa8e722993._spfm.itjobmail.com | 1 |
| dc-aa8e722993._spfm.jobitmail.com | 1 |
| dc-aa8e722993._spfm.myjobsmails.com | 1 |

## 6. Infrastructure pivot clusters

Clusters are sets of two or more domains sharing a selector, ordered from strongest to weakest attribution value. A shared DKIM key, provider tenant or disclosed registrant organisation implies a shared *account*; a same-registrar registration burst implies a shared *checkout*; a shared IP or PTR implies shared *hosting*; a shared registrar, ASN or provider implies only a shared *vendor* and is close to meaningless alone.

### Shared DKIM public key
*Attribution strength: very high — the same private key signs mail for every member, so one mail account/tenant controls them*

| Selector | Domains | Members |
|---|---|---|
| `dkim:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJudTILTG3qrzQzZzbptozaGQ0` | 3 | `passinbox.com`, `passmail.com`, `passmail.net` |
| `k2:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9` | 2 | `insightfulworkplace.com`, `prorecresources.com` |
| `k3:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsYGiMSn7fsUqSvfSX40x` | 2 | `insightfulworkplace.com`, `prorecresources.com` |

### Shared SPF-management tenant
*Attribution strength: very high — one account administers SPF for every member domain*

| Selector | Domains | Members |
|---|---|---|
| `spfm:aa8e722993` | 27 | `careernb.com`, `careersmails.com`, `cvmailhub.com`, `itjobmail.com`, `jobitmail.com`, `jobsmails.com`, `jobtechmail.com`, `mailmywork.com`, `mailscareer.com`, `mailsworks.com`, `mycareersjobs.com`, `mycvscout.com`, … (+15 more) |

### Shared DMARC reporting-platform account
*Attribution strength: very high — DMARC failure reports for every member land in one operator's account*

| Selector | Domains | Members |
|---|---|---|
| `uriports:p7rqadcw` | 15 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailboxcore.com`, `nextstepcareer.net`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, … (+3 more) |
| `ondmarc:e3936a44` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |

### Shared DMARC reporting address
*Attribution strength: high — same reporting mailbox (weaker where it is a provider default)*

| Selector | Domains | Members |
|---|---|---|
| `dmarc_rua@onsecureserver.net` | 20 | `careermailus.com`, `careersmails.com`, `inboxhere.com`, `insphiretalent.com`, `itcareerinfo.com`, `jobinboxhub.com`, `jobsupp.com`, `mailscareer.com`, `mycareersmail.com`, `myitjobshub.com`, `myjobfolio.com`, `myjobscouts.com`, … (+8 more) |
| `dmarc@p7rqadcw.uriports.com` | 15 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailboxcore.com`, `nextstepcareer.net`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, … (+3 more) |
| `e3936a44@inbox.ondmarc.com` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |

### Shared hosting reverse-DNS hostname
*Attribution strength: high — same host (excludes mail-vendor IPs)*

| Selector | Domains | Members |
|---|---|---|
| `a2aa9ff50de748dbe.awsglobalaccelerator.com` | 32 | `ajobguide.com`, `careerattainment.com`, `careeritjob.com`, `careernb.com`, `careersmails.com`, `cvmailhub.com`, `jobinboxhub.com`, `jobitmail.com`, `jobsmailbox.com`, `jobsmails.com`, `jobstechmail.com`, `jobsupp.com`, … (+20 more) |
| `a16e665f42988324c.awsglobalaccelerator.com` | 27 | `careermailus.com`, `cvtechmail.com`, `glidemail.io`, `itcareerinfo.com`, `itjobmail.com`, `itjobworks.com`, `jobitwork.com`, `jobstechmails.com`, `jobtechmail.com`, `jobtechsmail.com`, `mailjobtech.com`, `mailmywork.com`, … (+15 more) |
| `unalocated.63.wixsite.com` | 10 | `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `185-70-42-150.protonmail.ch` | 4 | `pm.me`, `proton.me`, `protonmail.ch`, `protonmail.com` |
| `185-70-42-31.protonmail.ch` | 3 | `pm.me`, `protonmail.ch`, `protonmail.com` |
| `redir.messagingengine.com` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |
| `www.messagingengine.com` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |
| `abe11aa245084d8f0.awsglobalaccelerator.com` | 2 | `careermails.com`, `quopost.com` |
| `sites.framer.app` | 2 | `eprivatemail.com`, `whisperpost.io` |

### Shared hosting IP
*Attribution strength: high on dedicated hosting, low on shared/parking/CDN ranges*

| Selector | Domains | Members |
|---|---|---|
| `198.185.159.144` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `198.185.159.145` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `198.49.23.144` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `198.49.23.145` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `15.197.148.33` | 32 | `ajobguide.com`, `careerattainment.com`, `careeritjob.com`, `careernb.com`, `careersmails.com`, `cvmailhub.com`, `jobinboxhub.com`, `jobitmail.com`, `jobsmailbox.com`, `jobsmails.com`, `jobstechmail.com`, `jobsupp.com`, … (+20 more) |
| `3.33.130.190` | 32 | `ajobguide.com`, `careerattainment.com`, `careeritjob.com`, `careernb.com`, `careersmails.com`, `cvmailhub.com`, `jobinboxhub.com`, `jobitmail.com`, `jobsmailbox.com`, `jobsmails.com`, `jobstechmail.com`, `jobsupp.com`, … (+20 more) |
| `13.248.243.5` | 27 | `careermailus.com`, `cvtechmail.com`, `glidemail.io`, `itcareerinfo.com`, `itjobmail.com`, `itjobworks.com`, `jobitwork.com`, `jobstechmails.com`, `jobtechmail.com`, `jobtechsmail.com`, `mailjobtech.com`, `mailmywork.com`, … (+15 more) |
| `76.223.105.230` | 27 | `careermailus.com`, `cvtechmail.com`, `glidemail.io`, `itcareerinfo.com`, `itjobmail.com`, `itjobworks.com`, `jobitwork.com`, `jobstechmails.com`, `jobtechmail.com`, `jobtechsmail.com`, `mailjobtech.com`, `mailmywork.com`, … (+15 more) |
| `2.57.91.91` | 18 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `itjobdesire.com`, `itjobemails.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmaildesk.com`, `jobmailoffer.com`, `jobrequires.com`, `jobsdesire.com`, `myemailjobs.com`, … (+6 more) |
| `185.230.63.107` | 10 | `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `185.230.63.171` | 10 | `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `185.230.63.186` | 10 | `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |

*24 further clusters of this type in `output/pivot_clusters.json`.*

### Same registrar, same registration day
*Attribution strength: medium-high when the span is minutes (see section 3.2); medium when hours*

| Selector | Domains | Members |
|---|---|---|
| `Squarespace (ex-Google Domains)|2023-11-01` | 11 | `fastmailzoom.com`, `mailflashpro.com`, `mailzoomexpress.com`, `postmailpro.com`, `propostbox.com`, `quickpostmail.com`, `rapidinboxpro.com`, `rapidmailpost.com`, `rapidposthub.com`, `speedmailhub.com`, `swiftinboxmail.com` |
| `Squarespace (ex-Google Domains)|2023-10-31` | 6 | `cometmailhub.com`, `flashpostmail.com`, `inboxflashpro.com`, `mailblitzhub.com`, `mailjethub.com`, `speedymailpost.com` |
| `Squarespace (ex-Google Domains)|2023-03-04` | 5 | `careeremail.net`, `jobemail.net`, `mycareermail.com`, `techcareermail.com`, `techjobsemail.net` |
| `Squarespace (ex-Google Domains)|2024-04-08` | 5 | `celestialflare.com`, `phoenixglide.com`, `quantumzens.com`, `terraquasar.com`, `zenithstellar.com` |
| `Squarespace (ex-Google Domains)|2023-10-25` | 5 | `couriermailhub.com`, `letterinboxpro.com`, `messagehubplus.com`, `promailcenter.com`, `swiftcouriermail.com` |
| `GoDaddy|2024-03-14` | 4 | `itjobmail.com`, `mailsworks.com`, `myemailjob.com`, `worksemails.com` |
| `Cloudflare|2025-11-22` | 4 | `activemails.net`, `mailactiv.com`, `mailmessage.co`, `swiftemail.co` |
| `Cloudflare|2026-01-21` | 4 | `mailboxcore.com`, `rapidmailhost.com`, `smartmailhost.net`, `tivomail.com` |
| `GoDaddy|2024-03-12` | 3 | `mycvhire.com`, `mycvtalent.com`, `nextitjobs.com` |
| `GoDaddy|2024-09-25` | 3 | `mailmywork.com`, `myjobsmails.com`, `techsmail.com` |
| `Cloudflare|2026-06-04` | 3 | `careermails.net`, `elitecandidates.com`, `swiftmailhost.com` |
| `GoDaddy|2025-01-06` | 3 | `jobitwork.com`, `myjobitmail.com`, `quickitmail.com` |

*17 further clusters of this type in `output/pivot_clusters.json`.*

### Shared SOA responsible mailbox
*Attribution strength: medium — same DNS operator*

| Selector | Domains | Members |
|---|---|---|
| `dns.jomax.net` | 67 | `ajobguide.com`, `applyme.co`, `careerattainment.com`, `careeritjob.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `cvmailhub.com`, `cvtechmail.com`, `ebsworksite.com`, `eprivatemail.com`, `glidemail.io`, … (+55 more) |
| `cloud-dns-hostmaster.google.com` | 34 | `applyitmail.com`, `career2026.com`, `careeremail.net`, `championtalentco.com`, `hcmconsultingpro.com`, `itworkmail.net`, `jobemail.net`, `jobemails24.com`, `jobmails.net`, `jobsitmail.com`, `jobtecmail.net`, `mycvwork.com`, … (+22 more) |
| `hostmaster.nsone.net` | 30 | `blazepinnacle.com`, `careermail.pro`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `duck.com`, `expressinboxmail.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, … (+18 more) |
| `dns.cloudflare.com` | 27 | `activemails.net`, `aogjob.com`, `boxmailhere.com`, `boxmailhost.com`, `careermails.net`, `careerx.us`, `contactbox.io`, `elitecandidates.com`, `inboxhere.com`, `inboxhires.com`, `jobhuntus.com`, `mailactiv.com`, … (+15 more) |
| `dns.hostinger.com` | 19 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `itjobemails.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmaildesk.com`, `jobmailoffer.com`, `jobrequires.com`, `jobsdesire.com`, `myemailjobs.com`, `myhotmail.net`, … (+7 more) |
| `support.wix.com` | 9 | `careerwebmail.com`, `jobemails.net`, `jobhuntmails.com`, `myjobsinbox.com`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `awsdns-hostmaster.amazon.com` | 7 | `careerio-aa.com`, `keemail.me`, `mailflyn.com`, `proctorconsultingservices.com`, `skymail.ai`, `tuta.io`, `tutanota.com` |
| `support.protonmail.ch` | 3 | `pm.me`, `protonmail.ch`, `protonmail.com` |
| `postmaster.messagingengine.com` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |
| `hostmaster.registrar-servers.com` | 2 | `hirehub.careers`, `jobmail.io` |
| `hostmaster.bnamed.eu` | 2 | `careermails.com`, `quopost.com` |
| `hostmaster.posteo.de` | 2 | `posteo.in`, `posteo.net` |

### Shared authoritative nameserver
*Attribution strength: medium*

| Selector | Domains | Members |
|---|---|---|
| `ns01.squarespacedns.com` | 27 | `blazepinnacle.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailjethub.com`, `mailzoomexpress.com`, … (+15 more) |
| `ns03.squarespacedns.com` | 27 | `blazepinnacle.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailjethub.com`, `mailzoomexpress.com`, … (+15 more) |
| `ns04.squarespacedns.com` | 27 | `blazepinnacle.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailjethub.com`, `mailzoomexpress.com`, … (+15 more) |
| `ns02.squarespacedns.com` | 27 | `blazepinnacle.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailjethub.com`, `mailzoomexpress.com`, … (+15 more) |
| `ns1.dns-parking.com` | 19 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `itjobdesire.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmailoffer.com`, `jobrequires.com`, `jobsdesire.com`, `myemailjobs.com`, `myhotmail.net`, `myitjobmails.com`, … (+7 more) |
| `ns2.dns-parking.com` | 19 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `itjobdesire.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmailoffer.com`, `jobrequires.com`, `jobsdesire.com`, `myemailjobs.com`, `myhotmail.net`, `myitjobmails.com`, … (+7 more) |
| `norm.ns.cloudflare.com` | 12 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `mailactiv.com`, `mailmessage.co`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, `tivomail.com`, `truemailhost.net`, `webpostbox.net` |
| `colette.ns.cloudflare.com` | 12 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `mailactiv.com`, `mailmessage.co`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, `tivomail.com`, `truemailhost.net`, `webpostbox.net` |
| `ns9.wixdns.net` | 10 | `careerwebmail.com`, `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `work-mail.net`, `workwebmail.com` |
| `ns8.wixdns.net` | 10 | `careerwebmail.com`, `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `work-mail.net`, `workwebmail.com` |
| `ns-cloud-a2.googledomains.com` | 8 | `career2026.com`, `careeremail.net`, `hcmconsultingpro.com`, `itworkmail.net`, `phoenixglide.com`, `quantumzens.com`, `tasksmail.com`, `workitmail.com` |
| `ns-cloud-a3.googledomains.com` | 8 | `career2026.com`, `careeremail.net`, `hcmconsultingpro.com`, `itworkmail.net`, `phoenixglide.com`, `quantumzens.com`, `tasksmail.com`, `workitmail.com` |

*115 further clusters of this type in `output/pivot_clusters.json`.*

### Shared retained registrant state/country
*Attribution strength: low-medium — independent of hosting, but shared by a whole population*

| Selector | Domains | Members |
|---|---|---|
| `US|NY` | 25 | `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailjethub.com`, `mailzoomexpress.com`, `mailzoomhub.com`, … (+13 more) |
| `US|TX` | 15 | `applyitmail.com`, `jobsitmail.com`, `myitemail.com`, `myitemailapp.com`, `myjobitapp.com`, `myjobtechmail.com`, `tasksemail.com`, `tasksmail.com`, `techemailapp.com`, `workapplyjob.com`, `workemailapply.com`, `workitmail.com`, … (+3 more) |
| `IN|Gujarat` | 14 | `career2026.com`, `careeremail.net`, `itworkmail.net`, `jobemail.net`, `jobemails24.com`, `jobmails.net`, `jobtecmail.net`, `mycareermail.com`, `mycvwork.com`, `myprofiley.com`, `myuswork.com`, `techcareermail.com`, … (+2 more) |
| `GB|East Sussex` | 13 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `mailactiv.com`, `mailboxcore.com`, `mailmessage.co`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, `tivomail.com`, `truemailhost.net`, … (+1 more) |
| `NL|?` | 7 | `career-techmail.com`, `careermails.com`, `carrermail.com`, `cvejobs.com`, `jobrequires.com`, `jobsdesire.com`, `quopost.com` |
| `US|FL` | 6 | `blazepinnacle.com`, `mailbluff.com`, `phoenixglide.com`, `pulsearcana.com`, `pulsedynamo.com`, `terraquasar.com` |
| `US|CA` | 5 | `jobhuntmails.com`, `mailflux.com`, `mywebemails.com`, `passmail.com`, `risemail.com` |
| `GB|Leicestershire` | 5 | `careermails.net`, `elitecandidates.com`, `nextstepcareer.net`, `swiftmailhost.com`, `topcandidate.co` |
| `CH|?` | 5 | `passinbox.com`, `passmail.net`, `pm.me`, `proton.me`, `protonmail.com` |
| `UY|Florida` | 3 | `celestialflare.com`, `quantumzens.com`, `zenithstellar.com` |
| `AU|Victoria` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |
| `IN|Maharashtra` | 2 | `careerwebmails.com`, `my-privatemail.com` |

*1 further clusters of this type in `output/pivot_clusters.json`.*

### Same registrar, same registry last-changed day
*Attribution strength: low — control-tested per batch in section 3.2*

| Selector | Domains | Members |
|---|---|---|
| `Squarespace (ex-Google Domains)|2025-10-17` | 15 | `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailzoomexpress.com`, `postmailpro.com`, `propostbox.com`, `quickpostmail.com`, `rapidinboxpro.com`, `rapidmailpost.com`, `rapidposthub.com`, … (+3 more) |
| `Hostinger|2026-02-02` | 5 | `itjobdesire.com`, `itresumejobs.com`, `newjobdesire.com`, `newjobrequire.com`, `newjobshunt.com` |
| `Squarespace (ex-Google Domains)|2025-10-10` | 5 | `couriermailhub.com`, `letterinboxpro.com`, `messagehubplus.com`, `promailcenter.com`, `swiftcouriermail.com` |
| `GoDaddy|2026-03-19` | 4 | `itjobmail.com`, `mailsworks.com`, `myemailjob.com`, `worksemails.com` |
| `Squarespace (ex-Google Domains)|2026-03-04` | 4 | `jobemail.net`, `mycareermail.com`, `techcareermail.com`, `techjobsemail.net` |
| `Cloudflare|2026-01-21` | 4 | `mailboxcore.com`, `rapidmailhost.com`, `smartmailhost.net`, `tivomail.com` |
| `GoDaddy|2025-08-12` | 3 | `mailmywork.com`, `myjobsmails.com`, `techsmail.com` |
| `Cloudflare|2026-06-04` | 3 | `careermails.net`, `elitecandidates.com`, `swiftmailhost.com` |
| `GoDaddy|2025-01-06` | 3 | `jobitwork.com`, `myjobitmail.com`, `quickitmail.com` |
| `GoDaddy|2025-11-03` | 3 | `mailjobhub.com`, `myjobscouts.com`, `savemymails.com` |
| `GoDaddy|2025-08-26` | 3 | `careersmails.com`, `mycareersjobs.com`, `mymailjob.com` |
| `Realtime Register B.V.|2025-11-25` | 3 | `carrermail.com`, `jobrequires.com`, `jobsdesire.com` |

*26 further clusters of this type in `output/pivot_clusters.json`.*

### Shared hosting BGP prefix
*Attribution strength: low*

| Selector | Domains | Members |
|---|---|---|
| `198.185.159.0/24` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `198.49.23.0/24` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `15.197.144.0/20` | 32 | `ajobguide.com`, `careerattainment.com`, `careeritjob.com`, `careernb.com`, `careersmails.com`, `cvmailhub.com`, `jobinboxhub.com`, `jobitmail.com`, `jobsmailbox.com`, `jobsmails.com`, `jobstechmail.com`, `jobsupp.com`, … (+20 more) |
| `3.33.128.0/20` | 32 | `ajobguide.com`, `careerattainment.com`, `careeritjob.com`, `careernb.com`, `careersmails.com`, `cvmailhub.com`, `jobinboxhub.com`, `jobitmail.com`, `jobsmailbox.com`, `jobsmails.com`, `jobstechmail.com`, `jobsupp.com`, … (+20 more) |
| `13.248.240.0/20` | 27 | `careermailus.com`, `cvtechmail.com`, `glidemail.io`, `itcareerinfo.com`, `itjobmail.com`, `itjobworks.com`, `jobitwork.com`, `jobstechmails.com`, `jobtechmail.com`, `jobtechsmail.com`, `mailjobtech.com`, `mailmywork.com`, … (+15 more) |
| `76.223.96.0/20` | 27 | `careermailus.com`, `cvtechmail.com`, `glidemail.io`, `itcareerinfo.com`, `itjobmail.com`, `itjobworks.com`, `jobitwork.com`, `jobstechmails.com`, `jobtechmail.com`, `jobtechsmail.com`, `mailjobtech.com`, `mailmywork.com`, … (+15 more) |
| `2.57.91.0/24` | 19 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `i-mail.in`, `itjobdesire.com`, `itjobemails.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmaildesk.com`, `jobmailoffer.com`, `jobrequires.com`, `jobsdesire.com`, … (+7 more) |
| `185.230.63.0/24` | 10 | `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `34.148.0.0/14` | 7 | `careerwebmail.com`, `jobhuntmails.com`, `mymailsbox.net`, `mywebemails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `2606:4700:3030::/48` | 4 | `careerx.us`, `passinbox.com`, `passmail.net`, `wgcv.me` |
| `176.119.200.0/24` | 4 | `pm.me`, `proton.me`, `protonmail.ch`, `protonmail.com` |
| `185.70.42.0/24` | 4 | `pm.me`, `proton.me`, `protonmail.ch`, `protonmail.com` |

*30 further clusters of this type in `output/pivot_clusters.json`.*

### Shared MX host
*Attribution strength: low — vendor-level*

| Selector | Domains | Members |
|---|---|---|
| `alt1.aspmx.l.google.com` | 69 | `applyme.co`, `blazepinnacle.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `celestialflare.com`, `championtalentco.com`, `cometmailhub.com`, `couriermailhub.com`, `cvmailhub.com`, `digitalexpress.co.uk`, `expressinboxmail.com`, … (+57 more) |
| `aspmx.l.google.com` | 69 | `applyme.co`, `blazepinnacle.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `celestialflare.com`, `championtalentco.com`, `cometmailhub.com`, `couriermailhub.com`, `cvmailhub.com`, `digitalexpress.co.uk`, `expressinboxmail.com`, … (+57 more) |
| `alt2.aspmx.l.google.com` | 68 | `applyme.co`, `blazepinnacle.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `celestialflare.com`, `championtalentco.com`, `cometmailhub.com`, `couriermailhub.com`, `cvmailhub.com`, `digitalexpress.co.uk`, `expressinboxmail.com`, … (+56 more) |
| `alt3.aspmx.l.google.com` | 66 | `applyme.co`, `blazepinnacle.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `celestialflare.com`, `championtalentco.com`, `cometmailhub.com`, `couriermailhub.com`, `cvmailhub.com`, `digitalexpress.co.uk`, `expressinboxmail.com`, … (+54 more) |
| `alt4.aspmx.l.google.com` | 65 | `applyme.co`, `blazepinnacle.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `celestialflare.com`, `championtalentco.com`, `cometmailhub.com`, `couriermailhub.com`, `cvmailhub.com`, `digitalexpress.co.uk`, `expressinboxmail.com`, … (+53 more) |
| `smtp.google.com` | 41 | `ajobguide.com`, `applyitmail.com`, `career2026.com`, `careeritjob.com`, `cvtechmail.com`, `hcmconsultingpro.com`, `itjobworks.com`, `itworkmail.net`, `jobemails24.com`, `jobhuntus.com`, `jobinboxhub.com`, `jobitwork.com`, … (+29 more) |
| `aspmx2.migadu.com` | 14 | `boxmailhere.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailmessage.co`, `nextstepcareer.net`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, `swiftmailhost.com`, `tivomail.com`, … (+2 more) |
| `aspmx1.migadu.com` | 14 | `boxmailhere.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailmessage.co`, `nextstepcareer.net`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, `swiftmailhost.com`, `tivomail.com`, … (+2 more) |
| `SMTP.GOOGLE.com` | 13 | `aogjob.com`, `carrermail.com`, `cvejobs.com`, `itjobdesire.com`, `itjobemails.com`, `jobmailoffer.com`, `jobrequires.com`, `myemailjobs.com`, `newjobdesire.com`, `newjobrequire.com`, `newjobshunt.com`, `sharemejobs.com`, … (+1 more) |
| `inbound-smtp.us-east-1.amazonaws.com` | 6 | `eprivatemail.com`, `jobmail.io`, `mailflyn.com`, `my-privatemail.com`, `skymail.ai`, `sorce.email` |
| `mail.protonmail.ch` | 5 | `pm.me`, `proton.me`, `protonmail.ch`, `protonmail.com`, `wgcv.me` |
| `mailsec.protonmail.ch` | 5 | `pm.me`, `proton.me`, `protonmail.ch`, `protonmail.com`, `wgcv.me` |

*21 further clusters of this type in `output/pivot_clusters.json`.*

### Shared SPF include
*Attribution strength: low — vendor-level*

| Selector | Domains | Members |
|---|---|---|
| `_spf.google.com` | 82 | `ajobguide.com`, `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `careeritjob.com`, `careermailus.com`, `careernb.com`, `championtalentco.com`, `couriermailhub.com`, `cvtechmail.com`, `expressinboxmail.com`, `fastmailzoom.com`, … (+70 more) |
| `spf.protection.outlook.com` | 24 | `ajoy2consult.com`, `careerattainment.com`, `careeremail.net`, `ebsworksite.com`, `jobemail.net`, `jobemails.net`, `jobhuntmails.com`, `mail.mcgill.ca`, `mail.utoronto.ca`, `mainewoodproducts.com`, `mycareermail.com`, `mycareersmail.com`, … (+12 more) |
| `spf.migadu.com` | 15 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailboxcore.com`, `mailmessage.co`, `nextstepcareer.net`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, … (+3 more) |
| `secureserver.net` | 12 | `careeritjob.com`, `ebsworksite.com`, `insightfulworkplace.com`, `jobslink-inc.com`, `jobstechmail.com`, `jobstechmails.com`, `jobsupp.com`, `jobtechmail.com`, `jobtechsmail.com`, `mailjobtech.com`, `techjobmail.com`, `thetalentarc.co.uk` |
| `amazonses.com` | 7 | `careerio-aa.com`, `jobmail.io`, `mailflyn.com`, `my-privatemail.com`, `mysecuremail.co`, `neuronmail.io`, `skymail.ai` |
| `mailgun.org` | 6 | `careermails.com`, `contactbox.io`, `inboxhere.com`, `myprivatemail.io`, `quopost.com`, `risemail.com` |
| `_spf.mx.cloudflare.net` | 3 | `inboxhere.com`, `inboxhires.com`, `mailbluff.com` |
| `_spf.protonmail.ch` | 3 | `pm.me`, `protonmail.ch`, `wgcv.me` |
| `spf.messagingengine.com` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |
| `simplelogin.co` | 3 | `passinbox.com`, `passmail.com`, `passmail.net` |
| `spf.tutanota.de` | 3 | `keemail.me`, `tuta.io`, `tutanota.com` |
| `162.0.237.182` | 2 | `aogjob.com`, `jobhuntus.com` |

### Registrar of record
*Attribution strength: very low — vendor-level only (section 3.1)*

| Selector | Domains | Members |
|---|---|---|
| `GoDaddy` | 78 | `ajobguide.com`, `ajoy2consult.com`, `aogjob.com`, `applyme.co`, `careerattainment.com`, `careeritjob.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `careerx.us`, `cvmailhub.com`, `cvtechmail.com`, … (+66 more) |
| `Squarespace (ex-Google Domains)` | 66 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `careeremail.net`, `celestialflare.com`, `championtalentco.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, … (+54 more) |
| `Cloudflare` | 21 | `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailbluff.com`, `mailboxcore.com`, `mailflux.com`, `mailmessage.co`, `my-privatemail.com`, `nextstepcareer.net`, … (+9 more) |
| `Hostinger` | 17 | `i-mail.in`, `itjobdesire.com`, `itjobemails.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmailoffer.com`, `myemailjobs.com`, `myhotmail.net`, `myitjobmails.com`, `myjobemails.com`, `myjobsca.com`, `newjobdesire.com`, … (+5 more) |
| `Wix` | 11 | `careerwebmail.com`, `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `Namecheap` | 10 | `careermail.pro`, `duck.com`, `hirehub.careers`, `jobmail.io`, `jobslink-inc.com`, `ohmymail.net`, `pxdmail.com`, `skymail.ai`, `thejobtec.com`, `wgcv.me` |
| `MarkMonitor` | 6 | `passinbox.com`, `passmail.com`, `passmail.net`, `pm.me`, `proton.me`, `protonmail.com` |
| `Tucows` | 6 | `hushmail.com`, `jgcareers.com`, `londondesignworks.com`, `neuronmail.io`, `oxfordnetworks.net`, `sharmasmail.com` |
| `Realtime Register B.V.` | 5 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `jobrequires.com`, `jobsdesire.com` |
| `Gandi` | 4 | `fastmail.com`, `fastmail.net`, `mailflyn.com`, `pobox.com` |
| `INWX GmbH` | 4 | `keemail.me`, `posteo.net`, `tuta.io`, `tutanota.com` |
| `NameWeb BVBA` | 2 | `careermails.com`, `quopost.com` |

*3 further clusters of this type in `output/pivot_clusters.json`.*

### Shared hosting ASN
*Attribution strength: very low — vendor-level only*

| Selector | Domains | Members |
|---|---|---|
| `AS16509` | 74 | `ajobguide.com`, `careerattainment.com`, `careeritjob.com`, `careermail.pro`, `careermails.com`, `careermailus.com`, `careernb.com`, `careersmails.com`, `contactbox.io`, `cvmailhub.com`, `cvtechmail.com`, `eprivatemail.com`, … (+62 more) |
| `AS53831` | 57 | `applyitmail.com`, `blazepinnacle.com`, `career2026.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `hcmconsultingpro.com`, `inboxflashpro.com`, `itworkmail.net`, … (+45 more) |
| `AS47583` | 21 | `career-techmail.com`, `carrermail.com`, `cvejobs.com`, `i-mail.in`, `itjobdesire.com`, `itjobemails.com`, `itjobinbox.com`, `itresumejobs.com`, `jobmaildesk.com`, `jobmailoffer.com`, `jobrequires.com`, `jobsdesire.com`, … (+9 more) |
| `AS13335` | 16 | `aogjob.com`, `careerx.us`, `fastmail.com`, `hushmail.com`, `inboxhere.com`, `inboxhires.com`, `jobemails.net`, `jobhuntus.com`, `mailflux.com`, `myjobsemail.com`, `myjobsinbox.com`, `passinbox.com`, … (+4 more) |
| `AS58182` | 10 | `jobemails.net`, `jobhuntmails.com`, `myjobsemail.com`, `myjobsinbox.com`, `mymailsbox.net`, `mywebemails.com`, `myworkmails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `AS396982` | 7 | `careerwebmail.com`, `jobhuntmails.com`, `mymailsbox.net`, `mywebemails.com`, `sharpcareerimage.com`, `work-mail.net`, `workwebmail.com` |
| `AS62371` | 4 | `pm.me`, `proton.me`, `protonmail.ch`, `protonmail.com` |
| `AS15169` | 3 | `ajoy2consult.com`, `jgcareers.com`, `myitjobmails.com` |
| `AS22612` | 3 | `jobmail.io`, `ohmymail.net`, `thejobtec.com` |
| `AS209242` | 3 | `hushmail.com`, `insightfulworkplace.com`, `mainewoodproducts.com` |
| `AS151847` | 3 | `fastmail.com`, `fastmail.net`, `pobox.com` |
| `AS210909` | 3 | `keemail.me`, `tuta.io`, `tutanota.com` |

*3 further clusters of this type in `output/pivot_clusters.json`.*

## 7. Linked operator groups

Single selectors are merged into connected components using **account-level selectors only** — a DKIM public key, an SPF-management tenant id, a DMARC reporting-platform account, a provider verification token, a disclosed registrant organisation, or reverse DNS on a host that is not a hosting vendor's shared estate. Vendor-level facts (registrar, shared MX, parking IPs, provider reverse DNS) and registration timing are attached as corroboration but never used to link. Members found by the expansion sweep (section 9) are folded in and marked.

**6 groups covering 52 of 263 source-list domains, plus 5 expansion-confirmed members.**

### Group 1 — 31 domains

**Linking evidence:** `spfm:aa8e722993`

| Attribute | Value |
|---|---|
| Registrar | GoDaddy (27) |
| Registered | 2012-05-24 → 2026-04-22 (5081 days; 14 of 31 in 5 bursts) |
| Registrant | Domains By Proxy (GoDaddy) (22), no registrar-side record (5) |
| Registrant geo (retained) | none retained |
| Abuse contact | `abuse@godaddy.com` |
| DNS operator | GoDaddy (25), none (2) |
| Mail provider | Google Workspace (22), none (5) |
| SOA responsible party | `dns.jomax.net` (23) |
| Hosting IPs | `15.197.148.33` (14), `3.33.130.190` (14), `13.248.243.5` (13), `76.223.105.230` (13) |
| DMARC policy | none-published (16), none (6), quarantine (5) |
| Risk tier | medium (22), high (5) |
| Naming theme | job_career_work_it_cv_themed (22), synthetic_generic_mailbox_brand (4), privacy_alias_mailbox (1) |

**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):

| Registered | Domain | Registrar |
|---|---|---|
| 2012-05-24 | `hiremails.com` ★ | GoDaddy |
| 2020-05-17 | `sorce.io` ★ | GoDaddy |
| 2023-08-09 | `careernb.com` | GoDaddy |
| 2023-10-02 | `cvmailhub.com` | GoDaddy |
| 2024-02-29 | `mymailworks.com` | GoDaddy |
| 2024-03-12 | `mycvtalent.com` | GoDaddy |
| 2024-03-14 | `worksemails.com` | GoDaddy |
| 2024-03-14 | `itjobmail.com` | GoDaddy |
| 2024-03-14 | `mailsworks.com` | GoDaddy |
| 2024-03-14 | `myemailjob.com` | GoDaddy |
| 2024-05-15 | `techjobmail.com` | GoDaddy |
| 2024-06-25 | `mycvscout.com` | GoDaddy |
| 2024-07-17 | `thetechbox.co` ★ | GoDaddy |
| 2024-07-29 | `jobtechmail.com` | GoDaddy |
| 2024-08-06 | `jobitmail.com` | GoDaddy |
| 2024-09-25 | `mailmywork.com` | GoDaddy |
| 2024-09-25 | `techsmail.com` | GoDaddy |
| 2024-09-25 | `myjobsmails.com` | GoDaddy |
| 2024-10-23 | `mymailkeeper.com` | GoDaddy |
| 2025-01-28 | `jobsmails.com` | GoDaddy |
| 2025-02-05 | `protectmymails.com` | GoDaddy |
| 2025-06-18 | `worksemail.com` | GoDaddy |
| 2025-08-26 | `mymailjob.com` | GoDaddy |
| 2025-08-26 | `careersmails.com` | GoDaddy |
| 2025-08-26 | `mycareersjobs.com` | GoDaddy |
| 2025-11-03 | `myjobscouts.com` | GoDaddy |
| 2025-11-03 | `savemymails.com` | GoDaddy |
| 2026-01-21 | `thepromail.co` | GoDaddy |
| 2026-04-22 | `mypostwork.com` ★ | GoDaddy |
| 2026-04-22 | `techmyjob.com` | GoDaddy |
| 2026-04-22 | `mailscareer.com` | GoDaddy |

Bursts: 2024-03-14T20:48:58Z (5s) — `worksemails.com`, `itjobmail.com`, `mailsworks.com`, `myemailjob.com`; 2024-09-25T18:21:26Z (5s) — `mailmywork.com`, `techsmail.com`, `myjobsmails.com`; 2025-08-26T19:01:36Z (32s) — `mymailjob.com`, `careersmails.com`, `mycareersjobs.com`; 2025-11-03T14:56:38Z (1s) — `myjobscouts.com`, `savemymails.com`; 2026-04-22T20:53:08Z (4s) — `techmyjob.com`, `mailscareer.com`

**Registered in the same checkout as a member but carrying no group marker** — leads for the marker probe, not members:

| Domain | Burst (UTC) | Span | Alongside |
|---|---|---|---|
| `mycvhire.com` | 2024-03-12T20:34:55Z | 357s | `mycvtalent.com` |
| `cvtechmail.com` | 2024-05-15T19:31:39Z | 2s | `techjobmail.com` |
| `ajobguide.com` | 2024-06-25T16:01:13Z | 39s | `mycvscout.com` |
| `careeritjob.com` | 2024-07-29T21:51:20Z | 47s | `jobtechmail.com` |
| `themailpad.com` | 2024-10-23T17:30:22Z | 3s | `mymailkeeper.com` |
| `mymailshub.com` | 2025-02-05T16:14:06Z | 0s | `protectmymails.com` |
| `mailjobhub.com` | 2025-11-03T14:56:38Z | 4s | `myjobscouts.com`, `savemymails.com` |

### Group 2 — 16 domains

**Linking evidence:** `uriports:p7rqadcw`

| Attribute | Value |
|---|---|
| Registrar | Cloudflare (15) |
| Registered | 2025-05-23 → 2026-06-04 (376 days; 9 of 16 in 3 bursts) |
| Registrant | redacted (15) |
| Registrant geo (retained) | GB / East Sussex (11), GB / Leicestershire (4) |
| Abuse contact | `registrar-abuse@cloudflare.com` |
| DNS operator | Cloudflare (13), none (2) |
| Mail provider | Google Workspace (11), none (4) |
| SOA responsible party | `dns.cloudflare.com` (13) |
| Hosting IPs |  |
| DMARC policy | quarantine (15) |
| Risk tier | medium (8), low (7) |
| Naming theme | synthetic_generic_mailbox_brand (11), job_career_work_it_cv_themed (4) |

**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):

| Registered | Domain | Registrar |
|---|---|---|
| 2025-05-23 | `boxmailhere.com` | Cloudflare |
| 2025-09-12 | `truemailhost.net` | Cloudflare |
| 2025-11-11 | `pulsemailbox.com` | Cloudflare |
| 2025-11-11 | `boxmailhost.com` | Cloudflare |
| 2025-11-22 | `mailactiv.com` | Cloudflare |
| 2025-11-22 | `activemails.net` | Cloudflare |
| 2025-11-22 | `swiftemail.co` | Cloudflare |
| 2026-01-21 | `rapidmailhost.com` | Cloudflare |
| 2026-01-21 | `mailboxcore.com` | Cloudflare |
| 2026-01-21 | `tivomail.com` | Cloudflare |
| 2026-01-21 | `smartmailhost.net` | Cloudflare |
| 2026-03-25 | `topcandidate.co` | Cloudflare |
| 2026-03-25 | `nextstepcareer.net` | Cloudflare |
| 2026-06-04 | `elitecandidates.com` | Cloudflare |
| 2026-06-04 | `careermails.net` | Cloudflare |
| 2026-06-04 | `primemailhost.com` ★ | Cloudflare |

Bursts: 2026-01-21T02:01:52Z (197s) — `rapidmailhost.com`, `mailboxcore.com`, `tivomail.com`, `smartmailhost.net`; 2026-06-04T08:48:52Z (269s) — `elitecandidates.com`, `careermails.net`, `primemailhost.com`; 2025-11-22T17:26:55Z (43s) — `mailactiv.com`, `activemails.net`

**Registered in the same checkout as a member but carrying no group marker** — leads for the marker probe, not members:

| Domain | Burst (UTC) | Span | Alongside |
|---|---|---|---|
| `swiftmailhost.com` | 2026-06-04T08:48:52Z | 425s | `elitecandidates.com`, `careermails.net`, `primemailhost.com` |

### Group 3 — 3 domains

**Linking evidence:** `ondmarc:e3936a44`

| Attribute | Value |
|---|---|
| Registrar | Gandi (3) |
| Registered | 1994-12-09 → 2002-08-05 (2796 days; 0 of 3 in 0 bursts) |
| Registrant | redacted (3) |
| Registrant geo (retained) | AU / Victoria (3) |
| Abuse contact | `abuse@support.gandi.net` |
| DNS operator | messagingengine.com (3) |
| Mail provider | Fastmail (3) |
| SOA responsible party | `postmaster.messagingengine.com` (3) |
| Hosting IPs | `103.168.172.37` (3), `103.168.172.52` (3), `103.168.172.65` (3), `103.168.172.38` (1), `103.168.172.39` (1), `103.168.172.53` (1) |
| DMARC policy | none (3) |
| Risk tier | low (3) |
| Naming theme | privacy_alias_mailbox (3) |

**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):

| Registered | Domain | Registrar |
|---|---|---|
| 1994-12-09 | `fastmail.com` | Gandi |
| 1995-01-05 | `pobox.com` | Gandi |
| 2002-08-05 | `fastmail.net` | Gandi |

### Group 4 — 3 domains

**Linking evidence:** `dkim:dkim:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJudTILTG3qrzQzZzbptozaGQ0`

| Attribute | Value |
|---|---|
| Registrar | MarkMonitor (3) |
| Registered | 2018-05-13 → 2023-02-11 (1734 days; 0 of 3 in 0 bursts) |
| Registrant | redacted (2), disclosed (1) |
| Registrant geo (retained) | CH (2), US / CA (1) |
| Abuse contact | `abusecomplaints@markmonitor.com` |
| DNS operator | Cloudflare (3) |
| Mail provider | self/other (simplelogin.co) (3) |
| SOA responsible party | `dns.cloudflare.com` (2) |
| Hosting IPs | `104.21.34.220` (1), `172.67.209.190` (1), `2606:4700:3030::6815:22dc` (1), `2606:4700:3032::ac43:d1be` (1), `104.21.15.227` (1), `172.67.208.40` (1) |
| DMARC policy | quarantine (3) |
| Risk tier | low (3) |
| Naming theme | privacy_alias_mailbox (2), synthetic_generic_mailbox_brand (1) |

**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):

| Registered | Domain | Registrar |
|---|---|---|
| 2018-05-13 | `passmail.com` | MarkMonitor |
| 2023-02-10 | `passmail.net` | MarkMonitor |
| 2023-02-11 | `passinbox.com` | MarkMonitor |

### Group 5 — 2 domains

**Linking evidence:** `ptr:sites.framer.app`

| Attribute | Value |
|---|---|
| Registrar | GoDaddy (2) |
| Registered | 2024-09-17 → 2025-01-23 (127 days; 0 of 2 in 0 bursts) |
| Registrant | Domains By Proxy (GoDaddy) (2) |
| Registrant geo (retained) | none retained |
| Abuse contact | `abuse@godaddy.com` |
| DNS operator | GoDaddy (1), Cloudflare (1) |
| Mail provider | self/other (amazonaws.com) (1), Bulk/ESP (1) |
| SOA responsible party | `dns.jomax.net` (1) |
| Hosting IPs | `31.43.160.6` (2), `31.43.161.6` (2), `35.71.142.77` (1), `52.223.52.2` (1) |
| DMARC policy | none (1), none-published (1) |
| Risk tier | low (1), medium (1) |
| Naming theme | privacy_alias_mailbox (2) |

**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):

| Registered | Domain | Registrar |
|---|---|---|
| 2024-09-17 | `eprivatemail.com` | GoDaddy |
| 2025-01-23 | `whisperpost.io` | GoDaddy |

### Group 6 — 2 domains

**Linking evidence:** `dkim:k2:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9`, `dkim:k3:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsYGiMSn7fsUqSvfSX40x`

| Attribute | Value |
|---|---|
| Registrar | GoDaddy (2) |
| Registered | 2010-11-30 → 2023-02-18 (4462 days; 0 of 2 in 0 bursts) |
| Registrant | Domains By Proxy (GoDaddy) (2) |
| Registrant geo (retained) | none retained |
| Abuse contact | `abuse@godaddy.com` |
| DNS operator | GoDaddy (2) |
| Mail provider | self/other (ppe-hosted.com) (1), Microsoft 365 (1) |
| SOA responsible party | `dns.jomax.net` (1) |
| Hosting IPs | `160.153.0.105` (1), `173.231.203.220` (1) |
| DMARC policy | none (2) |
| Risk tier | low (2) |
| Naming theme | job_career_work_it_cv_themed (1), synthetic_generic_mailbox_brand (1) |

**Registration timeline** (registry timestamps; ★ = expansion-confirmed member):

| Registered | Domain | Registrar |
|---|---|---|
| 2010-11-30 | `prorecresources.com` | GoDaddy |
| 2023-02-18 | `insightfulworkplace.com` | GoDaddy |

## 8. Registration cohorts outside the operator groups

Bursts whose members belong to no operator group. Timing at this resolution — several themed names created seconds apart at one registrar — is the registry-side trace of one shopping cart, and the control population shows how rarely it happens by chance. It is still not an account artefact, so these cohorts are kept separate from section 7 until a DKIM key, tenant id or disclosed registrant ties them.

### Squarespace synthetic-brand cohort — 32 domains

| Attribute | Value |
|---|---|
| Bursts | 2023-11-01T10:58:12Z (137s, n=6); 2023-10-25T21:24:46Z (569s, n=5); 2023-11-01T09:58:25Z (110s, n=5); 2023-10-31T22:34:23Z (94s, n=4); 2024-04-08T22:34:28Z (4s, n=3); 2024-04-16T11:23:28Z (7s, n=3); 2023-10-26T11:06:06Z (113s, n=2); 2023-10-31T21:44:48Z (5s, n=2); 2024-04-08T19:29:59Z (5s, n=2) |
| Naming theme | synthetic_generic_mailbox_brand (32) |
| DNS operator | NS1;Squarespace (27), Google Domains / Squarespace (3), none (2) |
| Mail provider | Google Workspace (30), none (2) |
| Hosting IPs | `198.185.159.144` (30), `198.185.159.145` (30), `198.49.23.144` (30), `198.49.23.145` (30) |
| Registrant | redacted (32) |
| Registrant geo (retained) | US / NY (24), US / FL (5), UY / Florida (3) |
| Abuse contact | `abuse-complaints@squarespace.com` |

**Members:** `blazepinnacle.com`, `celestialflare.com`, `cometmailhub.com`, `couriermailhub.com`, `expressinboxmail.com`, `fastmailzoom.com`, `flashpostmail.com`, `inboxflashpro.com`, `letterinboxpro.com`, `mailblitzhub.com`, `mailflashpro.com`, `mailjethub.com`, `mailzoomexpress.com`, `mailzoomhub.com`, `messagehubplus.com`, `phoenixglide.com`, `postmailpro.com`, `promailcenter.com`, `propostbox.com`, `pulsearcana.com`, `pulsedynamo.com`, `quantumzens.com`, `quickpostmail.com`, `rapidinboxpro.com`, `rapidmailpost.com`, `rapidposthub.com`, `speedmailhub.com`, `speedymailpost.com`, `swiftcouriermail.com`, `swiftinboxmail.com`, `terraquasar.com`, `zenithstellar.com`

### Squarespace job-themed cohort (Google Domains DNS) — 5 domains

| Attribute | Value |
|---|---|
| Bursts | 2023-03-04T11:33:30Z (6s, n=5) |
| Naming theme | job_career_work_it_cv_themed (5) |
| DNS operator | Google Domains / Squarespace (5) |
| Mail provider | Microsoft 365 (5) |
| Hosting IPs |  |
| Registrant | redacted (5) |
| Registrant geo (retained) | IN / Gujarat (5) |
| Abuse contact | `abuse-complaints@squarespace.com` |

**Members:** `careeremail.net`, `jobemail.net`, `mycareermail.com`, `techcareermail.com`, `techjobsemail.net`

Control-population names registered in the same checkout (leads, not members): `cvemail.net`, `mycvemail.com`, `workmails.net`.

### Other bursts

| Registrar | Start (UTC) | Span | Members | DNS operator | Hosting |
|---|---|---|---|---|---|
| GoDaddy | 2025-01-06T21:41:54Z | 43s | `jobitwork.com`, `myjobitmail.com`, `quickitmail.com` | GoDaddy (3) | `15.197.148.33` |
| Hostinger | 2025-01-31T20:55:06Z | 238s | `newjobrequire.com`, `newjobdesire.com`, `newjobshunt.com` | Hostinger (3) | `2.57.91.91` |
| Wix | 2024-05-13T18:46:53Z | 109s | `careerwebmail.com`, `mywebemails.com` | Wix (2) | `34.149.87.45` |
| Realtime Register B.V. | 2024-11-26T15:08:58Z | 513s | `jobrequires.com`, `jobsdesire.com` | Hostinger (2) | `2.57.91.91` |
| Hostinger | 2025-02-07T20:21:38Z | 171s | `itresumejobs.com`, `itjobdesire.com` | Hostinger (2) | `2.57.91.91` |
| GoDaddy | 2026-05-07T19:29:54Z | 281s | `jobsmailbox.com`, `jobinboxhub.com` | none (1), GoDaddy (1) | `15.197.148.33` |

## 9. Cluster expansion by DNS marker

Both large groups publish a marker that can be tested directly, so candidate names generated from the corpus naming grammar were checked for membership.

| Group | Marker tested | Candidates | Confirmed members |
|---|---|---|---|
| Group 1 | `dc-aa8e722993._spfm.<domain>` TXT exists | 20,227 | `hiremails.com`, `mypostwork.com`, `sorce.io`, `thetechbox.co` |
| Group 2 | `p7rqadcw.uriports.com` inside the DMARC record | 29,786 | `primemailhost.com` |

`primemailhost.com` matches Group 2 on every attribute — Cloudflare DNS and registrar, Migadu MX, `spf.migadu.com`, the same URIports account, and it was registered in the same 2026-06-04 burst as `elitecandidates.com` and `careermails.net`. `sorce.io` is a sibling of `sorce.email`, already in the source list.

Of the 639 registered candidates, the 617 that carried neither marker form the control population used throughout section 3.

## 10. Hypothesis tests and controls

Every batch or shared-selector finding was tested against a population that should *not* share it before it was believed. Verdicts:

| Hypothesis | Test | Result | Verdict |
|---|---|---|---|
| the 21 domains sharing zone-edit date 2026-08-20 were registered or configured as one batch | sampled 12 Hostinger-nameserver domains discovered by the expansion sweep that are unrelated to any cluster, and read their SOA serials | 12 of 12 controls carry the same 2026-08-20 serial | **FALSIFIED** — provider-wide serial bump, not operator activity |
| the 8 GoDaddy domains sharing zone-edit date 2026-02-05 were configured as one batch | sampled 79 GoDaddy-nameserver domains discovered by the expansion sweep that belong to no cluster, and read their SOA serials | 0 of 79 controls carry the 2026-02-05 serial; control dates are widely dispersed (most common is 2023-09-19 at 8 of 79) | **SURVIVES** — 2026-02-05 is not a GoDaddy-wide event, so the 8 domains share a genuine same-day configuration event |
| the 8 GoDaddy domains that share zone-edit date 2026-02-05 were registered together | read the RDAP registration date of each member | registration dates: `cvtechmail.com` 2024-05-15, `techjobmail.com` 2024-05-15, `careeritjob.com` 2024-07-29, `jobtechmail.com` 2024-07-29, `jobstechmail.com` 2024-12-10, `jobtechsmail.com` 2025-01-17, `jobstechmails.com` 2025-03-18, `mailjobtech.com` 2025-04-14 | **PARTIAL** — 2 of 8 registered on 2024-05-15; the rest were registered on other days and only reconfigured together on 2026-02-05 |
| Group 1 members were registered in bursts (same registrar, <= 10 min apart) | chain each member's registry registration timestamp with the group's other members at the same registrar; compare with the control-population burst share | 14 of 31 members sit in 5 intra-group burst(s); control-population burst share is 6.1% | **SUPPORTED** — 45% of the group vs 6.1% baseline |
| Group 2 members were registered in bursts (same registrar, <= 10 min apart) | chain each member's registry registration timestamp with the group's other members at the same registrar; compare with the control-population burst share | 9 of 16 members sit in 3 intra-group burst(s); control-population burst share is 6.1% | **SUPPORTED** — 56% of the group vs 6.1% baseline |
| registrar choice alone separates the corpus from unrelated themed domains | registrar share of the corpus against the control population | GoDaddy 31.8% vs 23.4% (lift 1.36); Squarespace (ex-Google Domains) 26.9% vs 4.4% (lift 6.09); Cloudflare 8.6% vs 3.9% (lift 2.2); Hostinger 6.9% vs 2.3% (lift 3.02); Wix 4.5% vs 0.2% (lift 25.37) | **PARTIAL** — Squarespace (ex-Google Domains) is 6.09x over-represented, Hostinger is 3.02x over-represented, Wix is 25.37x over-represented; still a mass-market registrar shared with the controls, so vendor-level and not used for linking |

Two false-positive modes in the marker sweep were controlled out before any expansion result was accepted. *Wildcard DNS*: parking providers (Afternic, Sedo, CashParking, NameFind) answer every subdomain, so a name-existence probe hits domains with no connection to the cluster; the uncontrolled first pass reported 71 'new members' including `pobox.co`, `proton.io` and `tuta.us`, and requiring the marker content to match the tenant's SPF rather than the parking default `v=spf1 -all`, plus random-label canaries, cut it to four. *Timeouts read as absence*: a canary lookup that fails is not proof of no wildcard; probes retry and only a definitive NXDOMAIN clears a zone. Group 2's hosting was likewise rejected as a marker: 12 of its members resolve `autoconfig.<domain>` to `141.94.97.141`, which is `autoconfig.migadu.com` — the mail vendor's shared host.

## 11. Certificate transparency

Certificate-transparency logs were checked for every corpus, expansion and lead domain and for the control population — 631 domains, 2096 distinct certificates. A certificate whose SANs span two or more different registrable domains is an account-level link: one party proved control of all of them to the CA in a single request, the same attribution strength as a shared DKIM key. Multi-tenant vendor and SaaS certificates (a CDN, website builder, CRM or mail provider packing unrelated customers onto one certificate) and the reference-set providers' own estates are identified and excluded from linking.

### 11.1 The operator groups do not share certificates

| Group | Members | With a certificate | Certs spanning ≥2 members |
|---|---|---|---|
| Group 1 | 27 | 20 | 0 |
| Group 2 | 15 | 11 | 0 |
| Group 3 | 3 | 1 | 0 |
| Group 4 | 3 | 3 | 2 |
| Group 5 | 2 | 2 | 0 |
| Group 6 | 2 | 1 | 0 |

No certificate links two members of Group 1, 2, 3, 5, 6. Every member sits on shared parking or CDN infrastructure and receives its own per-domain certificate, so the certificate channel adds no members to the operator groups and merges none of them — a negative result that corroborates the commodity-infrastructure reading of sections 6 and 7. The only intra-group spanning certificates belong to Group 4, and they are the reference-set provider's own (a SimpleLogin/Proton alias estate), not an operator artefact.

### 11.2 Corpus domains with a shared certificate

Only 2 corpus/lead domains share a certificate with any other registrable domain, and both resolve to established, unrelated businesses — benign names the mail/career grammar swept into the source list, now positively identified through the company they share a certificate with:

| Corpus/lead domain(s) | Shared-certificate siblings | Reading |
|---|---|---|
| `oxfordnetworks.com`, `oxfordnetworks.net` | `186comm.net`, `bayring.com`, `firstlight.net`, `firstlight.systems`, `firstlightcloud.net`, `fltg.com`, … (+1 more) | shares certificates with an established company's own domains — a benign inclusion |
| `restartworks.com` | `boltonservicegroup.com`, `optimum-financial.com`, `slatefinancialsolutions.com` | shares a GoDaddy multi-tenant certificate with unrelated small-business sites — a benign inclusion |

### 11.3 The control population is not made of singletons

Among the control domains the certificate pivot finds 15 shared-certificate clusters: 8 are bulk shared-hosting certificates (one control domain packed onto a reseller's certificate beside dozens of unrelated tenants) and the rest are small.
 One is a coherent operation of its own: `careersemail.com`, `thecareermail.com` ride shared Let's Encrypt certificates with 18 job-alert siblings not in the source list (`careeralert.co.uk`, `careeralertme.co.uk`, `careeremail.co.uk`, `careersalert.co.uk`, `clickalerts.co.uk`, `jobboardalerts.co.uk`), each carrying dedicated `mail.` and `click.` sending hosts. That is the signature of an opt-in job-alert email sender — structurally unlike the disposable-mailbox clusters, and a reminder that some control domains belong to real operators. It means the control burst rate in section 3.2 is a conservative upper bound on chance, exactly as stated there.

## 12. Non-resolving, unregistered and malformed entries

10 of 263 entries returned no NS/SOA/A/MX. With registry data the reasons separate cleanly:

| Reason | Entries |
|---|---|
| Invalid TLD — parsing artefacts, not real names | `email.scued`, `gmail.com0`, `gmail.comlinkedin`, `gmail.om`, `mymail.pomona.edi` |
| Host labels under other organisations' domains, not registrable names | `mail.mcgill.ca`, `mail.utoronto.ca`, `mailjobhub.com.test-google-a.com`, `myjobscouts.com.test-google-a.com`, `protectmymails.com.test-google-a.com`, `themailpad.com.test-google-a.com`, `use.startmail.com` |
| Valid TLD, not registered (registry 404) | `myjobesmails.com`, `myworksmail.com`, `thejobmail.com` |
| Registered but not resolving | `careerwebmails.com` |
| Undetermined (`.co` registry unavailable, no registrar hit) | `cvtechmail.co`, `mysecuremail.co`, `privatemailbox.co` |

The 4 `*.test-google-a.com` entries are Google Workspace domain-alias test hosts, which the platform generates for a tenant's secondary domains. Their parents are `mailjobhub.com` (same-checkout lead for Group 1), `myjobscouts.com` (Group 1), `protectmymails.com` (Group 1), `themailpad.com` (same-checkout lead for Group 1). All four belonging to one Workspace tenant is consistent with the Group membership and the checkout leads in section 7, though the list itself does not prove which tenant generated them.

## 13. Per-domain detail

Full records are in `output/dns_enumeration.json` and `output/rdap_enumeration.json` (raw) and `output/domain_infrastructure.csv` (flat table). Summary of the highest-risk tier:

| Domain | Score | Registrar | Registered | Registrant | NS operator | Mail | DMARC | IPs |
|---|---|---|---|---|---|---|---|---|
| mailjobtech.com | 85 | GoDaddy | 2025-04-14 | Domains By Proxy | GoDaddy | Google Workspace | none | 13.248.243.5;76.223.105.230 |
| nextitjobs.com | 85 | GoDaddy | 2024-03-12 | Domains By Proxy | GoDaddy | Google Workspace | quarantine | 15.197.148.33;3.33.130.190 |
| itjobmail.com | 80 | GoDaddy | 2024-03-14 | Domains By Proxy | GoDaddy | Google Workspace | - | 13.248.243.5;76.223.105.230 |
| myjobemails.com | 75 | Hostinger | 2025-02-25 | redacted (registrar placeholder geo) | Hostinger | none | none | 2.57.91.91 |
| careeremail.net | 75 | Squarespace (ex-Google Domains) | 2023-03-04 | IN/Gujarat | Google Domains / Squarespace | Microsoft 365 | none | - |
| itjobinbox.com | 75 | Hostinger | 2024-09-18 | redacted (registrar placeholder geo) | Hostinger | Google Workspace | - | 2.57.91.91 |
| aogjob.com | 75 | GoDaddy | 2023-04-18 | Domains By Proxy | Cloudflare | Google Workspace | none | 104.21.67.4;172.67.167.105;2606:4700:3033::a |
| itjobworks.com | 75 | GoDaddy | 2025-06-23 | Domains By Proxy | GoDaddy | Google Workspace | - | 13.248.243.5;76.223.105.230 |
| jobstechmails.com | 75 | GoDaddy | 2025-03-18 | Domains By Proxy | GoDaddy | Google Workspace | none | 13.248.243.5;76.223.105.230 |
| myitjobmails.com | 75 | Hostinger | 2024-09-24 | redacted (registrar placeholder geo) | Hostinger | none | - | 2.57.91.91;2607:f8b0:4002:c10::65;2607:f8b0: |
| jobitmail.com | 75 | GoDaddy | 2024-08-06 | - | GoDaddy | Google Workspace | - | 15.197.148.33;3.33.130.190 |
| careerattainment.com | 70 | GoDaddy | 2024-07-17 | Domains By Proxy | GoDaddy | Microsoft 365 | none | 15.197.148.33;3.33.130.190 |
| myjobsmails.com | 70 | GoDaddy | 2024-09-25 | Domains By Proxy | GoDaddy | none | - | 13.248.243.5;76.223.105.230 |
| myworkmails.com | 70 | Wix | 2023-12-01 | - | Wix | Microsoft 365 | - | 185.230.63.107;185.230.63.171;185.230.63.186 |
| workwebmail.com | 70 | Wix | 2024-10-18 | - | Wix | Microsoft 365 | none | 185.230.63.107;185.230.63.171;185.230.63.186 |
| jobsmails.com | 70 | GoDaddy | 2025-01-28 | Domains By Proxy | GoDaddy | Google Workspace | - | 15.197.148.33;3.33.130.190 |
| techcareermail.com | 70 | Squarespace (ex-Google Domains) | 2023-03-04 | IN/Gujarat | Google Domains / Squarespace | Microsoft 365 | none | - |
| cvtechmail.com | 70 | GoDaddy | 2024-05-15 | Domains By Proxy | GoDaddy | Google Workspace | - | 13.248.243.5;76.223.105.230 |
| jobtechmail.com | 70 | GoDaddy | 2024-07-29 | Domains By Proxy | GoDaddy | Google Workspace | none | 13.248.243.5;76.223.105.230 |
| jobtechsmail.com | 70 | GoDaddy | 2025-01-17 | Domains By Proxy | GoDaddy | Google Workspace | none | 13.248.243.5;76.223.105.230 |
| workitmail.com | 70 | Squarespace (ex-Google Domains) | 2024-09-11 | US/TX | Google Domains / Squarespace | Google Workspace | - | 198.185.159.144;198.185.159.145;198.49.23.14 |
| jobsitmail.com | 70 | Squarespace (ex-Google Domains) | 2025-03-13 | US/TX | Google Domains / Squarespace | Google Workspace | - | 198.185.159.144;198.185.159.145;198.49.23.14 |
| workmailit.com | 70 | Squarespace (ex-Google Domains) | 2025-06-19 | US/TX | Google Domains / Squarespace | Google Workspace | - | 198.185.159.144;198.185.159.145;198.49.23.14 |

## 14. Method notes and limitations

**Enumeration depth.** The DNS pass used a 133-name subdomain wordlist and 55 DKIM selectors, retrieving 228 DKIM keys across 171 domains. 16 wildcard zones were detected and their probe results suppressed; the subdomain count in section 2 (364) reflects that suppression — an earlier figure of 603 counted wildcard answers. 19 zones are DNSSEC-signed and 5 use walkable NSEC; the Proton-operated ones return RFC 4470 white lies and only `runbox.no` yielded a real chain.

**Registration data.** Registry RDAP is authoritative for dates, status and delegation and was obtained for every gTLD and for `.io`, `.me`, `.us`, `.ch`, `.uk`, `.ca`, `.in` and `.no`. The `.co` registry answers *not found* for every name, including live ones, so `.co` records come from the sponsoring registrar's RDAP (found from the delegated nameservers) and their timestamps are registrar-side and excluded from burst analysis. `.ru` has WHOIS only. Registrar-side servers rate-limit; a slow second pass recovered the records the first pass lost, and any domain still lacking a registrar record has no registrant fields. Registrant identity is withheld almost everywhere; what survives is the proxy service (which identifies the registrar, not the registrant), the state/country some registrars retain, and the handful of organisations that were disclosed. Individuals' names, where a registrar published them, are kept in the raw evidence file only.

**Timing signals.** Registration timestamps are the primary timing signal. SOA serials, used before registration data was available, date the last zone edit and remain a configuration-batch signal only: the 2026-08-20 Hostinger batch was a provider-wide serial bump, and the 2026-02-05 GoDaddy batch, which survived its control test, turned out on registration dates to be a joint reconfiguration of domains registered in pairs across 2024-05 to 2025-04 — consistent with one operator accumulating permutations of a stem over time, but not the single registration event the serials suggested.

**Vendor estates.** Reverse DNS on AWS Global Accelerator instances, Google MX addresses, Migadu's autoconfig host and Squarespace's shared front end identify vendors, not customers, and are excluded from linking; the same applies to registrar choice and to registrar placeholder geography. Cloudflare's free-plan nameserver pairs are drawn from a shared pool and are not account-unique.

## Appendix — abuse contacts by group

| Group / cohort | Registrar | Abuse contact | Domains |
|---|---|---|---|
| Group 1 | GoDaddy | `abuse@godaddy.com` | 31 |
| Group 2 | Cloudflare | `registrar-abuse@cloudflare.com` | 16 |
| Group 3 | Gandi | `abuse@support.gandi.net` | 3 |
| Group 4 | MarkMonitor | `abusecomplaints@markmonitor.com` | 3 |
| Group 5 | GoDaddy | `abuse@godaddy.com` | 2 |
| Group 6 | GoDaddy | `abuse@godaddy.com` | 2 |
| Squarespace cohort | Squarespace | `abuse-complaints@squarespace.com` | 37 |

