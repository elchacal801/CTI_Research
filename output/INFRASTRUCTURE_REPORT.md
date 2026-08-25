# Domain Infrastructure Enumeration

**Generated:** 2026-08-25T21:17:09.032539+00:00  
**Source list:** `data/Domain_Summary_Reconstructed.csv` — 263 domains  
**Collection:** live DNS over UDP/53 against 1.1.1.1, 8.8.8.8, 9.9.9.9, 1.0.0.1, 8.8.4.4; ASN/BGP/country via the Team Cymru IP-to-ASN DNS service.

## 1. Collection scope and coverage

| Metric | Count |
|---|---|
| Domains in list | 263 |
| Resolving (have NS/SOA/A/MX) | 253 |
| Non-resolving / NXDOMAIN | 10 |
| With MX (mail-capable) | 223 |
| With SPF | 186 |
| With DMARC | 151 |
| With DKIM key found | 129 |
| With CAA | 15 |
| Unique IPs observed | 1207 |
| Unique ASNs | 49 |
| Subdomains discovered | 603 |

### RDAP / WHOIS status

Not collected in this environment. Outbound HTTPS to RDAP endpoints (`rdap.org`, `rdap.verisign.com`, registry RDAP servers) is refused by the session's egress policy with `403 Forbidden` on CONNECT, and outbound TCP/443-to-43 WHOIS is likewise blocked. `scripts/enumerate_rdap.py` implements the full collection (registrar, IANA ID, creation/expiry/last-changed dates, status codes, abuse contact, registrant country, delegated NS, DNSSEC) and will populate `output/rdap_enumeration.json` when run from a network that permits that egress.

Registrar attribution below is therefore inferred from **delegated nameservers and SOA responsible-party mailboxes**, which is a reliable proxy for the DNS operator and usually the registrar, but is not a substitute for registration dates.

## 2. Hosting and service concentration

**DNS operator / inferred registrar**

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
| AS8075 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US | 27 |
| AS47583 | AS-HOSTINGER - Hostinger International Limited, CY | 22 |
| AS13335 |  | 17 |
| AS16276 | OVH - OVH SAS, FR | 16 |
| AS58182 | wix_com - Wix.com Ltd., IL | 10 |
| AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | 7 |
| AS62371 | PROTON - Proton AG, CH | 4 |
| AS15169 | GOOGLE - Google LLC, US | 3 |
| AS22612 | NAMECHEAP-NET - Namecheap, Inc., US | 3 |
| AS209242 |  | 3 |
| AS151847 | FASTMAILPTYLTD-AS-AP - Fastmail Pty Ltd, AU | 3 |
| AS210909 | TUTA - Tutao GmbH, DE | 3 |
| AS398787 |  | 2 |

**Mail-path ASN** (from MX host IPs — vendor infrastructure, not attributable)

| ASN | AS name | Domains |
|---|---|---|
| AS15169 | GOOGLE - Google LLC, US | 128 |
| AS8075 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US | 26 |
| AS16276 | OVH - OVH SAS, FR | 15 |
| AS62371 | PROTON - Proton AG, CH | 8 |
| AS14618 | AMAZON-AES - Amazon.com, Inc., US | 7 |
| AS16509 | AMAZON-02 - Amazon.com, Inc., US | 5 |
| AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | 4 |
| AS151847 | FASTMAILPTYLTD-AS-AP - Fastmail Pty Ltd, AU | 3 |

**Geo (BGP registry country):** US (183), CY (22), FR (15), IL (10), DE (8), CH (4), NL (3), AU (3), CA (3), LT (2)

## 3. Mail authentication posture

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

## 4. Infrastructure pivot clusters

Clusters are sets of two or more domains sharing an infrastructure selector. Selectors are ordered below from strongest to weakest attribution value: a shared DKIM public key or provider verification token implies a shared *account*, a shared IP or PTR implies shared *hosting*, and a shared ASN or provider only implies a shared *vendor* and is weak on its own.

### Shared DKIM public key
*Attribution strength: very high — the same private key signs mail for every member, so one mail account/tenant controls them*

| Selector | Domains | Members |
|---|---|---|
| `dkim:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJudTILTG3qrzQzZzbptozaGQ0` | 3 | passinbox.com, passmail.com, passmail.net |
| `k2:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9` | 2 | insightfulworkplace.com, prorecresources.com |

### Shared SPF-management tenant
*Attribution strength: very high — one account administers SPF for every member domain*

| Selector | Domains | Members |
|---|---|---|
| `spfm:aa8e722993` | 27 | careernb.com, careersmails.com, cvmailhub.com, itjobmail.com, jobitmail.com, jobsmails.com, jobtechmail.com, mailmywork.com, mailscareer.com, mailsworks.com, mycareersjobs.com, mycvscout.com, … (+15 more) |

### Shared DMARC reporting-platform account
*Attribution strength: very high — DMARC failure reports for every member land in one operator's account*

| Selector | Domains | Members |
|---|---|---|
| `uriports:p7rqadcw` | 15 | activemails.net, boxmailhere.com, boxmailhost.com, careermails.net, elitecandidates.com, mailactiv.com, mailboxcore.com, nextstepcareer.net, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, swiftemail.co, … (+3 more) |
| `ondmarc:e3936a44` | 3 | fastmail.com, fastmail.net, pobox.com |

### Shared DMARC reporting address
*Attribution strength: high — same reporting mailbox (weaker where it is a provider default)*

| Selector | Domains | Members |
|---|---|---|
| `dmarc_rua@onsecureserver.net` | 20 | careermailus.com, careersmails.com, inboxhere.com, insphiretalent.com, itcareerinfo.com, jobinboxhub.com, jobsupp.com, mailscareer.com, mycareersmail.com, myitjobshub.com, myjobfolio.com, myjobscouts.com, … (+8 more) |
| `dmarc@p7rqadcw.uriports.com` | 15 | activemails.net, boxmailhere.com, boxmailhost.com, careermails.net, elitecandidates.com, mailactiv.com, mailboxcore.com, nextstepcareer.net, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, swiftemail.co, … (+3 more) |
| `e3936a44@inbox.ondmarc.com` | 3 | fastmail.com, fastmail.net, pobox.com |

### Shared hosting reverse-DNS hostname
*Attribution strength: high — same host (excludes mail-vendor IPs)*

| Selector | Domains | Members |
|---|---|---|
| `a2aa9ff50de748dbe.awsglobalaccelerator.com` | 32 | ajobguide.com, careerattainment.com, careeritjob.com, careernb.com, careersmails.com, cvmailhub.com, jobinboxhub.com, jobitmail.com, jobsmailbox.com, jobsmails.com, jobstechmail.com, jobsupp.com, … (+20 more) |
| `a16e665f42988324c.awsglobalaccelerator.com` | 27 | careermailus.com, cvtechmail.com, glidemail.io, itcareerinfo.com, itjobmail.com, itjobworks.com, jobitwork.com, jobstechmails.com, jobtechmail.com, jobtechsmail.com, mailjobtech.com, mailmywork.com, … (+15 more) |
| `unalocated.63.wixsite.com` | 10 | jobemails.net, jobhuntmails.com, myjobsemail.com, myjobsinbox.com, mymailsbox.net, mywebemails.com, myworkmails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |
| `185-70-42-15.protonmail.ch` | 4 | pm.me, proton.me, protonmail.ch, protonmail.com |
| `185-70-42-150.protonmail.ch` | 4 | pm.me, proton.me, protonmail.ch, protonmail.com |
| `185-70-42-31.protonmail.ch` | 3 | pm.me, protonmail.ch, protonmail.com |
| `redir.messagingengine.com` | 3 | fastmail.com, fastmail.net, pobox.com |
| `www.messagingengine.com` | 3 | fastmail.com, fastmail.net, pobox.com |
| `abe11aa245084d8f0.awsglobalaccelerator.com` | 2 | careermails.com, quopost.com |
| `sites.framer.app` | 2 | eprivatemail.com, whisperpost.io |

### Shared hosting IP
*Attribution strength: high on dedicated hosting, low on shared/parking/CDN ranges*

| Selector | Domains | Members |
|---|---|---|
| `198.185.159.144` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `198.185.159.145` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `198.49.23.144` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `198.49.23.145` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `15.197.148.33` | 32 | ajobguide.com, careerattainment.com, careeritjob.com, careernb.com, careersmails.com, cvmailhub.com, jobinboxhub.com, jobitmail.com, jobsmailbox.com, jobsmails.com, jobstechmail.com, jobsupp.com, … (+20 more) |
| `3.33.130.190` | 32 | ajobguide.com, careerattainment.com, careeritjob.com, careernb.com, careersmails.com, cvmailhub.com, jobinboxhub.com, jobitmail.com, jobsmailbox.com, jobsmails.com, jobstechmail.com, jobsupp.com, … (+20 more) |
| `13.248.243.5` | 27 | careermailus.com, cvtechmail.com, glidemail.io, itcareerinfo.com, itjobmail.com, itjobworks.com, jobitwork.com, jobstechmails.com, jobtechmail.com, jobtechsmail.com, mailjobtech.com, mailmywork.com, … (+15 more) |
| `76.223.105.230` | 27 | careermailus.com, cvtechmail.com, glidemail.io, itcareerinfo.com, itjobmail.com, itjobworks.com, jobitwork.com, jobstechmails.com, jobtechmail.com, jobtechsmail.com, mailjobtech.com, mailmywork.com, … (+15 more) |
| `2.57.91.91` | 18 | career-techmail.com, carrermail.com, cvejobs.com, itjobdesire.com, itjobemails.com, itjobinbox.com, itresumejobs.com, jobmaildesk.com, jobmailoffer.com, jobrequires.com, jobsdesire.com, myemailjobs.com, … (+6 more) |
| `141.94.97.141` | 15 | activemails.net, boxmailhere.com, boxmailhost.com, careermails.net, mailactiv.com, mailboxcore.com, mailmessage.co, nextstepcareer.net, rapidmailhost.com, smartmailhost.net, swiftemail.co, swiftmailhost.com, … (+3 more) |
| `2001:41d0:403:488d::` | 11 | activemails.net, boxmailhere.com, boxmailhost.com, mailactiv.com, mailmessage.co, nextstepcareer.net, rapidmailhost.com, smartmailhost.net, swiftemail.co, topcandidate.co, webpostbox.net |
| `185.230.63.107` | 10 | jobemails.net, jobhuntmails.com, myjobsemail.com, myjobsinbox.com, mymailsbox.net, mywebemails.com, myworkmails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |

*106 further clusters of this type in `output/pivot_clusters.json`.*

### Shared SOA responsible mailbox
*Attribution strength: medium — same DNS operator*

| Selector | Domains | Members |
|---|---|---|
| `dns.jomax.net` | 67 | ajobguide.com, applyme.co, careerattainment.com, careeritjob.com, careermailus.com, careernb.com, careersmails.com, cvmailhub.com, cvtechmail.com, ebsworksite.com, eprivatemail.com, glidemail.io, … (+55 more) |
| `cloud-dns-hostmaster.google.com` | 34 | applyitmail.com, career2026.com, careeremail.net, championtalentco.com, hcmconsultingpro.com, itworkmail.net, jobemail.net, jobemails24.com, jobmails.net, jobsitmail.com, jobtecmail.net, mycvwork.com, … (+22 more) |
| `hostmaster.nsone.net` | 30 | blazepinnacle.com, careermail.pro, celestialflare.com, cometmailhub.com, couriermailhub.com, duck.com, expressinboxmail.com, flashpostmail.com, inboxflashpro.com, letterinboxpro.com, mailblitzhub.com, mailflashpro.com, … (+18 more) |
| `dns.cloudflare.com` | 27 | activemails.net, aogjob.com, boxmailhere.com, boxmailhost.com, careermails.net, careerx.us, contactbox.io, elitecandidates.com, inboxhere.com, inboxhires.com, jobhuntus.com, mailactiv.com, … (+15 more) |
| `dns.hostinger.com` | 19 | career-techmail.com, carrermail.com, cvejobs.com, itjobemails.com, itjobinbox.com, itresumejobs.com, jobmaildesk.com, jobmailoffer.com, jobrequires.com, jobsdesire.com, myemailjobs.com, myhotmail.net, … (+7 more) |
| `support.wix.com` | 9 | careerwebmail.com, jobemails.net, jobhuntmails.com, myjobsinbox.com, mywebemails.com, myworkmails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |
| `awsdns-hostmaster.amazon.com` | 7 | careerio-aa.com, keemail.me, mailflyn.com, proctorconsultingservices.com, skymail.ai, tuta.io, tutanota.com |
| `support.protonmail.ch` | 3 | pm.me, protonmail.ch, protonmail.com |
| `postmaster.messagingengine.com` | 3 | fastmail.com, fastmail.net, pobox.com |
| `hostmaster.registrar-servers.com` | 2 | hirehub.careers, jobmail.io |
| `hostmaster.bnamed.eu` | 2 | careermails.com, quopost.com |
| `hostmaster.posteo.de` | 2 | posteo.in, posteo.net |

### Shared authoritative nameserver
*Attribution strength: medium*

| Selector | Domains | Members |
|---|---|---|
| `ns01.squarespacedns.com` | 27 | blazepinnacle.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, inboxflashpro.com, letterinboxpro.com, mailblitzhub.com, mailflashpro.com, mailjethub.com, mailzoomexpress.com, … (+15 more) |
| `ns03.squarespacedns.com` | 27 | blazepinnacle.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, inboxflashpro.com, letterinboxpro.com, mailblitzhub.com, mailflashpro.com, mailjethub.com, mailzoomexpress.com, … (+15 more) |
| `ns04.squarespacedns.com` | 27 | blazepinnacle.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, inboxflashpro.com, letterinboxpro.com, mailblitzhub.com, mailflashpro.com, mailjethub.com, mailzoomexpress.com, … (+15 more) |
| `ns02.squarespacedns.com` | 27 | blazepinnacle.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, inboxflashpro.com, letterinboxpro.com, mailblitzhub.com, mailflashpro.com, mailjethub.com, mailzoomexpress.com, … (+15 more) |
| `ns1.dns-parking.com` | 19 | career-techmail.com, carrermail.com, cvejobs.com, itjobdesire.com, itjobinbox.com, itresumejobs.com, jobmailoffer.com, jobrequires.com, jobsdesire.com, myemailjobs.com, myhotmail.net, myitjobmails.com, … (+7 more) |
| `ns2.dns-parking.com` | 19 | career-techmail.com, carrermail.com, cvejobs.com, itjobdesire.com, itjobinbox.com, itresumejobs.com, jobmailoffer.com, jobrequires.com, jobsdesire.com, myemailjobs.com, myhotmail.net, myitjobmails.com, … (+7 more) |
| `norm.ns.cloudflare.com` | 12 | activemails.net, boxmailhere.com, boxmailhost.com, mailactiv.com, mailmessage.co, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, swiftemail.co, tivomail.com, truemailhost.net, webpostbox.net |
| `colette.ns.cloudflare.com` | 12 | activemails.net, boxmailhere.com, boxmailhost.com, mailactiv.com, mailmessage.co, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, swiftemail.co, tivomail.com, truemailhost.net, webpostbox.net |
| `ns9.wixdns.net` | 10 | careerwebmail.com, jobemails.net, jobhuntmails.com, myjobsemail.com, myjobsinbox.com, mymailsbox.net, mywebemails.com, myworkmails.com, work-mail.net, workwebmail.com |
| `ns8.wixdns.net` | 10 | careerwebmail.com, jobemails.net, jobhuntmails.com, myjobsemail.com, myjobsinbox.com, mymailsbox.net, mywebemails.com, myworkmails.com, work-mail.net, workwebmail.com |
| `ns-cloud-a2.googledomains.com` | 8 | career2026.com, careeremail.net, hcmconsultingpro.com, itworkmail.net, phoenixglide.com, quantumzens.com, tasksmail.com, workitmail.com |
| `ns-cloud-a3.googledomains.com` | 8 | career2026.com, careeremail.net, hcmconsultingpro.com, itworkmail.net, phoenixglide.com, quantumzens.com, tasksmail.com, workitmail.com |

*115 further clusters of this type in `output/pivot_clusters.json`.*

### Shared hosting BGP prefix
*Attribution strength: low*

| Selector | Domains | Members |
|---|---|---|
| `198.185.159.0/24` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `198.49.23.0/24` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `15.197.144.0/20` | 32 | ajobguide.com, careerattainment.com, careeritjob.com, careernb.com, careersmails.com, cvmailhub.com, jobinboxhub.com, jobitmail.com, jobsmailbox.com, jobsmails.com, jobstechmail.com, jobsupp.com, … (+20 more) |
| `3.33.128.0/20` | 32 | ajobguide.com, careerattainment.com, careeritjob.com, careernb.com, careersmails.com, cvmailhub.com, jobinboxhub.com, jobitmail.com, jobsmailbox.com, jobsmails.com, jobstechmail.com, jobsupp.com, … (+20 more) |
| `13.248.240.0/20` | 27 | careermailus.com, cvtechmail.com, glidemail.io, itcareerinfo.com, itjobmail.com, itjobworks.com, jobitwork.com, jobstechmails.com, jobtechmail.com, jobtechsmail.com, mailjobtech.com, mailmywork.com, … (+15 more) |
| `76.223.96.0/20` | 27 | careermailus.com, cvtechmail.com, glidemail.io, itcareerinfo.com, itjobmail.com, itjobworks.com, jobitwork.com, jobstechmails.com, jobtechmail.com, jobtechsmail.com, mailjobtech.com, mailmywork.com, … (+15 more) |
| `52.96.0.0/14` | 25 | ajoy2consult.com, careeremail.net, careerwebmail.com, ebsworksite.com, insightfulworkplace.com, jobemail.net, jobemails.net, jobhuntmails.com, mail.mcgill.ca, mail.utoronto.ca, mainewoodproducts.com, mycareermail.com, … (+13 more) |
| `2603:1000::/25` | 24 | ajoy2consult.com, careerattainment.com, careerwebmail.com, ebsworksite.com, insightfulworkplace.com, jobemail.net, jobemails.net, jobhuntmails.com, mail.utoronto.ca, mainewoodproducts.com, mycareermail.com, mycareersmail.com, … (+12 more) |
| `2.57.91.0/24` | 19 | career-techmail.com, carrermail.com, cvejobs.com, i-mail.in, itjobdesire.com, itjobemails.com, itjobinbox.com, itresumejobs.com, jobmaildesk.com, jobmailoffer.com, jobrequires.com, jobsdesire.com, … (+7 more) |
| `141.94.0.0/16` | 15 | activemails.net, boxmailhere.com, boxmailhost.com, careermails.net, mailactiv.com, mailboxcore.com, mailmessage.co, nextstepcareer.net, rapidmailhost.com, smartmailhost.net, swiftemail.co, swiftmailhost.com, … (+3 more) |
| `185.230.63.0/24` | 10 | jobemails.net, jobhuntmails.com, myjobsemail.com, myjobsinbox.com, mymailsbox.net, mywebemails.com, myworkmails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |
| `34.148.0.0/14` | 7 | careerwebmail.com, jobhuntmails.com, mymailsbox.net, mywebemails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |

*33 further clusters of this type in `output/pivot_clusters.json`.*

### Shared MX host
*Attribution strength: low — vendor-level*

| Selector | Domains | Members |
|---|---|---|
| `alt1.aspmx.l.google.com` | 69 | applyme.co, blazepinnacle.com, careermailus.com, careernb.com, careersmails.com, celestialflare.com, championtalentco.com, cometmailhub.com, couriermailhub.com, cvmailhub.com, digitalexpress.co.uk, expressinboxmail.com, … (+57 more) |
| `aspmx.l.google.com` | 69 | applyme.co, blazepinnacle.com, careermailus.com, careernb.com, careersmails.com, celestialflare.com, championtalentco.com, cometmailhub.com, couriermailhub.com, cvmailhub.com, digitalexpress.co.uk, expressinboxmail.com, … (+57 more) |
| `alt2.aspmx.l.google.com` | 68 | applyme.co, blazepinnacle.com, careermailus.com, careernb.com, careersmails.com, celestialflare.com, championtalentco.com, cometmailhub.com, couriermailhub.com, cvmailhub.com, digitalexpress.co.uk, expressinboxmail.com, … (+56 more) |
| `alt3.aspmx.l.google.com` | 66 | applyme.co, blazepinnacle.com, careermailus.com, careernb.com, careersmails.com, celestialflare.com, championtalentco.com, cometmailhub.com, couriermailhub.com, cvmailhub.com, digitalexpress.co.uk, expressinboxmail.com, … (+54 more) |
| `alt4.aspmx.l.google.com` | 65 | applyme.co, blazepinnacle.com, careermailus.com, careernb.com, careersmails.com, celestialflare.com, championtalentco.com, cometmailhub.com, couriermailhub.com, cvmailhub.com, digitalexpress.co.uk, expressinboxmail.com, … (+53 more) |
| `smtp.google.com` | 41 | ajobguide.com, applyitmail.com, career2026.com, careeritjob.com, cvtechmail.com, hcmconsultingpro.com, itjobworks.com, itworkmail.net, jobemails24.com, jobhuntus.com, jobinboxhub.com, jobitwork.com, … (+29 more) |
| `aspmx2.migadu.com` | 14 | boxmailhere.com, careermails.net, elitecandidates.com, mailactiv.com, mailmessage.co, nextstepcareer.net, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, swiftemail.co, swiftmailhost.com, tivomail.com, … (+2 more) |
| `aspmx1.migadu.com` | 14 | boxmailhere.com, careermails.net, elitecandidates.com, mailactiv.com, mailmessage.co, nextstepcareer.net, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, swiftemail.co, swiftmailhost.com, tivomail.com, … (+2 more) |
| `SMTP.GOOGLE.com` | 13 | aogjob.com, carrermail.com, cvejobs.com, itjobdesire.com, itjobemails.com, jobmailoffer.com, jobrequires.com, myemailjobs.com, newjobdesire.com, newjobrequire.com, newjobshunt.com, sharemejobs.com, … (+1 more) |
| `inbound-smtp.us-east-1.amazonaws.com` | 6 | eprivatemail.com, jobmail.io, mailflyn.com, my-privatemail.com, skymail.ai, sorce.email |
| `mail.protonmail.ch` | 5 | pm.me, proton.me, protonmail.ch, protonmail.com, wgcv.me |
| `mailsec.protonmail.ch` | 5 | pm.me, proton.me, protonmail.ch, protonmail.com, wgcv.me |

*21 further clusters of this type in `output/pivot_clusters.json`.*

### Shared SPF include
*Attribution strength: low — vendor-level*

| Selector | Domains | Members |
|---|---|---|
| `_spf.google.com` | 82 | ajobguide.com, applyitmail.com, blazepinnacle.com, career2026.com, careeritjob.com, careermailus.com, careernb.com, championtalentco.com, couriermailhub.com, cvtechmail.com, expressinboxmail.com, fastmailzoom.com, … (+70 more) |
| `spf.protection.outlook.com` | 24 | ajoy2consult.com, careerattainment.com, careeremail.net, ebsworksite.com, jobemail.net, jobemails.net, jobhuntmails.com, mail.mcgill.ca, mail.utoronto.ca, mainewoodproducts.com, mycareermail.com, mycareersmail.com, … (+12 more) |
| `spf.migadu.com` | 15 | activemails.net, boxmailhere.com, boxmailhost.com, careermails.net, elitecandidates.com, mailactiv.com, mailboxcore.com, mailmessage.co, nextstepcareer.net, pulsemailbox.com, rapidmailhost.com, smartmailhost.net, … (+3 more) |
| `secureserver.net` | 12 | careeritjob.com, ebsworksite.com, insightfulworkplace.com, jobslink-inc.com, jobstechmail.com, jobstechmails.com, jobsupp.com, jobtechmail.com, jobtechsmail.com, mailjobtech.com, techjobmail.com, thetalentarc.co.uk |
| `amazonses.com` | 7 | careerio-aa.com, jobmail.io, mailflyn.com, my-privatemail.com, mysecuremail.co, neuronmail.io, skymail.ai |
| `mailgun.org` | 6 | careermails.com, contactbox.io, inboxhere.com, myprivatemail.io, quopost.com, risemail.com |
| `_spf.mx.cloudflare.net` | 3 | inboxhere.com, inboxhires.com, mailbluff.com |
| `_spf.protonmail.ch` | 3 | pm.me, protonmail.ch, wgcv.me |
| `spf.messagingengine.com` | 3 | fastmail.com, fastmail.net, pobox.com |
| `simplelogin.co` | 3 | passinbox.com, passmail.com, passmail.net |
| `spf.tutanota.de` | 3 | keemail.me, tuta.io, tutanota.com |
| `162.0.237.182` | 2 | aogjob.com, jobhuntus.com |

### Shared hosting ASN
*Attribution strength: very low — vendor-level only*

| Selector | Domains | Members |
|---|---|---|
| `AS16509` | 74 | ajobguide.com, careerattainment.com, careeritjob.com, careermail.pro, careermails.com, careermailus.com, careernb.com, careersmails.com, contactbox.io, cvmailhub.com, cvtechmail.com, eprivatemail.com, … (+62 more) |
| `AS53831` | 57 | applyitmail.com, blazepinnacle.com, career2026.com, celestialflare.com, cometmailhub.com, couriermailhub.com, expressinboxmail.com, fastmailzoom.com, flashpostmail.com, hcmconsultingpro.com, inboxflashpro.com, itworkmail.net, … (+45 more) |
| `AS8075` | 27 | ajoy2consult.com, careerattainment.com, careeremail.net, careerwebmail.com, duck.com, ebsworksite.com, insightfulworkplace.com, jobemail.net, jobemails.net, jobhuntmails.com, mail.mcgill.ca, mail.utoronto.ca, … (+15 more) |
| `AS47583` | 22 | career-techmail.com, carrermail.com, cvejobs.com, i-mail.in, itjobdesire.com, itjobemails.com, itjobinbox.com, itresumejobs.com, jobmaildesk.com, jobmailoffer.com, jobrequires.com, jobsdesire.com, … (+10 more) |
| `AS13335` | 17 | aogjob.com, careerx.us, fastmail.com, hushmail.com, inboxhere.com, inboxhires.com, jobemails.net, jobhuntus.com, mailflux.com, myjobsemail.com, myjobsinbox.com, passinbox.com, … (+5 more) |
| `AS16276` | 16 | activemails.net, boxmailhere.com, boxmailhost.com, careermails.net, mailactiv.com, mailboxcore.com, mailmessage.co, myquickmails.com, nextstepcareer.net, rapidmailhost.com, smartmailhost.net, swiftemail.co, … (+4 more) |
| `AS58182` | 10 | jobemails.net, jobhuntmails.com, myjobsemail.com, myjobsinbox.com, mymailsbox.net, mywebemails.com, myworkmails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |
| `AS396982` | 7 | careerwebmail.com, jobhuntmails.com, mymailsbox.net, mywebemails.com, sharpcareerimage.com, work-mail.net, workwebmail.com |
| `AS62371` | 4 | pm.me, proton.me, protonmail.ch, protonmail.com |
| `AS15169` | 3 | ajoy2consult.com, jgcareers.com, myitjobmails.com |
| `AS22612` | 3 | jobmail.io, ohmymail.net, thejobtec.com |
| `AS209242` | 3 | hushmail.com, insightfulworkplace.com, mainewoodproducts.com |

*6 further clusters of this type in `output/pivot_clusters.json`.*

## 5. Linked operator groups

The clusters in section 4 are single selectors. This section merges them into connected components using **account-level selectors only** — a DKIM public key, an SPF-management tenant id, a DMARC reporting-platform account, a provider verification token, or reverse DNS on a host that is not a hosting vendor's shared estate. Vendor-level facts (shared MX, shared parking IPs, provider reverse DNS) are attached as corroboration but never used to link, because clustering on them only rediscovers the vendor's customer base.

**6 groups covering 52 of 263 domains.**

### Group 1 — 27 domains

**Linking evidence:** `spfm:aa8e722993`

| Attribute | Value |
|---|---|
| DNS operator | GoDaddy (25), none (2) |
| Mail provider | Google Workspace (22), none (5) |
| SOA responsible party | `dns.jomax.net` (23) |
| Hosting IPs | `15.197.148.33` (14), `3.33.130.190` (14), `13.248.243.5` (13), `76.223.105.230` (13) |
| DMARC policy | none-published (16), none (6), quarantine (5) |
| Risk tier | medium (22), high (5) |
| Naming theme | job_career_work_it_cv_themed (22), synthetic_generic_mailbox_brand (4), privacy_alias_mailbox (1) |

**Members:** `careernb.com`, `careersmails.com`, `cvmailhub.com`, `itjobmail.com`, `jobitmail.com`, `jobsmails.com`, `jobtechmail.com`, `mailmywork.com`, `mailscareer.com`, `mailsworks.com`, `mycareersjobs.com`, `mycvscout.com`, `mycvtalent.com`, `myemailjob.com`, `myjobscouts.com`, `myjobsmails.com`, `mymailjob.com`, `mymailkeeper.com`, `mymailworks.com`, `protectmymails.com`, `savemymails.com`, `techjobmail.com`, `techmyjob.com`, `techsmail.com`, `thepromail.co`, `worksemail.com`, `worksemails.com`

### Group 2 — 15 domains

**Linking evidence:** `uriports:p7rqadcw`

| Attribute | Value |
|---|---|
| DNS operator | Cloudflare (13), none (2) |
| Mail provider | Google Workspace (11), none (4) |
| SOA responsible party | `dns.cloudflare.com` (13) |
| Hosting IPs | `141.94.97.141` (12), `2001:41d0:403:488d::` (9), `104.21.73.99` (1), `172.67.160.234` (1), `2606:4700:3033::ac43:a0ea` (1), `2606:4700:3035::6815:4963` (1) |
| DMARC policy | quarantine (15) |
| Risk tier | medium (8), low (7) |
| Naming theme | synthetic_generic_mailbox_brand (11), job_career_work_it_cv_themed (4) |

**Members:** `activemails.net`, `boxmailhere.com`, `boxmailhost.com`, `careermails.net`, `elitecandidates.com`, `mailactiv.com`, `mailboxcore.com`, `nextstepcareer.net`, `pulsemailbox.com`, `rapidmailhost.com`, `smartmailhost.net`, `swiftemail.co`, `tivomail.com`, `topcandidate.co`, `truemailhost.net`

### Group 3 — 3 domains

**Linking evidence:** `ondmarc:e3936a44`

| Attribute | Value |
|---|---|
| DNS operator | messagingengine.com (3) |
| Mail provider | Fastmail (3) |
| SOA responsible party | `postmaster.messagingengine.com` (3) |
| Hosting IPs | `103.168.172.37` (3), `103.168.172.52` (3), `103.168.172.65` (3), `103.168.172.38` (1), `103.168.172.39` (1), `103.168.172.43` (1) |
| DMARC policy | none (3) |
| Risk tier | low (3) |
| Naming theme | privacy_alias_mailbox (3) |

**Members:** `fastmail.com`, `fastmail.net`, `pobox.com`

### Group 4 — 3 domains

**Linking evidence:** `dkim:dkim:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJudTILTG3qrzQzZzbptozaGQ0`

| Attribute | Value |
|---|---|
| DNS operator | Cloudflare (3) |
| Mail provider | self/other (simplelogin.co) (3) |
| SOA responsible party | `dns.cloudflare.com` (2) |
| Hosting IPs | `104.21.34.220` (1), `172.67.209.190` (1), `2606:4700:3030::6815:22dc` (1), `2606:4700:3032::ac43:d1be` (1), `104.21.15.227` (1), `172.67.208.40` (1) |
| DMARC policy | quarantine (3) |
| Risk tier | low (3) |
| Naming theme | privacy_alias_mailbox (2), synthetic_generic_mailbox_brand (1) |

**Members:** `passinbox.com`, `passmail.com`, `passmail.net`

### Group 5 — 2 domains

**Linking evidence:** `ptr:sites.framer.app`

| Attribute | Value |
|---|---|
| DNS operator | GoDaddy (1), Cloudflare (1) |
| Mail provider | self/other (amazonaws.com) (1), Bulk/ESP (1) |
| SOA responsible party | `dns.jomax.net` (1) |
| Hosting IPs | `31.43.160.6` (2), `31.43.161.6` (2), `35.71.142.77` (1), `52.223.52.2` (1) |
| DMARC policy | none (1), none-published (1) |
| Risk tier | low (1), medium (1) |
| Naming theme | privacy_alias_mailbox (2) |

**Members:** `eprivatemail.com`, `whisperpost.io`

### Group 6 — 2 domains

**Linking evidence:** `dkim:k2:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9`

| Attribute | Value |
|---|---|
| DNS operator | GoDaddy (2) |
| Mail provider | self/other (ppe-hosted.com) (1), Microsoft 365 (1) |
| SOA responsible party | `dns.jomax.net` (1) |
| Hosting IPs | `52.96.156.8` (2), `160.153.0.105` (1), `2603:1036:304:2852::8` (1), `2603:1036:304:3404::8` (1), `2603:1036:304:806::8` (1), `2603:1036:304:85e::8` (1) |
| DMARC policy | none (2) |
| Risk tier | low (2) |
| Naming theme | job_career_work_it_cv_themed (1), synthetic_generic_mailbox_brand (1) |

**Members:** `insightfulworkplace.com`, `prorecresources.com`

## 6. Non-resolving domains

10 of 263 entries returned no NS/SOA/A/MX. These are either deregistered/expired, never registered, or malformed strings captured from log or header parsing (e.g. truncated or concatenated addresses).

**Invalid/nonexistent TLD — parsing artefacts, not real infrastructure:**

`email.scued`, `gmail.com0`, `gmail.comlinkedin`, `gmail.om`, `mymail.pomona.edi`

**Valid TLD but not resolving (expired, parked-without-DNS, or never registered):**

`careerwebmails.com`, `cvtechmail.co`, `myjobesmails.com`, `myworksmail.com`, `thejobmail.com`

## 7. Per-domain detail

Full records are in `output/dns_enumeration.json` (raw) and `output/domain_infrastructure.csv` (flat table). Summary of the highest-risk tier:

| Domain | Score | NS operator | Mail provider | ASN | DMARC | IPs |
|---|---|---|---|---|---|---|
| mailjobtech.com | 85 | GoDaddy | Google Workspace | AS16509 | none | 13.248.243.5;76.223.105.230 |
| nextitjobs.com | 85 | GoDaddy | Google Workspace | AS16509 | quarantine | 15.197.148.33;3.33.130.190 |
| itjobmail.com | 80 | GoDaddy | Google Workspace | AS16509 | - | 13.248.243.5;76.223.105.230 |
| myjobemails.com | 75 | Hostinger | none | AS47583;AS8075 | none | 2.57.91.91;2603:1036:304:2852::8;2603:1036:3 |
| careeremail.net | 75 | Google Domains / Squarespace | Microsoft 365 | AS8075 | none | 52.96.156.24;52.96.156.8;52.96.170.72;52.96. |
| itjobinbox.com | 75 | Hostinger | Google Workspace | AS47583 | - | 2.57.91.91 |
| aogjob.com | 75 | Cloudflare | Google Workspace | AS13335 | none | 104.21.67.4;172.67.167.105;2606:4700:3033::a |
| itjobworks.com | 75 | GoDaddy | Google Workspace | AS16509 | - | 13.248.243.5;76.223.105.230 |
| jobstechmails.com | 75 | GoDaddy | Google Workspace | AS16509 | none | 13.248.243.5;76.223.105.230 |
| myitjobmails.com | 75 | Hostinger | none | AS15169;AS47583 | - | 2.57.91.91;2607:f8b0:4002:c10::65;2607:f8b0: |
| jobitmail.com | 75 | GoDaddy | Google Workspace | AS16509 | - | 15.197.148.33;3.33.130.190 |
| careerattainment.com | 70 | GoDaddy | Microsoft 365 | AS16509;AS8075 | none | 15.197.148.33;2603:1036:304:2853::8;2603:103 |
| myjobsmails.com | 70 | GoDaddy | none | AS16509 | - | 13.248.243.5;76.223.105.230 |
| myworkmails.com | 70 | Wix | Microsoft 365 | AS58182;AS8075 | - | 185.230.63.107;185.230.63.171;185.230.63.186 |
| workwebmail.com | 70 | Wix | Microsoft 365 | AS396982;AS58182;AS8075 | none | 185.230.63.107;185.230.63.171;185.230.63.186 |
| jobsmails.com | 70 | GoDaddy | Google Workspace | AS16509 | - | 15.197.148.33;3.33.130.190 |
| techcareermail.com | 70 | Google Domains / Squarespace | Microsoft 365 | AS8075 | none | 2603:1036:304:284d::8;2603:1036:304:2857::8; |
| cvtechmail.com | 70 | GoDaddy | Google Workspace | AS16509 | - | 13.248.243.5;76.223.105.230 |
| jobtechmail.com | 70 | GoDaddy | Google Workspace | AS16509 | none | 13.248.243.5;76.223.105.230 |
| jobtechsmail.com | 70 | GoDaddy | Google Workspace | AS16509 | none | 13.248.243.5;76.223.105.230 |
| workitmail.com | 70 | Google Domains / Squarespace | Google Workspace | AS53831 | - | 198.185.159.144;198.185.159.145;198.49.23.14 |
| jobsitmail.com | 70 | Google Domains / Squarespace | Google Workspace | AS53831 | - | 198.185.159.144;198.185.159.145;198.49.23.14 |
| workmailit.com | 70 | Google Domains / Squarespace | Google Workspace | AS53831 | - | 198.185.159.144;198.185.159.145;198.49.23.14 |

## 8. Follow-on collection and negative findings

### Cluster expansion by DNS marker

Group 1 membership is directly testable: members carry `include:dc-aa8e722993._spfm.<domain>` in their apex SPF, so the record exists at that name. Candidate names generated from the corpus naming grammar were tested against it — 20,227 candidates probed, 639 registered.

**Two false-positive modes had to be controlled out before the result meant anything:**

1. *Wildcard DNS.* Parking providers (Afternic, Sedo, CashParking, NameFind) answer every subdomain, so the marker query returns a hit on domains with no connection to the cluster. An uncontrolled first pass returned 71 'hits'; adding a random-label canary and rejecting the parking default `v=spf1 -all` cut it to 4. Parked brand names such as `pobox.co`, `proton.io` and `tuta.us` were all in the discarded set.
2. *Timeouts read as absence.* A failed canary lookup is not proof of no wildcard. The probe now retries and treats only a definitive NXDOMAIN as clearing a zone; undecidable cases are flagged, not counted.

**Confirmed new members (4):** `hiremails.com`, `mypostwork.com`, `sorce.io`, `thetechbox.co` — each verified with the tenant's exact SPF content and two NXDOMAIN canaries.

This takes Group 1 from 27 to 31 domains. Group 2 did not expand: no generated candidate carried the URIports account, which is expected given its members are brandable coinages rather than compound job/mail words.

### Negative finding: the 2026-08-20 'batch' is not real

**Hypothesis:** the 21 domains sharing zone-edit date 2026-08-20 were registered or configured as one batch  
**Test:** sampled 12 Hostinger-nameserver domains discovered by the expansion sweep that are unrelated to any cluster, and read their SOA serials  
**Result:** 12 of 12 controls carry the same 2026-08-20 serial  
**Verdict:** FALSIFIED - provider-wide serial bump, not operator activity

21 domains share a 2026-08-20 SOA serial, all on Hostinger — which reads as a batch operation until you sample unrelated Hostinger domains and find the same serial. It is a provider-wide bump. SOA serials date the last zone edit, never registration, and any single-provider batch needs this control before it is believed. The remaining candidate batches are in `output/temporal_analysis.json`; the 2026-02-05 GoDaddy set (8 domains, all Google Workspace, two carrying the Group 1 tenant) spans one provider and is untested.

