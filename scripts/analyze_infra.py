#!/usr/bin/env python3
"""
Infrastructure analysis and pivot-clustering over the DNS enumeration output.

Turns raw records into the things an analyst actually pivots on: hosting and
mail providers, ASN concentration, shared nameservers, shared SPF/DKIM
material, shared verification tokens and DMARC reporting addresses -- then
groups domains into infrastructure clusters on those shared selectors.

Outputs:
  output/domain_infrastructure.csv   flat per-domain table
  output/pivot_clusters.json         shared-selector clusters
  output/INFRASTRUCTURE_REPORT.md    analyst-facing report
"""
import json, csv, os, re, sys
from collections import defaultdict, Counter
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_JSON = os.path.join(ROOT, "output", "dns_enumeration.json")
OUT_DIR = os.path.join(ROOT, "output")

# Nameserver base-domain -> DNS operator / likely registrar
NS_OPERATOR = {
    "domaincontrol.com": "GoDaddy",
    "godaddy.com": "GoDaddy",
    "cloudflare.com": "Cloudflare",
    "namecheaphosting.com": "Namecheap",
    "registrar-servers.com": "Namecheap",
    "name.com": "Name.com",
    "dnsowl.com": "NameSilo",
    "namesilo.com": "NameSilo",
    "hostinger.com": "Hostinger",
    "dns-parking.com": "Hostinger",
    "wixdns.net": "Wix",
    "squarespacedns.com": "Squarespace",
    "google.com": "Google Cloud DNS",
    "googledomains.com": "Google Domains / Squarespace",
    "awsdns-00.org": "AWS Route 53",
    "bluehost.com": "Bluehost",
    "hostgator.com": "HostGator",
    "ionos.com": "IONOS",
    "1and1.com": "IONOS",
    "porkbun.com": "Porkbun",
    "dynadot.com": "Dynadot",
    "sedoparking.com": "Sedo (parked)",
    "parkingcrew.net": "ParkingCrew (parked)",
    "bodis.com": "Bodis (parked)",
    "afternic.com": "Afternic (for sale)",
    "above.com": "Above.com (parked)",
    "hover.com": "Hover",
    "gandi.net": "Gandi",
    "ovh.net": "OVH",
    "digitalocean.com": "DigitalOcean",
    "zoho.com": "Zoho",
    "protonmail.ch": "Proton",
    "yandex.net": "Yandex",
    "nsone.net": "NS1",
    "ultradns.com": "UltraDNS",
    "worldnic.com": "Network Solutions",
    "register.com": "Register.com",
    "epik.com": "Epik",
    "spaceship.net": "Spaceship",
}

MX_PROVIDER = [
    (r"google\.com|googlemail\.com|aspmx", "Google Workspace"),
    (r"outlook\.com|protection\.outlook|office365", "Microsoft 365"),
    (r"zoho", "Zoho Mail"),
    (r"protonmail|proton\.me", "Proton Mail"),
    (r"secureserver\.net", "GoDaddy Email"),
    (r"privateemail\.com", "Namecheap Private Email"),
    (r"yandex", "Yandex Mail"),
    (r"mail\.ru", "Mail.ru"),
    (r"titan\.email|titan", "Titan Email"),
    (r"improvmx", "ImprovMX (forwarder)"),
    (r"forwardemail", "ForwardEmail"),
    (r"mailgun|sendgrid|mailchimp|mandrill", "Bulk/ESP"),
    (r"hostinger", "Hostinger Mail"),
    (r"fastmail|messagingengine", "Fastmail"),
    (r"migadu", "Migadu"),
    (r"tutanota|tutao", "Tuta"),
    (r"one\.com", "One.com"),
    (r"ionos|1and1|kundenserver|perfora", "IONOS Mail"),
    (r"bluehost|hostgator|websitewelcome|unifiedlayer", "EIG/Newfold Hosting Mail"),
    (r"cloudflare", "Cloudflare Email Routing"),
]


# Subdomain labels whose addresses belong to the mail provider, not the domain's
# own hosting. autoconfig/autodiscover in particular are usually CNAMEs straight
# into the mail vendor (e.g. autoconfig.migadu.com), so counting their IPs as
# "hosting" makes every customer of that vendor look co-hosted.
MAIL_PATH_LABELS = {"autoconfig", "autodiscover", "mail", "smtp", "imap",
                    "pop", "pop3", "webmail", "mx", "mx1", "mx2", "owa",
                    "exchange"}


def base_domain(host):
    """Best-effort registrable domain (handles the common two-label suffixes)."""
    host = (host or "").rstrip(".").lower()
    parts = host.split(".")
    if len(parts) < 2:
        return host
    two = {"co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.in", "co.za"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def mx_provider(mx_hosts):
    for h in mx_hosts:
        for pat, name in MX_PROVIDER:
            if re.search(pat, h, re.I):
                return name
    if mx_hosts:
        return f"self/other ({base_domain(mx_hosts[0])})"
    return "none"


def spf_includes(txts):
    inc = []
    for t in txts:
        if t.lower().startswith("v=spf1"):
            inc.extend(re.findall(r"(?:include|redirect=)[:=]([^\s]+)", t, re.I))
            inc.extend(re.findall(r"\bip4:([^\s]+)", t, re.I))
    return sorted(set(inc))


def dmarc_fields(dmarc):
    pol, rua, ruf = None, [], []
    for t in dmarc:
        if not t.lower().startswith("v=dmarc1"):
            continue
        m = re.search(r"\bp\s*=\s*(\w+)", t, re.I)
        if m:
            pol = m.group(1).lower()
        rua.extend(re.findall(r"mailto:([^;,\s]+)", re.search(r"rua=([^;]+)", t, re.I).group(1))
                   if re.search(r"rua=([^;]+)", t, re.I) else [])
        ruf.extend(re.findall(r"mailto:([^;,\s]+)", re.search(r"ruf=([^;]+)", t, re.I).group(1))
                   if re.search(r"ruf=([^;]+)", t, re.I) else [])
    return pol, sorted(set(rua)), sorted(set(ruf))


def verification_tokens(txts):
    """Provider domain-ownership tokens. A shared token means a shared tenant."""
    patterns = [
        r"google-site-verification=[\w\-]+",
        r"\bMS=[\w\-]+",
        r"facebook-domain-verification=[\w\-]+",
        r"atlassian-domain-verification=[\w\-/+=]+",
        r"zoho-verification=[\w\-.]+",
        r"apple-domain-verification=[\w\-]+",
        r"stripe-verification=[\w\-]+",
        r"logmein-verification-code=[\w\-]+",
        r"docusign=[\w\-]+",
        r"adobe-idp-site-verification=[\w\-]+",
        r"onetrust-domain-verification=[\w\-]+",
        r"shopify-verification-code=[\w\-]+",
        r"hosted-email-verify=[\w\-]+",
        r"mailru-verification=[\w\-]+",
        r"yandex-verification=[\w\-]+",
        r"globalsign-domain-verification=[\w\-/+=]+",
    ]
    toks = []
    for t in txts:
        for pat in patterns:
            m = re.search(pat, t, re.I)
            if m:
                toks.append(m.group(0))
    return sorted(set(toks))



def spf_manager_tenants(txts):
    """SPF-delegation/flattening service tenant ids (e.g. dc-<id>._spfm.<domain>).
    A shared tenant id means one account manages SPF for all those domains."""
    out = []
    for t in txts:
        out.extend(f"spfm:{m}" for m in re.findall(r"dc-([0-9a-f]{6,})\._spfm\.", t, re.I))
    return sorted(set(out))


def dmarc_tenants(dmarc):
    """Reporting-platform account ids inside DMARC rua/ruf targets."""
    out = []
    for t in dmarc:
        for host_pat, label in ((r"([\w-]+)\.uriports\.com", "uriports"),
                                (r"([\w-]+)@inbox\.ondmarc\.com", "ondmarc"),
                                (r"([\w-]+)@[\w.-]*dmarcian", "dmarcian"),
                                (r"([\w-]+)@[\w.-]*valimail", "valimail"),
                                (r"rua@[\w-]+\.([\w-]+)\.report-uri\.com", "report-uri")):
            for m in re.findall(host_pat, t, re.I):
                out.append(f"{label}:{m}")
    return sorted(set(out))


def main():
    data = json.load(open(IN_JSON))
    ipintel = data["ip_intel"]
    domains = data["domains"]
    by_dom = {d["domain"]: d for d in domains}

    # Second-pass sweep used a far longer DKIM selector list; merge those keys in
    # so the DKIM pivot sees every selector actually found.
    deep_path = os.path.join(OUT_DIR, "deep_enumeration.json")
    deep_dkim = {}
    if os.path.exists(deep_path):
        deep_dkim = {d["domain"]: d.get("dkim", {})
                     for d in json.load(open(deep_path))["domains"]}
    for dom, extra in deep_dkim.items():
        if dom in by_dom:
            merged = dict(by_dom[dom]["dkim"])
            merged.update(extra)
            by_dom[dom]["dkim"] = merged

    def ip_meta(ips):
        asns, as_names, ccs, prefixes, ptrs = set(), set(), set(), set(), set()
        for ip in ips:
            info = ipintel.get(ip) or {}
            if info.get("asn"):
                asns.add(info["asn"])
                if info.get("as_name"):
                    as_names.add(info["as_name"])
                if info.get("cc"):
                    ccs.add(info["cc"])
                if info.get("bgp_prefix"):
                    prefixes.add(info["bgp_prefix"])
            ptrs.update(info.get("ptr", []))
        return asns, as_names, ccs, prefixes, ptrs

    rows = []
    for d in domains:
        r = d["records"]
        mx_hosts = [m.split()[-1].rstrip(".").lower() for m in r["MX"]]
        ns_hosts = [n.rstrip(".").lower() for n in r["NS"]]
        ns_bases = sorted({base_domain(n) for n in ns_hosts})
        pol, rua, ruf = dmarc_fields(d["dmarc"])

        # Hosting IPs (what the domain itself points at) are the attributable ones.
        # MX-host IPs belong to the mail vendor and are shared by every tenant, so
        # they are tracked separately and kept out of the hosting pivots.
        host_sub, mail_sub = set(), set()
        for fqdn, s_rec in d["subdomains"].items():
            label = fqdn.split(".")[0]
            (mail_sub if label in MAIL_PATH_LABELS else host_sub).update(
                s_rec["A"] + s_rec["AAAA"])
        hosting_ips = sorted(set(r["A"]) | set(r["AAAA"]) | host_sub)
        mail_ips = sorted({ip for lst in d["mx_hosts"].values() for ip in lst} | mail_sub)

        h_asns, h_names, h_ccs, h_prefix, h_ptr = ip_meta(hosting_ips)
        m_asns, m_names, _, _, m_ptr = ip_meta(mail_ips)

        rows.append({
            "domain": d["domain"],
            "domain_class": d["domain_class"],
            "risk_score": d["risk_score"],
            "risk_tier": d["risk_tier"],
            "resolves": d["resolves"],
            "nxdomain": d.get("nxdomain", False),
            "a_records": ";".join(r["A"]),
            "aaaa_records": ";".join(r["AAAA"]),
            "cname": ";".join(x.rstrip(".") for x in r["CNAME"]),
            "ns": ";".join(ns_hosts),
            "ns_operator": ";".join(sorted({NS_OPERATOR.get(b, b) for b in ns_bases})) or "none",
            "soa_mname": r["SOA"][0].split()[0].rstrip(".") if r["SOA"] else "",
            "soa_rname": r["SOA"][0].split()[1].rstrip(".") if r["SOA"] else "",
            "soa_serial": r["SOA"][0].split()[2] if r["SOA"] else "",
            "mx": ";".join(r["MX"]),
            "mx_provider": mx_provider(mx_hosts),
            "spf": ";".join(t for t in r["TXT"] if t.lower().startswith("v=spf1")),
            "spf_includes": ";".join(spf_includes(r["TXT"])),
            "spf_manager_tenant": ";".join(spf_manager_tenants(r["TXT"])),
            "txt_all": " | ".join(r["TXT"]),
            "verification_tokens": ";".join(verification_tokens(r["TXT"])),
            "caa": ";".join(r["CAA"]),
            "dmarc": ";".join(d["dmarc"]),
            "dmarc_policy": pol or "",
            "dmarc_rua": ";".join(rua),
            "dmarc_ruf": ";".join(ruf),
            "dmarc_tenant": ";".join(dmarc_tenants(d["dmarc"])),
            "dkim_selectors": ";".join(sorted(by_dom[d["domain"]]["dkim"])),
            "mta_sts": ";".join(d["mta_sts"]),
            "tls_rpt": ";".join(d["tls_rpt"]),
            "subdomains_found": ";".join(sorted(d["subdomains"])),
            "hosting_ips": ";".join(hosting_ips),
            "hosting_asns": ";".join(sorted(h_asns)),
            "hosting_as_names": ";".join(sorted(h_names)),
            "hosting_bgp_prefixes": ";".join(sorted(h_prefix)),
            "hosting_ptr": ";".join(sorted(h_ptr)),
            "geo_cc": ";".join(sorted(h_ccs)),
            "mail_ips": ";".join(mail_ips),
            "mail_asns": ";".join(sorted(m_asns)),
            "mail_as_names": ";".join(sorted(m_names)),
            # union kept for completeness / backwards compatibility
            "ips": ";".join(sorted(set(hosting_ips) | set(mail_ips))),
            "asns": ";".join(sorted(h_asns | m_asns)),
            "as_names": ";".join(sorted(h_names | m_names)),
        })

    csv_path = os.path.join(OUT_DIR, "domain_infrastructure.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # ---------------- pivot clustering ----------------
    def cluster(keyfn, label):
        buckets = defaultdict(list)
        for row in rows:
            for k in keyfn(row):
                if k:
                    buckets[k].append(row["domain"])
        return {
            "selector_type": label,
            "clusters": sorted(
                ({"selector": k, "count": len(v), "domains": sorted(v)}
                 for k, v in buckets.items() if len(v) > 1),
                key=lambda c: -c["count"],
            ),
        }

    def dkim_keys(row_domain):
        out = []
        for sel, vals in by_dom[row_domain]["dkim"].items():
            for v in vals:
                m = re.search(r"p=([A-Za-z0-9+/=]{40,})", v)
                if m:
                    out.append(f"{sel}:{m.group(1)[:64]}")
        return out

    pivots = {
        "dkim_key": cluster(lambda r: dkim_keys(r["domain"]), "shared DKIM public key"),
        "spf_manager_tenant": cluster(lambda r: r["spf_manager_tenant"].split(";"),
                                      "shared SPF-management tenant"),
        "dmarc_tenant": cluster(lambda r: r["dmarc_tenant"].split(";"),
                                "shared DMARC reporting-platform account"),
        "verification_token": cluster(lambda r: r["verification_tokens"].split(";"),
                                      "shared provider verification token"),
        "dmarc_rua": cluster(lambda r: r["dmarc_rua"].split(";"),
                             "shared DMARC reporting address"),
        "hosting_ip": cluster(lambda r: r["hosting_ips"].split(";"), "shared hosting IP"),
        "hosting_ptr": cluster(lambda r: r["hosting_ptr"].split(";"),
                               "shared hosting reverse-DNS hostname"),
        "soa_rname": cluster(lambda r: [r["soa_rname"]], "SOA responsible-party mailbox"),
        "nameserver_host": cluster(lambda r: r["ns"].split(";"),
                                   "shared authoritative nameserver"),
        "cname_target": cluster(lambda r: [x for x in r["cname"].split(";") if x],
                                "shared CNAME target"),
        "hosting_bgp_prefix": cluster(lambda r: r["hosting_bgp_prefixes"].split(";"),
                                      "shared hosting BGP prefix"),
        "mx_host": cluster(lambda r: [m.split()[-1].rstrip(".") for m in r["mx"].split(";") if m],
                           "shared MX host"),
        "spf_include": cluster(lambda r: r["spf_includes"].split(";"), "shared SPF include"),
        "ns_operator": cluster(lambda r: [r["ns_operator"]], "DNS operator / registrar"),
        "mx_provider": cluster(lambda r: [r["mx_provider"]], "mail provider"),
        "hosting_asn": cluster(lambda r: [f"AS{a}" for a in r["hosting_asns"].split(";") if a],
                               "shared hosting ASN"),
    }

    with open(os.path.join(OUT_DIR, "pivot_clusters.json"), "w") as fh:
        json.dump({"generated_utc": datetime.now(timezone.utc).isoformat(),
                   "pivots": pivots}, fh, indent=2)

    print(f"[+] wrote {csv_path}")
    print(f"[+] wrote {os.path.join(OUT_DIR,'pivot_clusters.json')}")
    return rows, pivots, data


if __name__ == "__main__":
    main()
