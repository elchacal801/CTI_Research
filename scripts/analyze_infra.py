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
    toks = []
    for t in txts:
        for pat in (r"google-site-verification=([\w\-]+)",
                    r"^MS=([\w\-]+)", r"facebook-domain-verification=([\w\-]+)",
                    r"atlassian-domain-verification=([\w\-/+=]+)",
                    r"zoho-verification=([\w\-\.]+)",
                    r"^apple-domain-verification=([\w\-]+)"):
            m = re.search(pat, t, re.I)
            if m:
                toks.append(f"{pat.split('=')[0].strip('^()\\\\w-')}:{m.group(1)}"
                            if False else m.group(0))
    return sorted(set(toks))


def main():
    data = json.load(open(IN_JSON))
    ipintel = data["ip_intel"]
    domains = data["domains"]

    rows = []
    for d in domains:
        r = d["records"]
        mx_hosts = [m.split()[-1].rstrip(".").lower() for m in r["MX"]]
        ns_hosts = [n.rstrip(".").lower() for n in r["NS"]]
        ns_bases = sorted({base_domain(n) for n in ns_hosts})
        soa_rname = r["SOA"][0].split()[1].rstrip(".") if r["SOA"] else ""
        pol, rua, ruf = dmarc_fields(d["dmarc"])

        asns, as_names, ccs, prefixes, ptrs = set(), set(), set(), set(), set()
        for ip in d["ips"]:
            info = ipintel.get(ip) or {}
            if info.get("asn"):
                asns.add(info["asn"])
                as_names.add(info.get("as_name") or "")
                ccs.add(info.get("cc") or "")
                prefixes.add(info.get("bgp_prefix") or "")
            for p in info.get("ptr", []):
                ptrs.add(p)

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
            "soa_rname": soa_rname,
            "soa_serial": r["SOA"][0].split()[2] if r["SOA"] else "",
            "mx": ";".join(r["MX"]),
            "mx_provider": mx_provider(mx_hosts),
            "spf": ";".join(t for t in r["TXT"] if t.lower().startswith("v=spf1")),
            "spf_includes": ";".join(spf_includes(r["TXT"])),
            "txt_all": " | ".join(r["TXT"]),
            "verification_tokens": ";".join(verification_tokens(r["TXT"])),
            "caa": ";".join(r["CAA"]),
            "dmarc": ";".join(d["dmarc"]),
            "dmarc_policy": pol or "",
            "dmarc_rua": ";".join(rua),
            "dmarc_ruf": ";".join(ruf),
            "dkim_selectors": ";".join(sorted(d["dkim"])),
            "mta_sts": ";".join(d["mta_sts"]),
            "tls_rpt": ";".join(d["tls_rpt"]),
            "subdomains_found": ";".join(sorted(d["subdomains"])),
            "ips": ";".join(d["ips"]),
            "asns": ";".join(sorted(asns)),
            "as_names": ";".join(sorted(x for x in as_names if x)),
            "bgp_prefixes": ";".join(sorted(x for x in prefixes if x)),
            "geo_cc": ";".join(sorted(x for x in ccs if x)),
            "ptr": ";".join(sorted(ptrs)),
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
        for d in domains:
            if d["domain"] != row_domain:
                continue
            for sel, vals in d["dkim"].items():
                for v in vals:
                    m = re.search(r"p=([A-Za-z0-9+/=]{40,})", v)
                    if m:
                        out.append(f"{sel}:{m.group(1)[:64]}")
        return out

    pivots = {
        "nameserver_host": cluster(lambda r: r["ns"].split(";"), "shared authoritative nameserver"),
        "ns_operator": cluster(lambda r: [r["ns_operator"]], "DNS operator / registrar"),
        "soa_rname": cluster(lambda r: [r["soa_rname"]], "SOA responsible-party mailbox"),
        "mx_host": cluster(lambda r: [m.split()[-1].rstrip(".") for m in r["mx"].split(";") if m],
                           "shared MX host"),
        "mx_provider": cluster(lambda r: [r["mx_provider"]], "mail provider"),
        "ip_address": cluster(lambda r: r["ips"].split(";"), "shared IP address"),
        "bgp_prefix": cluster(lambda r: r["bgp_prefixes"].split(";"), "shared BGP prefix"),
        "asn": cluster(lambda r: [f"AS{a}" for a in r["asns"].split(";") if a], "shared ASN"),
        "spf_include": cluster(lambda r: r["spf_includes"].split(";"), "shared SPF include"),
        "verification_token": cluster(lambda r: r["verification_tokens"].split(";"),
                                      "shared provider verification token"),
        "dmarc_rua": cluster(lambda r: r["dmarc_rua"].split(";"), "shared DMARC reporting address"),
        "dkim_key": cluster(lambda r: dkim_keys(r["domain"]), "shared DKIM public key"),
        "ptr_hostname": cluster(lambda r: r["ptr"].split(";"), "shared reverse-DNS hostname"),
    }

    with open(os.path.join(OUT_DIR, "pivot_clusters.json"), "w") as fh:
        json.dump({"generated_utc": datetime.now(timezone.utc).isoformat(),
                   "pivots": pivots}, fh, indent=2)

    print(f"[+] wrote {csv_path}")
    print(f"[+] wrote {os.path.join(OUT_DIR,'pivot_clusters.json')}")
    return rows, pivots, data


if __name__ == "__main__":
    main()
