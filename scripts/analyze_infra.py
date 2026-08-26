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



# ---------------- registration (RDAP) ----------------
REGISTRAR_LABEL = [
    (r"godaddy", "GoDaddy"), (r"namecheap", "Namecheap"), (r"cloudflare", "Cloudflare"),
    (r"squarespace|google", "Squarespace (ex-Google Domains)"), (r"hostinger", "Hostinger"),
    (r"name\.com", "Name.com"), (r"wix", "Wix"), (r"porkbun", "Porkbun"),
    (r"namesilo", "NameSilo"), (r"dynadot", "Dynadot"), (r"tucows|hover|enom", "Tucows"),
    (r"markmonitor", "MarkMonitor"), (r"network solutions|register\.com|web\.com", "Network Solutions / Web.com"),
    (r"ionos|1&1", "IONOS"), (r"gandi", "Gandi"), (r"spaceship", "Spaceship"),
    (r"publicdomainregistry|pdr", "PDR"), (r"key-systems|rrpproxy", "Key-Systems"),
    (r"amazon", "Amazon Registrar"), (r"ru-center|nic\.ru", "RU-CENTER"),
    (r"cira|webnames", "Webnames.ca"), (r"nominet", "Nominet"),
]


def registrar_label(name):
    n = (name or "").lower()
    for pat, label in REGISTRAR_LABEL:
        if re.search(pat, n):
            return label
    return (name or "")[:40] or "unknown"


def load_rdap():
    """domain -> flattened registration record (empty dict when not collected)."""
    p = os.path.join(OUT_DIR, "rdap_enumeration.json")
    if not os.path.exists(p):
        return {}
    data = json.load(open(p))
    return {r["domain"]: r for r in data.get("records", [])}


def _geo_key(rg):
    if not rg or not (rg.get("country") or rg.get("region")):
        return None
    return f"{(rg.get('country') or '?').upper()}|{rg.get('region') or '?'}"


def placeholder_geos():
    """(registrar, geo) pairs that are the registrar's own placeholder, not the
    registrant's location. Decided from the control population: if nearly every
    redacted record a registrar returns carries the same state/country, that value
    is the registrar's default (Hostinger answers LT for everyone, Squarespace
    Domains LLC answers New York), and it must not be pivoted on. Returns
    {(registrar, geo): (share, n)} for pairs with n >= 5 and share >= 0.8."""
    p = os.path.join(OUT_DIR, "rdap_controls.json")
    if not os.path.exists(p):
        return {}
    per = defaultdict(Counter)
    for r in json.load(open(p)).get("records", []):
        m = r.get("rdap") or {}
        rg = m.get("registrant") or {}
        if rg.get("disclosure") == "redacted" and _geo_key(rg):
            per[m.get("registrar")][_geo_key(rg)] += 1
    out = {}
    for reg, c in per.items():
        n = sum(c.values())
        geo, k = c.most_common(1)[0]
        if n >= 5 and k / n >= 0.8:
            out[(reg, geo)] = (round(k / n, 2), n)
    return out, {reg: c for reg, c in per.items()}


PLACEHOLDER_GEO, GEO_CONTROL = placeholder_geos()


def geo_control_check(registrar_raw, geo):
    """How the control population bears on a (registrar, geo) pair:
    (verdict, controls_same_geo, controls_with_geo_at_registrar)."""
    c = GEO_CONTROL.get(registrar_raw, Counter())
    n = sum(c.values())
    k = c.get(geo, 0)
    if (registrar_raw, geo) in PLACEHOLDER_GEO:
        return "registrar placeholder", k, n
    if n < 5:
        return "unverified (too few controls at this registrar)", k, n
    if k / n >= 0.15:
        return "common among controls too (population trait)", k, n
    return "rare among controls", k, n


def registration_fields(rec, now):
    """Flat registration columns for one domain. Registrant geography is kept only
    where the registrar retained the registrant's own state/country (disclosed or
    redacted records); a proxy service's address is never treated as geography, and
    neither is a registrar's control-verified placeholder value."""
    empty = {"registered": "", "registrar": "", "registrar_raw": "", "registrar_iana_id": "", "reseller": "",
             "created": "", "created_day": "", "expires": "", "last_changed": "",
             "time_basis": "", "domain_age_days": "", "epp_status": "",
             "registrant_disclosure": "", "registrant_proxy_service": "",
             "registrant_org": "", "registrant_geo": "", "abuse_email": "", "rdap_source": ""}
    if not rec:
        return empty
    m = rec.get("rdap") or {}
    reg = rec.get("registered")
    out = dict(empty)
    out["registered"] = "yes" if reg else ("no" if reg is False else "unknown")
    out["rdap_source"] = rec.get("source") or ""
    if not m:
        return out
    rg = m.get("registrant") or {}
    created = m.get("created") or ""
    out.update({
        "registrar": registrar_label(m.get("registrar")),
        "registrar_raw": m.get("registrar") or "",
        "registrar_iana_id": m.get("registrar_iana_id") or "",
        "reseller": m.get("reseller") or "",
        "created": created,
        "created_day": created[:10],
        "expires": m.get("expires") or "",
        "last_changed": m.get("last_changed") or "",
        "time_basis": m.get("time_basis") or "",
        "epp_status": ";".join(m.get("status") or []),
        "registrant_disclosure": rg.get("disclosure") or ("absent" if rec.get("registrar") else ""),
        "registrant_proxy_service": rg.get("proxy_service") or "",
        "abuse_email": m.get("abuse_email") or "",
    })
    if rg.get("disclosure") == "disclosed":
        # organisations only: a disclosed individual's name stays in the raw
        # evidence file and is not carried into the flat table or the report
        org_like = re.compile(r"\b(llc|inc|ltd|limited|corp|gmbh|ag|s\.?a\.?s?|bv|b\.v\.|e\.k\.|"
                              r"oy|ab|pty|plc|llp|co\b|company|technolog|solutions|services)",
                              re.I)
        cand = rg.get("org") or ""
        if not cand and rg.get("name") and (rg.get("kind") == "org" or org_like.search(rg["name"])):
            cand = rg["name"]
        out["registrant_org"] = cand
    geo = _geo_key(rg)
    if rg.get("disclosure") in ("disclosed", "redacted") and geo:
        if (m.get("registrar"), geo) in PLACEHOLDER_GEO:
            out["registrant_disclosure"] = "redacted (registrar placeholder geo)"
        else:
            out["registrant_geo"] = geo
    if len(created) >= 10:
        try:
            c = datetime.fromisoformat(created[:19]).replace(tzinfo=timezone.utc)
            out["domain_age_days"] = (now - c).days
        except ValueError:
            pass
    return out


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

    rdap = load_rdap()
    now = datetime.now(timezone.utc)

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
            **registration_fields(rdap.get(d["domain"]), now),
        })

    csv_path = os.path.join(OUT_DIR, "domain_infrastructure.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
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
        # registration-derived selectors (populated only when RDAP was collected)
        "registrant_org": cluster(lambda r: [r["registrant_org"]],
                                  "shared disclosed registrant organisation"),
        "registration_day": cluster(
            lambda r: [f"{r['registrar']}|{r['created_day']}"] if r["created_day"] else [],
            "same registrar, same registration day"),
        "last_changed_day": cluster(
            lambda r: [f"{r['registrar']}|{r['last_changed'][:10]}"] if r["last_changed"] else [],
            "same registrar, same registry last-changed day"),
        "registrant_geo": cluster(lambda r: [r["registrant_geo"]],
                                  "shared retained registrant state/country"),
        "registrar": cluster(lambda r: [r["registrar"]] if r["registrar"] else [],
                             "registrar of record"),
    }

    with open(os.path.join(OUT_DIR, "pivot_clusters.json"), "w") as fh:
        json.dump({"generated_utc": datetime.now(timezone.utc).isoformat(),
                   "pivots": pivots}, fh, indent=2)

    print(f"[+] wrote {csv_path}")
    print(f"[+] wrote {os.path.join(OUT_DIR,'pivot_clusters.json')}")
    return rows, pivots, data


if __name__ == "__main__":
    main()
