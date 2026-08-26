#!/usr/bin/env python3
"""
RDAP (and WHOIS port-43 fallback) enumeration for the CTI domain set.

RDAP is the structured replacement for WHOIS and the preferred source for
registrar, registration/expiry dates, EPP status codes, registrant contact
disclosure and delegated nameservers.

Collection is two-stage. The registry RDAP server (resolved from the IANA
bootstrap, with a small override table for ccTLDs the bootstrap does not list)
is authoritative for dates, status and nameservers. Thin registries such as
.com/.net carry no registrant data, so the `related` link they publish into the
registrar's own RDAP server is followed and the registrant, abuse-contact and
reseller fields are merged from there.

Where a registry offers no usable RDAP at all (.co refuses public lookups; .ru
has none), the registrar is guessed from the delegated nameservers and its RDAP
server -- taken from the IANA registrar-ID registry -- is queried directly,
falling back through a short list of major registrars, then to WHOIS/43.

Registrant data is classified before it is used. Almost every registrar
substitutes a privacy/proxy service for the registrant, and the proxy's own
address (Domains By Proxy in Tempe AZ, Withheld for Privacy in Reykjavik,
Domain Protection Services in Denver) then appears in the `registrant` entity.
Treating that as registrant geography would cluster every GoDaddy customer in
Arizona. Records are therefore tagged `proxy:<service>`, `redacted`,
`disclosed` or `absent`; only `disclosed` (and, for state/country only,
`redacted`) fields are pivotable downstream.

This script is network-egress sensitive: it needs outbound HTTPS to the
registry/registrar RDAP servers, or outbound TCP/43 for the WHOIS fallback.
Where those are blocked it records the failure per-domain rather than
aborting, so a run is replayable from a network that permits the egress.

Usage:
  enumerate_rdap.py                          # corpus + discovered -> output/rdap_enumeration.json
  enumerate_rdap.py --controls               # expansion-sweep controls -> output/rdap_controls.json
  enumerate_rdap.py --domains-file x.txt --out y.json
"""
import csv, json, os, re, socket, sys, time, threading, argparse
import urllib.request, urllib.error
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_CSV = os.path.join(ROOT, "data", "Domain_Summary_Reconstructed.csv")
IN_DISCOVERED = os.path.join(ROOT, "data", "Discovered_Domains.csv")
IN_EXPANSION = os.path.join(ROOT, "output", "cluster_expansion.json")
DNS_JSONS = [os.path.join(ROOT, "output", "dns_enumeration.json"),
             os.path.join(ROOT, "output", "discovered_enumeration.json")]
OUT_JSON = os.path.join(ROOT, "output", "rdap_enumeration.json")
OUT_CONTROLS = os.path.join(ROOT, "output", "rdap_controls.json")

IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
IANA_REGISTRARS = "https://www.iana.org/assignments/registrar-ids/registrar-ids.xml"
REDIRECTOR = "https://rdap.org/domain/"          # generic fallback (302 -> registry)

# ccTLDs absent from the IANA gTLD bootstrap. None = registry RDAP unavailable.
TLD_RDAP_OVERRIDES = {
    "io": "https://rdap.identitydigital.services/rdap/",
    "me": "https://rdap.identitydigital.services/rdap/",
    "us": "https://rdap.nic.us/",
    "ch": "https://rdap.nic.ch/",
    "co": None,   # rdap.registry.co / whois.registry.co answer "not found" for every name
    "ru": None,   # no RDAP; TCI WHOIS only
}
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "io": "whois.nic.io", "me": "whois.nic.me",
    "uk": "whois.nic.uk", "ca": "whois.cira.ca", "ru": "whois.tcinet.ru",
    "ch": "whois.nic.ch", "no": "whois.norid.no", "in": "whois.registry.in",
    "us": "whois.nic.us", "ai": "whois.nic.ai",
}
# Delegated-nameserver suffix -> registrar name (as it appears in the IANA list).
NS_TO_REGISTRAR = [
    ("domaincontrol.com", "GoDaddy.com, LLC"),
    ("registrar-servers.com", "NameCheap, Inc."),
    ("ns.cloudflare.com", "Cloudflare, Inc."),
    ("dns-parking.com", "HOSTINGER operations, UAB"),
    ("hostinger.com", "HOSTINGER operations, UAB"),
    ("squarespacedns.com", "Squarespace Domains II LLC"),
    ("googledomains.com", "Squarespace Domains II LLC"),
    ("wixdns.net", "Wix.com Ltd."),
    ("dnsowl.com", "NameSilo, LLC"),
    ("name.com", "Name.com, Inc."),
    ("porkbun.com", "Porkbun LLC"),
    ("dynadot.com", "Dynadot Inc"),
    ("spaceship.net", "Spaceship, Inc."),
    ("namebrightdns.com", "TurnCommerce, Inc. DBA NameBright.com"),
    ("worldnic.com", "Network Solutions, LLC"),
    ("register.com", "Register.com - Network Solutions, LLC"),
    ("ionos.com", "IONOS SE"),
    ("gandi.net", "Gandi SAS"),
    ("hover.com", "Tucows Domains Inc."),
    ("bluehost.com", "Bluehost Inc."),
]
REGISTRAR_SWEEP = ["GoDaddy.com, LLC", "NameCheap, Inc.", "Cloudflare, Inc.",
                   "Squarespace Domains II LLC", "Name.com, Inc.", "HOSTINGER operations, UAB",
                   "Porkbun LLC", "NameSilo, LLC", "Dynadot Inc", "Tucows Domains Inc.",
                   "Wix.com Ltd.", "Network Solutions, LLC", "IONOS SE", "Spaceship, Inc."]
UA = "Mozilla/5.0 (compatible; rdap-enum/1.2)"

# Privacy / proxy services that registrars substitute for the registrant.
PROXY_SERVICES = [
    ("Domains By Proxy", "Domains By Proxy (GoDaddy)"),
    ("Registration Private", "Domains By Proxy (GoDaddy)"),
    ("Withheld for Privacy", "Withheld for Privacy (Namecheap)"),
    ("Contact Privacy Inc", "Contact Privacy (Tucows/Google/Squarespace)"),
    ("Domain Protection Services", "Domain Protection Services (Name.com)"),
    ("WhoisGuard", "WhoisGuard (Namecheap)"),
    ("PrivacyGuardian", "PrivacyGuardian (NameSilo)"),
    ("Privacy Protect", "PrivacyProtect.org (Hostinger et al.)"),
    ("PrivacyProtect", "PrivacyProtect.org (Hostinger et al.)"),
    ("Private by Design", "Private by Design (Porkbun)"),
    ("Super Privacy Service", "Super Privacy Service (Dynadot)"),
    ("Perfect Privacy", "Perfect Privacy (Web.com)"),
    ("FBO Registrant", "Domain Privacy Service FBO Registrant (Newfold)"),
    ("Whois Privacy", "Whois Privacy service"),
    ("Privacy service provided by", "registrar privacy service"),
    ("Identity Protection Service", "Identity Protection Service"),
    ("Whois Agent", "Whois Agent"),
    ("Domain Privacy", "Domain Privacy service"),
    ("Proxy Protection", "Proxy Protection"),
    ("Privacy Administrator", "Privacy Administrator"),
    ("Anonymize", "Anonymize (Epik)"),
    ("Privacy Hero", "Privacy Hero"),
    ("On behalf of", "registrar proxy (on behalf of)"),
    ("c/o ", "registrar proxy (c/o)"),
]
REDACTED_MARKERS = ["REDACTED", "DATA PROTECTED", "NOT DISCLOSED", "GDPR", "MASKED",
                    "STATUTORY", "PRIVATE", "WITHHELD", "N/A", "NOT AVAILABLE"]
EPP_STATUSES = ["clientDeleteProhibited", "clientHold", "clientRenewProhibited",
                "clientTransferProhibited", "clientUpdateProhibited", "serverDeleteProhibited",
                "serverHold", "serverRenewProhibited", "serverTransferProhibited",
                "serverUpdateProhibited", "pendingCreate", "pendingDelete", "pendingRenew",
                "pendingRestore", "pendingTransfer", "pendingUpdate", "inactive", "ok",
                "active", "autoRenewPeriod", "addPeriod", "redemptionPeriod", "renewPeriod",
                "transferPeriod", "locked", "associated", "registered", "delegated",
                "verified", "unverified"]
_EPP = {re.sub(r"[^a-z]", "", s.lower()): s for s in EPP_STATUSES}
# Registrar-side RDAP (GoDaddy) drops the client/server prefix; registrar-set locks are client*.
_EPP.update({"deleteprohibited": "clientDeleteProhibited", "renewprohibited": "clientRenewProhibited",
             "transferprohibited": "clientTransferProhibited",
             "updateprohibited": "clientUpdateProhibited", "hold": "clientHold"})

_lock = threading.Lock()
_done = {"n": 0, "total": 0}
_bootstrap = {}
_registrar_rdap = {}       # registrar name -> RDAP base
_ns_map = {}               # domain -> [nameservers] (from DNS enumeration)


# ---------------------------------------------------------------- transport
def http_json(url, timeout=25, tries=3):
    """GET JSON with retry on transient failures. Returns (status, json|None, err|None)."""
    last = None
    for attempt in range(tries):
        req = urllib.request.Request(url, headers={
            "Accept": "application/rdap+json, application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                return resp.status, json.loads(body), None
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            if e.code in (429, 500, 502, 503, 504) and attempt < tries - 1:
                time.sleep(2 + 3 * attempt)
                last = f"HTTP {e.code}"
                continue
            return e.code, None, f"HTTP {e.code} {body.strip()[:160]}"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
            if attempt < tries - 1:
                time.sleep(1 + 2 * attempt)
                continue
    return None, None, last


def whois43(domain, server, timeout=15):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((domain + "\r\n").encode())
        buf = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
    return buf.decode("utf-8", "replace")


def load_bootstrap():
    """TLD -> registry RDAP base URL from the IANA bootstrap, plus ccTLD overrides."""
    m = {}
    st, js, err = http_json(IANA_BOOTSTRAP)
    if js:
        for entry in js.get("services", []):
            for tld in entry[0]:
                m[tld.lower()] = entry[1][0].rstrip("/") + "/"
    else:
        print(f"[!] IANA bootstrap unavailable ({err})", file=sys.stderr)
    for tld, base in TLD_RDAP_OVERRIDES.items():
        if base:
            m[tld] = base
        else:
            m.pop(tld, None)
    return m


def load_registrar_rdap():
    """Registrar name -> RDAP base URL from the IANA registrar-ID registry."""
    out = {}
    try:
        req = urllib.request.Request(IANA_REGISTRARS, headers={"User-Agent": UA})
        raw = urllib.request.urlopen(req, timeout=30).read()
        ns = "{http://www.iana.org/assignments}"
        for r in ET.fromstring(raw).iter(ns + "record"):
            name = r.find(ns + "name")
            u = r.find(ns + "rdapurl")
            srv = u.find(ns + "server") if u is not None else None
            url = (srv.text if srv is not None else (u.text if u is not None else "")) or ""
            if name is not None and url.strip():
                out[name.text.strip()] = url.strip().rstrip("/") + "/"
    except Exception as e:  # noqa: BLE001
        print(f"[!] IANA registrar list unavailable ({e}); registrar fallback disabled",
              file=sys.stderr)
    return out


def load_ns_map():
    m = {}
    for p in DNS_JSONS:
        if os.path.exists(p):
            for d in json.load(open(p)).get("domains", []):
                m[d["domain"]] = [n.rstrip(".").lower() for n in d["records"].get("NS", [])]
    return m


# ---------------------------------------------------------------- parsing
def vcard_get(ent, field):
    for item in ent.get("vcardArray", [[], []])[1]:
        if item and item[0] == field:
            return item[3], item[1]
    return None, {}


def classify_registrant(fn, org, has_entity=True):
    text = f"{fn or ''} | {org or ''}"
    for needle, label in PROXY_SERVICES:
        if needle.lower() in text.lower():
            return "proxy", label
    if not ((fn or "").strip() or (org or "").strip()):
        return ("redacted" if has_entity else "absent"), None
    if any(m in text.upper() for m in REDACTED_MARKERS):
        return "redacted", None
    return "disclosed", None


def norm_status(status):
    """EPP status names as canonical camelCase tokens whatever the source spelling."""
    out = set()
    for s in status or []:
        for tok in re.split(r"[,;]", s):
            tok = tok.strip()
            if not tok:
                continue
            tok = tok.split(" http")[0].split(" (")[0]
            key = re.sub(r"[^a-z]", "", tok.lower())
            if key:
                out.add(_EPP.get(key, tok))
    return sorted(out)


def parse_rdap(js, side):
    """Flatten an RDAP domain object. `side` is 'registry' or 'registrar'."""
    out = {"side": side, "handle": js.get("handle"), "registrar": None,
           "registrar_iana_id": None, "registrar_url": None, "abuse_email": None,
           "abuse_phone": None, "reseller": None, "created": None, "expires": None,
           "last_changed": None, "registrar_expiration": None, "transfer": None,
           "status": norm_status(js.get("status", [])), "nameservers": [],
           "dnssec": (js.get("secureDNS") or {}).get("delegationSigned"),
           "registrant": None, "related_rdap": None, "redacted_fields": None,
           "port43": js.get("port43")}

    for ev in js.get("events", []):
        a, d = ev.get("eventAction"), ev.get("eventDate")
        if a == "registration":
            out["created"] = d
        elif a == "expiration":
            out["expires"] = d
        elif a == "registrar expiration":
            out["registrar_expiration"] = d
        elif a == "last changed":
            out["last_changed"] = d
        elif a == "transfer":
            out["transfer"] = d

    out["nameservers"] = sorted({(ns.get("ldhName") or "").lower().rstrip(".")
                                 for ns in js.get("nameservers", []) if ns.get("ldhName")})

    for link in js.get("links", []):
        if link.get("rel") == "related" and "rdap" in (link.get("type", "") + link.get("href", "")):
            out["related_rdap"] = link.get("href")

    if isinstance(js.get("redacted"), list):
        names = []
        for rd in js["redacted"]:
            nm = rd.get("name") or {}
            names.append(nm.get("description") or nm.get("type") or "?")
        out["redacted_fields"] = names

    for ent in js.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles and not out["registrar"]:
            out["registrar"] = vcard_get(ent, "fn")[0] or ent.get("handle")
            for pid in ent.get("publicIds", []):
                if "IANA" in str(pid.get("type", "")):
                    out["registrar_iana_id"] = str(pid.get("identifier"))
            for link in ent.get("links", []):
                if link.get("rel") == "about":
                    out["registrar_url"] = link.get("href")
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    out["abuse_email"] = out["abuse_email"] or vcard_get(sub, "email")[0]
                    out["abuse_phone"] = out["abuse_phone"] or vcard_get(sub, "tel")[0]
            if not out["abuse_email"]:
                out["abuse_email"] = vcard_get(ent, "email")[0]
        if "reseller" in roles:
            out["reseller"] = vcard_get(ent, "fn")[0] or vcard_get(ent, "org")[0]
        if "registrant" in roles:
            fn, _ = vcard_get(ent, "fn")
            org, _ = vcard_get(ent, "org")
            adr, adr_params = vcard_get(ent, "adr")
            email, _ = vcard_get(ent, "email")
            cc, region, locality = None, None, None
            if isinstance(adr, list) and len(adr) >= 7:
                locality, region, cc = adr[3] or None, adr[4] or None, adr[6] or None
            cc = cc or adr_params.get("cc")
            kind, proxy = classify_registrant(fn, org, has_entity=True)
            out["registrant"] = {"name": fn or None, "org": org or None, "email": email,
                                 "country": cc, "region": region, "locality": locality,
                                 "kind": vcard_get(ent, "kind")[0],
                                 "disclosure": kind, "proxy_service": proxy,
                                 "handle": ent.get("handle")}
    return out


WHOIS_FIELDS = [
    ("created", r"^\s*(?:Creation Date|Created(?: On)?|created|Registered on|Registration Date|First registration date)\s*:\s*\n?\s*(\S.*)$"),
    ("expires", r"^\s*(?:Registry Expiry Date|Expiry date|Expiration Date|paid-till|Expires On)\s*:\s*\n?\s*(\S.*)$"),
    ("last_changed", r"^\s*(?:Updated Date|Last updated|Last Modified|changed)\s*:\s*\n?\s*(\S.*)$"),
    ("registrar", r"^\s*(?:Registrar|registrar|Sponsoring Registrar)\s*:\s*\n?\s*(\S.*)$"),
    ("registrar_iana_id", r"^\s*Registrar IANA ID\s*:\s*(.+)$"),
    ("abuse_email", r"^\s*Registrar Abuse Contact Email\s*:\s*(.+)$"),
    ("registrant_org", r"^\s*Registrant Organi[sz]ation\s*:\s*(.+)$"),
    ("registrant_country", r"^\s*Registrant Country\s*:\s*(.+)$"),
    ("registrant_state", r"^\s*Registrant State/Province\s*:\s*(.+)$"),
]


def parse_whois(raw):
    out = {"side": "whois", "status": [], "nameservers": []}
    for key, pat in WHOIS_FIELDS:
        m = re.search(pat, raw, re.I | re.M)
        if m and key not in out:
            out[key] = m.group(1).strip()
    out["status"] = norm_status(
        re.findall(r"^\s*(?:Domain Status|state)\s*:\s*(.+)$", raw, re.I | re.M))
    out["nameservers"] = sorted({n.strip().lower().rstrip(".") for n in
                                 re.findall(r"^\s*(?:Name Server|nserver)\s*:\s*(\S+)", raw, re.I | re.M)})
    if out.get("registrant_org") or out.get("registrant_country"):
        kind, proxy = classify_registrant(None, out.get("registrant_org"), has_entity=True)
        out["registrant"] = {"name": None, "org": out.pop("registrant_org", None),
                             "country": out.pop("registrant_country", None),
                             "region": out.pop("registrant_state", None),
                             "disclosure": kind, "proxy_service": proxy}
    not_found = re.search(r"No match for|NOT FOUND|No Data Found|No entries found|not registered|"
                          r"does not exist", raw, re.I)
    return out, bool(not_found)


# ---------------------------------------------------------------- per-domain
def merge(registry, registrar):
    """Registry is authoritative for dates/status/NS; registrar supplies the rest."""
    m = dict(registry)
    if registrar:
        for k in ("registrant", "reseller", "redacted_fields", "registrar_expiration"):
            if registrar.get(k) is not None:
                m[k] = registrar[k]
        for k in ("abuse_email", "abuse_phone", "registrar_url", "registrar_iana_id", "registrar"):
            if not m.get(k) and registrar.get(k):
                m[k] = registrar[k]
        m["registrar_status"] = registrar.get("status")
        for k in ("created", "expires"):
            if not m.get(k) and registrar.get(k):
                m[k] = registrar[k]
    if not m.get("expires") and m.get("registrar_expiration"):
        m["expires"] = m["registrar_expiration"]
    # Which side supplied the timestamps matters: registry times are UTC; some
    # registrar servers (GoDaddy) label local time as Z.
    m["time_basis"] = registry.get("side", "registry")
    m.pop("side", None)
    return m


def registrar_candidates(domain, meta):
    """Ordered registrar RDAP bases to try when the registry offers none."""
    nss = _ns_map.get(domain) or meta.get("ns_seen") or []
    names = []
    for ns in nss:
        for suffix, reg in NS_TO_REGISTRAR:
            if ns.endswith(suffix) and reg not in names:
                names.append(reg)
    for reg in REGISTRAR_SWEEP:
        if reg not in names:
            names.append(reg)
    return [(n, _registrar_rdap[n]) for n in names if n in _registrar_rdap]


def lookup(item):
    d, meta = item
    tld = d.rsplit(".", 1)[-1]
    rec = {"domain": d, "tld": tld, **meta, "registered": None, "ok": False,
           "registry_url": None, "registrar_url": None, "source": None,
           "errors": [], "registry": None, "registrar": None, "rdap": None,
           "whois_raw": None}

    urls = []
    if tld in _bootstrap:
        urls.append(("registry", _bootstrap[tld] + "domain/" + d))
    elif tld not in TLD_RDAP_OVERRIDES:
        urls.append(("redirector", REDIRECTOR + d))

    registry_js = None
    for kind, url in urls:
        st, js, err = http_json(url)
        if js and js.get("objectClassName") == "domain":
            registry_js = js
            rec["registry_url"] = url
            break
        if st == 404:
            rec["errors"].append(f"{kind}: HTTP 404")
            if kind == "registry":
                rec["registered"] = False          # authoritative: no such domain
            continue                               # rdap.org 404 is ambiguous
        rec["errors"].append(f"{kind}: {err}")

    if registry_js:
        reg = parse_rdap(registry_js, "registry")
        rec["registry"] = reg
        rec["registered"] = True
        rec["source"] = "rdap"
        rar = None
        if reg.get("related_rdap"):
            st, js, err = http_json(reg["related_rdap"], timeout=20, tries=2)
            if js and js.get("objectClassName") == "domain":
                rar = parse_rdap(js, "registrar")
                rec["registrar_url"] = reg["related_rdap"]
            else:
                rec["errors"].append(f"registrar: {err or 'non-domain response'}")
        rec["registrar"] = rar
        rec["rdap"] = merge(reg, rar)
        rec["ok"] = True
        rec["raw_registry"] = {k: v for k, v in registry_js.items()
                               if k not in ("notices", "rdapConformance", "links")}

    # No registry answer. Registry WHOIS first where one exists (cheap, authoritative
    # for existence); the registrar sweep only for TLDs whose registry offers nothing
    # usable, or where the registry RDAP errored rather than answering 404.
    registry_errored = any(e.startswith("registry:") and "404" not in e for e in rec["errors"])
    if not rec["ok"] and rec["registered"] is None and tld in WHOIS_SERVERS:
        try:
            raw = whois43(d, WHOIS_SERVERS[tld])
            rec["whois_raw"] = raw[:6000]
            parsed, not_found = parse_whois(raw)
            if not_found:
                rec["registered"] = False
            else:
                parsed.pop("side", None)
                parsed["time_basis"] = "whois"
                rec["rdap"] = parsed
                rec["registered"] = True
                rec["ok"] = True
                rec["source"] = f"whois://{WHOIS_SERVERS[tld]}"
        except Exception as e:  # noqa: BLE001
            rec["errors"].append(f"whois43: {type(e).__name__}: {e}")

    sweep_ok = (tld in TLD_RDAP_OVERRIDES and TLD_RDAP_OVERRIDES[tld] is None) or registry_errored
    if not rec["ok"] and rec["registered"] is None and _registrar_rdap and sweep_ok:
        tried = 0
        for name, base in registrar_candidates(d, meta):
            tried += 1
            st, js, err = http_json(base + "domain/" + d, timeout=20, tries=2)
            if js and js.get("objectClassName") == "domain":
                rar = parse_rdap(js, "registrar")
                rec["registrar"] = rar
                rec["registrar_url"] = base + "domain/" + d
                rec["rdap"] = merge({k: v for k, v in rar.items()}, None)
                rec["rdap"]["registrar"] = rec["rdap"]["registrar"] or name
                rec["registered"] = True
                rec["ok"] = True
                rec["source"] = "registrar-rdap"
                rec["raw_registrar"] = {k: v for k, v in js.items()
                                        if k not in ("notices", "rdapConformance", "links")}
                break
        if not rec["ok"]:
            rec["errors"].append(f"registrar-rdap: no hit across {tried} registrars")
    elif not rec["ok"] and rec["registered"] is None:
        rec["errors"].append("no RDAP or WHOIS source for this TLD")

    with _lock:
        _done["n"] += 1
        if _done["n"] % 25 == 0:
            print(f"  {_done['n']}/{_done['total']}", file=sys.stderr, flush=True)
    return rec


# ---------------------------------------------------------------- inputs
def corpus_items():
    items = []
    for path, src in ((IN_CSV, "corpus"), (IN_DISCOVERED, "discovered")):
        if not os.path.exists(path):
            continue
        for row in csv.DictReader(open(path)):
            d = row["Domain"].strip().lower()
            if d:
                items.append((d, {"source_list": src,
                                  "domain_class": row.get("Domain Class", ""),
                                  "risk_tier": row.get("Risk Tier", "")}))
    return items


def control_items():
    """Registered, naming-adjacent domains from the expansion sweep that matched no
    cluster marker: an unrelated-population baseline for registrar and timing rates."""
    exp = json.load(open(IN_EXPANSION))
    items = []
    for det in exp["detail"]:
        if det.get("registered") and not det.get("group"):
            items.append((det["domain"], {"source_list": "expansion_control",
                                          "ns_seen": det.get("ns", [])}))
    return items


def retry_pass(path, pause):
    """Slow, single-threaded second pass over an existing output file: re-fetch
    registrar RDAP where the first pass was rate-limited (HTTP 429/5xx/timeouts) and
    re-run the registrar sweep for names the registry could not answer. Records are
    replaced in place; nothing that succeeded is touched."""
    data = json.load(open(path))
    todo = []
    for i, r in enumerate(data["records"]):
        rar_failed = any(e.startswith("registrar:") and "404" not in e for e in r["errors"])
        sweep_failed = any(e.startswith("registrar-rdap:") for e in r["errors"])
        if (r["ok"] and rar_failed and not r.get("registrar")) or (not r["ok"] and sweep_failed):
            todo.append(i)
    print(f"[*] retry pass over {path}: {len(todo)} records", file=sys.stderr)
    fixed = 0
    for n, i in enumerate(todo, 1):
        r = data["records"][i]
        d = r["domain"]
        meta = {k: r[k] for k in ("source_list", "domain_class", "risk_tier", "ns_seen") if k in r}
        if r["ok"] and r.get("registry"):
            url = r["registry"].get("related_rdap")
            st, js, err = http_json(url, timeout=25, tries=4) if url else (None, None, "no link")
            if js and js.get("objectClassName") == "domain":
                rar = parse_rdap(js, "registrar")
                r["registrar"] = rar
                r["registrar_url"] = url
                r["rdap"] = merge(r["registry"], rar)
                r["errors"] = [e for e in r["errors"] if not e.startswith("registrar:")]
                fixed += 1
            else:
                r["errors"] = [e for e in r["errors"] if not e.startswith("registrar:")]
                r["errors"].append(f"registrar (retry): {err or 'non-domain response'}")
        else:
            new = lookup((d, meta))
            _done["n"] -= 1
            if new["ok"]:
                data["records"][i] = new
                fixed += 1
        if n % 10 == 0:
            print(f"  retry {n}/{len(todo)} ({fixed} fixed)", file=sys.stderr, flush=True)
        time.sleep(pause)
    res = data["records"]
    data.update({
        "retry_pass_utc": datetime.now(timezone.utc).isoformat(),
        "retry_fixed": fixed,
        "succeeded": sum(1 for r in res if r["ok"]),
        "with_registrar_rdap": sum(1 for r in res if r.get("registrar")),
        "by_source": dict(sorted(
            ((s, sum(1 for r in res if r["source"] == s)) for s in {r["source"] for r in res}),
            key=lambda kv: -kv[1])),
        "not_registered": sum(1 for r in res if r["registered"] is False),
        "undetermined": sum(1 for r in res if r["registered"] is None),
    })
    data["failed"] = len(res) - data["succeeded"] - data["not_registered"]
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"[+] retry pass: {fixed}/{len(todo)} fixed; now {data['succeeded']} ok / "
          f"{data['with_registrar_rdap']} with registrar RDAP / {data['undetermined']} undetermined",
          file=sys.stderr)


def main():
    global _bootstrap, _registrar_rdap, _ns_map
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--controls", action="store_true",
                    help="enumerate the expansion-sweep control population instead")
    ap.add_argument("--domains-file", help="plain list of domains, one per line")
    ap.add_argument("--out", help="output path override")
    ap.add_argument("--retry", metavar="JSON",
                    help="slow second pass over an existing output file (rate-limited records)")
    ap.add_argument("--pause", type=float, default=2.0, help="seconds between retry requests")
    args = ap.parse_args()

    if args.retry:
        _bootstrap = load_bootstrap()
        _registrar_rdap = load_registrar_rdap()
        _ns_map = load_ns_map()
        _done["total"] = 10**9
        retry_pass(args.retry, args.pause)
        return

    if args.domains_file:
        items = [(l.strip().lower(), {"source_list": "file"}) for l in open(args.domains_file)
                 if l.strip() and not l.startswith("#")]
        out_path = args.out or os.path.join(ROOT, "output", "rdap_custom.json")
    elif args.controls:
        items = control_items()
        out_path = args.out or OUT_CONTROLS
    else:
        items = corpus_items()
        out_path = args.out or OUT_JSON
    if args.limit:
        items = items[: args.limit]
    _done["total"] = len(items)

    _bootstrap = load_bootstrap()
    _registrar_rdap = load_registrar_rdap()
    _ns_map = load_ns_map()
    print(f"[*] IANA bootstrap: {len(_bootstrap)} TLDs; {len(_registrar_rdap)} registrar RDAP "
          f"servers; RDAP/WHOIS for {len(items)} domains", file=sys.stderr)
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        res = list(ex.map(lookup, items))

    ok = sum(1 for r in res if r["ok"])
    unreg = sum(1 for r in res if r["registered"] is False)
    unknown = sum(1 for r in res if r["registered"] is None)
    with_registrar = sum(1 for r in res if r.get("registrar"))
    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "method": ("registry RDAP via the IANA bootstrap (ccTLD overrides for .io/.me/.us/.ch), "
                   "registrar RDAP followed via the registry's `related` link; where the "
                   "registry offers no RDAP the registrar is guessed from delegated NS and "
                   "queried directly (IANA registrar-ID list), then WHOIS/43"),
        "collection_note": ("collected from a network permitting outbound HTTPS to "
                            "registry/registrar RDAP servers and TCP/43"),
        "domains": len(res),
        "succeeded": ok,
        "with_registrar_rdap": with_registrar,
        "by_source": dict(sorted(
            ((s, sum(1 for r in res if r["source"] == s)) for s in {r["source"] for r in res}),
            key=lambda kv: -kv[1])),
        "not_registered": unreg,
        "undetermined": unknown,
        "failed": len(res) - ok - unreg,
        "elapsed_s": round(time.time() - t0, 1),
        "records": res,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] wrote {out_path}: {ok} ok / {unreg} unregistered / {unknown} undetermined "
          f"/ {with_registrar} with registrar RDAP, {out['elapsed_s']}s", file=sys.stderr)


if __name__ == "__main__":
    main()
