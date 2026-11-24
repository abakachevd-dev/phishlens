#!/usr/bin/env python3
"""PhishLens: an offline phishing email analyzer.

Usage: python phishlens.py samples/phish_paypal.eml -o report.html
"""
import argparse, html, json, re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
          "amazon": "amazon.com", "google": "google.com", "netflix": "netflix.com",
          "docusign": "docusign.com", "dhl": "dhl.com"}
URGENCY = ["urgent", "immediately", "within 24 hours", "account has been suspended",
           "act now", "final notice", "will be closed", "limited time"]
CREDS = ["verify your", "confirm your", "password", "log in", "login",
         "social security", "update your payment", "billing information"]
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".lnk", ".iso", ".jar",
             ".docm", ".xlsm", ".html", ".htm", ".zip"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
LEET = str.maketrans("0135", "oles")


class LinkParser(HTMLParser):
    """Collects (href, visible text) pairs and all visible text from HTML."""
    def __init__(self):
        super().__init__()
        self.links, self.text, self._href, self._buf = [], [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._buf = dict(attrs).get("href") or "", []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None


def dom(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(" >") if "@" in addr else ""


def same_org(a, b):
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def lookalike(domain):
    """Return (brand, real_domain) if `domain` imitates a known brand."""
    d = domain.lower()
    for brand, legit in BRANDS.items():
        if d == legit or d.endswith("." + legit):
            continue
        norm = d.translate(LEET).replace("rn", "m").replace("vv", "w").replace("-", "")
        if brand in norm:
            return brand, legit
    return None


def analyze(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    F = []

    def add(sev, pts, title, detail):
        F.append({"severity": sev, "points": pts, "title": title, "detail": detail})

    h = lambda k: str(msg.get(k) or "")
    name, addr = parseaddr(h("From"))
    fdom = dom(addr)

    # 1. Email authentication results written by the receiving server
    ar = h("Authentication-Results").lower()
    for proto, pts in (("spf", 12), ("dkim", 12), ("dmarc", 16)):
        m = re.search(proto + r"=(\w+)", ar)
        res = m.group(1) if m else "missing"
        if res in ("fail", "softfail", "permerror"):
            add("high", pts, f"{proto.upper()} {res}",
                f"The receiving server reported {proto.upper()}={res}, so the sender may not be who they claim.")
        elif res in ("none", "missing", "neutral"):
            add("medium", pts // 3, f"{proto.upper()} not verified",
                f"No passing {proto.upper()} result was found in the headers.")

    # 2. Sender identity
    for hdr in ("Reply-To", "Return-Path"):
        d = dom(parseaddr(h(hdr))[1])
        if d and fdom and not same_org(d, fdom):
            add("medium", 10, f"{hdr} domain mismatch",
                f"From is @{fdom} but {hdr} is @{d}, so replies go somewhere else.")
    hit = lookalike(fdom) if fdom else None
    if hit:
        add("high", 25, "Lookalike sender domain", f"@{fdom} imitates {hit[0].title()} ({hit[1]}).")
    else:
        for brand, legit in BRANDS.items():
            if brand in name.lower() and fdom and not same_org(fdom, legit):
                add("high", 15, "Display name impersonates a brand",
                    f'Name says "{name}" but the address is @{fdom}.')
                break

    # 3. Body language
    plain, htm = msg.get_body(("plain",)), msg.get_body(("html",))
    ptxt = plain.get_content() if plain else ""
    lp = LinkParser()
    lp.feed(htm.get_content() if htm else "")
    text = (ptxt + " " + " ".join(lp.text)).lower()
    urg = [w for w in URGENCY if w in text]
    if urg:
        add("medium", min(18, 6 * len(urg)), "Urgency language", "Pressure phrases found: " + ", ".join(urg) + ".")
    cr = [w for w in CREDS if w in text]
    if cr:
        add("medium", min(15, 5 * len(cr)), "Credential-harvesting language",
            "Asks for sensitive actions: " + ", ".join(cr) + ".")

    # 4. Links
    links = list(lp.links) + [(u, "") for u in re.findall(r"https?://[^\s<>\"]+", ptxt)]
    seen = set()
    for href, label in links:
        host = (urlparse(href).hostname or "").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        shown = re.search(r"([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})", label.lower())
        if shown and not same_org(shown.group(1).replace("www.", ""), host.replace("www.", "")):
            add("high", 20, "Link text doesn't match destination",
                f"Displays {shown.group(1)} but actually goes to {host}.")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            add("high", 18, "Link uses a raw IP address", f"{host} is not a normal brand domain.")
        elif host in SHORTENERS:
            add("medium", 8, "URL shortener hides destination", host)
        elif host.startswith("xn--") or ".xn--" in host:
            add("high", 15, "Punycode link (possible lookalike characters)", host)
        elif (ll := lookalike(host)):
            add("high", 18, "Lookalike link domain", f"{host} imitates {ll[0].title()}.")
        if urlparse(href).scheme == "http":
            add("low", 4, "Unencrypted http link", host)

    # 5. Attachments
    for part in msg.iter_attachments():
        fn = (part.get_filename() or "").lower()
        ext = "." + fn.rsplit(".", 1)[-1] if "." in fn else ""
        if re.search(r"\.\w{2,4}\.(exe|scr|js|vbs|bat|lnk)$", fn):
            add("high", 25, "Double file extension", f"{fn} pretends to be a document but is executable.")
        elif ext in RISKY_EXT:
            add("high", 20, "Risky attachment type", f"{fn} ({ext}) can run code or hide content.")

    # 6. Delivery path, oldest hop first
    hops = []
    for r in reversed(msg.get_all("Received", [])):
        r = " ".join(str(r).split())
        hops.append({"from": (re.search(r"from (\S+)", r) or [None, "?"])[1],
                     "by": (re.search(r"by (\S+)", r) or [None, "?"])[1],
                     "date": r.rsplit(";", 1)[-1].strip() if ";" in r else ""})

    score = min(100, sum(f["points"] for f in F))
    verdict = ("Likely phishing" if score >= 70 else "Suspicious" if score >= 40
               else "Low risk" if score >= 15 else "Looks clean")
    return {"subject": h("Subject"), "from": h("From"), "score": score, "verdict": verdict,
            "findings": sorted(F, key=lambda f: -f["points"]), "hops": hops,
            "links": [l[0] for l in links]}


CSS = """
:root{--bg:#f2f5f9;--card:#fff;--ink:#14202e;--mut:#5d6b7c;--line:#dde3ea;--high:#c2362b;--medium:#b4690e;--low:#2b6cb0;--ok:#23805a;color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{--bg:#0e151d;--card:#18212c;--ink:#e8edf3;--mut:#93a1b1;--line:#2b3846;--high:#f0705f;--medium:#e3a24a;--low:#6aa8ee;--ok:#5cc79a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:820px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px;font-size:1.6rem}h2{margin:32px 0 12px;font-size:1.1rem}
.mut,small{color:var(--mut)}.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:20px}
.gauge{width:240px;max-width:100%}.verdict{font-size:1.5rem;font-weight:700}.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;margin:10px 0;background:var(--line);min-width:200px}
.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--low);border-radius:10px;padding:10px 14px;margin-bottom:10px}
.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--medium)}.f p{margin:4px 0 0;color:var(--mut)}
.pts{float:right;font-weight:700}ol{padding-left:20px}li{margin-bottom:8px;overflow-wrap:anywhere}
"""


def render(r):
    e = html.escape
    col = "high" if r["score"] >= 70 else "medium" if r["score"] >= 40 else "low" if r["score"] >= 15 else "ok"
    arc = 251.3
    counts = {s: sum(f["severity"] == s for f in r["findings"]) for s in ("high", "medium", "low")}
    bar = "".join(f'<span style="flex:{n};background:var(--{s})"></span>' for s, n in counts.items() if n)
    cards = "".join(f'<div class="f {e(f["severity"])}"><span class="pts">+{f["points"]}</span>'
                    f'<b>{e(f["title"])}</b><p>{e(f["detail"])}</p></div>' for f in r["findings"]) or "<p>No findings.</p>"
    hops = "".join(f'<li><b>{e(x["from"])}</b> to {e(x["by"])}<br><small>{e(x["date"])}</small></li>'
                   for x in r["hops"]) or "<li>No Received headers found.</li>"
    arcpath = "M20 100A80 80 0 0 1 180 100"
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishLens report</title><style>{CSS}</style><main>
<h1>PhishLens report</h1><p class="mut">Subject: {e(r['subject'])}<br>From: {e(r['from'])}</p>
<section class="hero"><svg class="gauge" viewBox="0 0 200 120" role="img" aria-label="Risk score {r['score']} out of 100">
<path d="{arcpath}" fill="none" stroke="var(--line)" stroke-width="16" stroke-linecap="round"/>
<path d="{arcpath}" fill="none" stroke="var(--{col})" stroke-width="16" stroke-linecap="round" stroke-dasharray="{r['score']/100*arc:.1f} {arc}"/>
<text x="100" y="92" text-anchor="middle" font-size="38" font-weight="700" fill="var(--ink)">{r['score']}</text>
<text x="100" y="114" text-anchor="middle" font-size="12" fill="var(--mut)">out of 100</text></svg>
<div><div class="verdict" style="color:var(--{col})">{e(r['verdict'])}</div>
<div class="bar">{bar}</div><small>{counts['high']} high, {counts['medium']} medium, {counts['low']} low findings</small></div></section>
<h2>Why this score</h2>{cards}
<h2>Delivery path (oldest first)</h2><ol>{hops}</ol>
<h2>Links found</h2><ol>{"".join(f"<li>{e(l)}</li>" for l in r['links']) or "<li>None</li>"}</ol>
</main></html>"""


def main():
    ap = argparse.ArgumentParser(description="Offline phishing email analyzer")
    ap.add_argument("eml", help="path to a raw .eml file")
    ap.add_argument("-o", "--output", help="write an HTML report to this path")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    a = ap.parse_args()
    with open(a.eml, "rb") as fh:
        r = analyze(fh.read())
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"{r['verdict']} (score {r['score']}/100)")
        for f in r["findings"]:
            print(f"  [{f['severity']:<6}] +{f['points']:<3} {f['title']}")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(render(r))
        print("Report written to", a.output)


if __name__ == "__main__":
    main()
