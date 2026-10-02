#!/usr/bin/env python3
"""
Daily Brief — payload builder.

Gathers live data, renders the briefing HTML, gzips it, encrypts with
AES-256-GCM under a PBKDF2-SHA256(600k) key derived from BRIEF_PASSCODE,
and PATCHes it into the secret gist as payload.txt.

Wire format (matches index.html exactly):
    base64( salt[16] || iv[12] || ciphertext+tag )

Environment:
    BRIEF_PASSCODE  passphrase used to unlock the briefing in the browser
    GIST_ID         id of the secret gist holding payload.txt
    GIST_TOKEN      GitHub PAT with the 'gist' scope
"""

import os, sys, io, re, gzip, json, base64, html, datetime as dt
from xml.etree import ElementTree as ET

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PHT = dt.timezone(dt.timedelta(hours=8))
NOW = dt.datetime.now(PHT)
TIMEOUT = 25

# Policy rates have no clean free API. Edit these when a central bank moves;
# the workflow will pick the change up on its next run.
RATES = {
    "bsp":  ("4.50%",        "hawkish bias"),
    "fed":  ("3.50-3.75%",   "hold expected"),
    "boj":  ("1.00%",        "31-yr high; +25bps seen by year-end"),
    "ecb":  ("2.15%",        "on hold"),
}

CITY = {"name": "Manila", "lat": 14.5995, "lon": 120.9842}

# Gists this builder must never write to. The legacy briefing is maintained by a
# separate Claude scheduled task with its own locked template; writing here would
# silently replace it. Refusing is deliberate - do not "fix" by removing the entry.
PROTECTED_GISTS = {"fd25c59bbbab14d6ea56532bad7bfa9c"}

# Which edition this is. The 6am run shows today; the 6pm run shows what is left
# of today plus tomorrow, because by evening today's agenda is mostly spent.
EDITION = "evening" if NOW.hour >= 12 else "morning"

FEEDS = [
    ("PH",         "ph", "https://news.google.com/rss?hl=en-PH&gl=PH&ceid=PH:en"),
    ("Markets",    "mk", "https://news.google.com/rss/search?q=stock+market+OR+Federal+Reserve+when:1d&hl=en-US&gl=US&ceid=US:en"),
    ("Crypto",     "cr", "https://news.google.com/rss/search?q=bitcoin+OR+ethereum+crypto+when:1d&hl=en-US&gl=US&ceid=US:en"),
    ("Tech/AI",    "ai", "https://news.google.com/rss/search?q=artificial+intelligence+when:1d&hl=en-US&gl=US&ceid=US:en"),
    ("Sports/Ent", "sp", "https://news.google.com/rss/search?q=sports+OR+entertainment+headlines+when:1d&hl=en-US&gl=US&ceid=US:en"),
]

COINS = [("BTC", "Bitcoin"), ("ETH", "Ethereum"), ("SOL", "Solana"),
         ("BONK", "Bonk"), ("JUP", "Jupiter")]

FX = ["USD", "EUR", "JPY", "GBP", "SGD", "AUD", "CNY", "HKD"]


def get(url, headers=None, **kw):
    h = {"User-Agent": "daily-brief/1.0"}
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=h, **kw)
        if r.ok:
            return r
    except Exception as e:
        print(f"  ! fetch failed {url}: {e}", file=sys.stderr)
    return None


# ----------------------------------------------------------------- weather
WMO = {0:("Clear","☀️"),1:("Mainly clear","\U0001F324️"),2:("Partly cloudy","⛅"),
       3:("Overcast","☁️"),45:("Fog","\U0001F32B️"),48:("Fog","\U0001F32B️"),
       51:("Drizzle","\U0001F327️"),53:("Drizzle","\U0001F327️"),55:("Drizzle","\U0001F327️"),
       61:("Light rain","\U0001F327️"),63:("Rain","\U0001F327️"),65:("Heavy rain","\U0001F327️"),
       80:("Showers","\U0001F326️"),81:("Showers","\U0001F326️"),82:("Heavy showers","\U0001F326️"),
       95:("Thunderstorms","⛈️"),96:("Thunderstorms","⛈️"),99:("Thunderstorms","⛈️")}


def weather():
    url = ("https://api.open-meteo.com/v1/forecast"
           f"?latitude={CITY['lat']}&longitude={CITY['lon']}"
           "&hourly=temperature_2m,precipitation_probability,weather_code"
           "&current=temperature_2m,relative_humidity_2m,weather_code"
           "&daily=temperature_2m_max,temperature_2m_min"
           "&timezone=Asia%2FManila&forecast_days=1")
    r = get(url)
    if not r:
        return None
    j = r.json()
    cur, hourly = j.get("current", {}), j.get("hourly", {})
    times = hourly.get("time", [])

    def slot(target_hour):
        for i, t in enumerate(times):
            if int(t[11:13]) == target_hour:
                code = hourly["weather_code"][i]
                desc, emoji = WMO.get(code, ("—", "\U0001F321️"))
                return {"temp": round(hourly["temperature_2m"][i]),
                        "pop": hourly["precipitation_probability"][i],
                        "desc": desc, "emoji": emoji}
        return None

    daily = j.get("daily", {})
    cdesc, cemoji = WMO.get(cur.get("weather_code"), ("—", "\U0001F321️"))
    return {
        "temp": round(cur.get("temperature_2m", 0)),
        "humidity": cur.get("relative_humidity_2m"),
        "desc": cdesc, "emoji": cemoji,
        "hi": round(daily.get("temperature_2m_max", [0])[0]),
        "lo": round(daily.get("temperature_2m_min", [0])[0]),
        "morning": slot(8), "afternoon": slot(14), "evening": slot(19),
    }


def golf_line(w):
    if not w:
        return "Weather unavailable — check before heading out."
    parts = [("morning", w.get("morning")), ("afternoon", w.get("afternoon")),
             ("evening", w.get("evening"))]
    scored = [(p, s) for p, s in parts if s]
    if not scored:
        return "Hourly detail unavailable today."
    best = min(scored, key=lambda ps: ps[1]["pop"])
    worst = max(scored, key=lambda ps: ps[1]["pop"])
    if best[1]["pop"] <= 20:
        return (f"Good window in the {best[0]} — only {best[1]['pop']}% rain. "
                f"Avoid the {worst[0]} ({worst[1]['pop']}%).")
    if best[1]["pop"] <= 50:
        return (f"{best[0].capitalize()} is your driest shot at {best[1]['pop']}% rain, "
                f"but keep an eye on the radar.")
    return f"Wet all day — lowest is the {best[0]} at {best[1]['pop']}%. Probably an indoor one."


# ----------------------------------------------------------------- markets
def fx():
    r = get("https://api.frankfurter.app/latest?from=PHP&to=" + ",".join(FX))
    if not r:
        return None
    rates = r.json().get("rates", {})
    out = {}
    for k, v in rates.items():
        if not v:
            continue
        php = 1.0 / v
        out[k] = php * 100 if k == "JPY" else php
    return out


def crypto():
    y = (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    rows = []
    for sym, name in COINS:
        r = get(f"https://api.coinbase.com/v2/prices/{sym}-USD/spot")
        if not r:
            continue
        try:
            now_p = float(r.json()["data"]["amount"])
        except Exception:
            continue
        chg = None
        ry = get(f"https://api.coinbase.com/v2/prices/{sym}-USD/spot?date={y}")
        if ry:
            try:
                prev = float(ry.json()["data"]["amount"])
                if prev:
                    chg = (now_p - prev) / prev * 100
            except Exception:
                pass
        rows.append({"sym": sym, "name": name, "price": now_p, "chg": chg})
    if rows:
        print("  crypto: " + ", ".join(f"{r['sym']}={r['price']:.6f}".rstrip("0").rstrip(".")
                                       for r in rows))
    return rows


def fear_greed():
    r = get("https://api.alternative.me/fng/")
    if not r:
        return None
    try:
        d = r.json()["data"][0]
        return {"value": int(d["value"]), "label": d["value_classification"]}
    except Exception:
        return None


def fred_series(series_id, days=40):
    """FRED CSV, no API key needed. Stooq rate-limits datacenter IPs such as
    GitHub runners, which is why the index data moved here."""
    cosd = (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%d")
    r = get(f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}&cosd={cosd}")
    if not r:
        return None
    pts = []
    for line in r.text.strip().splitlines()[1:]:
        parts = line.split(",")
        if len(parts) < 2:
            continue
        try:
            pts.append((parts[0], float(parts[1])))
        except ValueError:
            continue          # FRED writes "." on non-trading days
    if not pts:
        return None
    last = pts[-1][1]
    prev = pts[-2][1] if len(pts) > 1 else None
    return {"close": last,
            "pct": ((last - prev) / prev * 100) if prev else None,
            "asof": pts[-1][0]}


def indices():
    """S&P 500, Nasdaq Composite and VIX - most recent published close."""
    out = {}
    for key, sid in (("spx", "SP500"), ("ndq", "NASDAQCOM"), ("vix", "VIXCLS")):
        v = fred_series(sid)
        if v:
            out[key] = v
    if out:
        print("  indices (FRED): " +
              ", ".join(f"{k}={v['close']:,.2f} ({v['asof']})" for k, v in out.items()))
    else:
        print("  ! no index data from FRED", file=sys.stderr)
    return out


# ---------------------------------------------------------------- calendar
def _sa_token(scopes):
    """One access token from the service-account key, or None."""
    sa_json = os.environ.get("GOOGLE_SA_JSON")
    if not sa_json:
        return None
    try:
        import google.auth.transport.requests as gatr
        from google.oauth2 import service_account
        creds = service_account.Credentials.from_service_account_info(
            json.loads(sa_json), scopes=scopes)
        creds.refresh(gatr.Request())
        return creds.token
    except Exception as e:
        print(f"  ! service account auth failed: {type(e).__name__}", file=sys.stderr)
        return None


def _window():
    """Morning edition covers today; evening covers the rest of today plus tomorrow."""
    start = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    days = 2 if EDITION == "evening" else 1
    return start, start + dt.timedelta(days=days), days


def _keep(when, allday, start, end):
    """Enforce the window locally rather than trusting the upstream filter,
    and on the evening edition hide events that have already finished."""
    if when < start or when >= end:
        return False
    if EDITION == "evening" and not allday and when < NOW - dt.timedelta(hours=1):
        return False
    return True


def calendar_via_api():
    """Preferred path: Google expands recurring events for us, so there is no RRULE logic here.
    Share your calendar with the service account email, then set CALENDAR_ID."""
    cal_id = os.environ.get("CALENDAR_ID")
    if not cal_id:
        return None
    tok = _sa_token(["https://www.googleapis.com/auth/calendar.readonly"])
    if not tok:
        return None
    start, end, _ = _window()
    import urllib.parse as up
    q = up.urlencode({"timeMin": start.isoformat(), "timeMax": end.isoformat(),
                      "singleEvents": "true", "orderBy": "startTime", "maxResults": "50"})
    r = get(f"https://www.googleapis.com/calendar/v3/calendars/{up.quote(cal_id)}/events?{q}",
            headers={"Authorization": f"Bearer {tok}"})
    if not r:
        return None
    out = []
    for ev in r.json().get("items", []):
        st = ev.get("start", {})
        if "dateTime" in st:
            when = dt.datetime.fromisoformat(st["dateTime"]).astimezone(PHT)
            allday = False
        elif "date" in st:
            d = dt.date.fromisoformat(st["date"])
            when = dt.datetime(d.year, d.month, d.day, tzinfo=PHT)
            allday = True
        else:
            continue
        if not _keep(when, allday, start, end):
            continue
        out.append({"when": when, "allday": allday, "today": when.date() == NOW.date(),
                    "title": str(ev.get("summary") or "(no title)"),
                    "where": str(ev.get("location") or "")})
    out.sort(key=lambda e: (e["when"], e["title"]))
    print(f"  calendar (api): {len(out)} event(s)")
    return out


def calendar_via_ics():
    """Fallback: the secret iCal URL. Needs icalendar + recurring-ical-events."""
    url = os.environ.get("CALENDAR_ICS_URL")
    if not url:
        return None
    r = get(url)
    if not r:
        return None
    try:
        import icalendar
        import recurring_ical_events
    except ImportError:
        print("  ! icalendar/recurring-ical-events not installed", file=sys.stderr)
        return None
    try:
        cal = icalendar.Calendar.from_ical(r.content)
        start, end, _ = _window()
        found = recurring_ical_events.of(cal).between(start, end)
    except Exception as e:
        print(f"  ! ics parse/expand failed: {type(e).__name__}", file=sys.stderr)
        return None
    out = []
    for ev in found:
        st = ev.get("DTSTART")
        if st is None:
            continue
        v = st.dt
        allday = not isinstance(v, dt.datetime)
        if allday:
            when = dt.datetime(v.year, v.month, v.day, tzinfo=PHT)
        else:
            when = v.astimezone(PHT) if v.tzinfo else v.replace(tzinfo=PHT)
        if not _keep(when, allday, start, end):
            continue
        out.append({"when": when, "allday": allday, "today": when.date() == NOW.date(),
                    "title": str(ev.get("SUMMARY") or "(no title)"),
                    "where": str(ev.get("LOCATION") or "")})
    out.sort(key=lambda e: (e["when"], e["title"]))
    print(f"  calendar (ics): {len(out)} event(s)")
    return out


def calendar_events():
    return calendar_via_api() or calendar_via_ics()


# --------------------------------------------------------------- portfolio
def sheet_rows():
    """Read the holdings tab via a service account. Nothing public, nothing expiring."""
    sheet_id = os.environ.get("SHEET_ID")
    rng = os.environ.get("SHEET_RANGE", "A1:Z200")
    if not sheet_id:
        return None
    tok = _sa_token(["https://www.googleapis.com/auth/spreadsheets.readonly"])
    if not tok:
        return None
    r = get(f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{rng}",
            headers={"Authorization": f"Bearer {tok}"})
    if not r:
        return None
    return r.json().get("values", [])


ALIASES = {
    "ticker": "sym", "symbol": "sym", "asset": "sym", "holding": "sym", "code": "sym",
    "qty": "qty", "quantity": "qty", "shares": "qty", "units": "qty", "amount": "qty",
    "cost": "cost", "costbasis": "cost", "avgcost": "cost", "averagecost": "cost",
    "buyprice": "cost", "entry": "cost", "cost/unit": "cost",
    "type": "kind", "class": "kind", "category": "kind",
}


def parse_holdings(rows):
    """Flexible header detection so the sheet layout does not have to be exact."""
    if not rows:
        return []
    hdr_i, cols = None, {}
    for i, row in enumerate(rows[:10]):
        m = {}
        for j, cell in enumerate(row):
            key = str(cell).strip().lower().replace(" ", "").replace("_", "")
            if key in ALIASES:
                m[ALIASES[key]] = j
        if "sym" in m and "qty" in m:
            hdr_i, cols = i, m
            break
    if hdr_i is None:
        print("  ! no ticker/quantity header found in sheet", file=sys.stderr)
        return []

    def num(x):
        try:
            return float(str(x).replace(",", "").replace("$", "").replace("\u20b1", "").strip())
        except Exception:
            return None

    out = []
    for row in rows[hdr_i + 1:]:
        if not row or cols["sym"] >= len(row):
            continue
        sym = str(row[cols["sym"]]).strip().upper()
        if not sym:
            continue
        qty = num(row[cols["qty"]]) if cols["qty"] < len(row) else None
        if not qty:
            continue
        cost = num(row[cols["cost"]]) if "cost" in cols and cols["cost"] < len(row) else None
        kind = (str(row[cols["kind"]]).strip().lower()
                if "kind" in cols and cols["kind"] < len(row) else "")
        if not kind:
            kind = "crypto" if sym in {c[0] for c in COINS} else "etf"
        out.append({"sym": sym, "qty": qty, "cost": cost,
                    "kind": "crypto" if "cryp" in kind or "coin" in kind else "etf"})
    print(f"  holdings: {len(out)} row(s)")
    return out


def yahoo_quotes(symbols):
    out = {}
    for sym in symbols:
        r = get(f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}?range=5d&interval=1d")
        if not r:
            continue
        try:
            meta = r.json()["chart"]["result"][0]["meta"]
            price = meta.get("regularMarketPrice")
            prev = meta.get("chartPreviousClose") or meta.get("previousClose")
            if price is None:
                continue
            out[sym.upper()] = {"price": float(price),
                                "pct": ((price - prev) / prev * 100) if prev else None}
        except Exception:
            continue
    return out


def etf_quotes(symbols):
    """Yahoo first; Stooq as fallback. Logs which source answered."""
    if not symbols:
        return {}
    q = yahoo_quotes(symbols)
    if q:
        print(f"  etf quotes (yahoo): {len(q)}/{len(symbols)}")
    missing = [x for x in symbols if x.upper() not in q]
    if missing:
        fb = stooq_quotes(missing)
        if fb:
            print(f"  etf quotes (stooq fallback): {len(fb)}/{len(missing)}")
        q.update(fb)
    if not q:
        print("  ! no ETF quotes from any source", file=sys.stderr)
    return q


def stooq_quotes(symbols):
    if not symbols:
        return {}
    q = "+".join(f"{s.lower()}.us" for s in symbols)
    r = get(f"https://stooq.com/q/l/?s={q}&f=sd2t2ohlcv&h&e=csv")
    out = {}
    if not r:
        return out
    for line in r.text.strip().splitlines()[1:]:
        p = line.split(",")
        if len(p) < 8:
            continue
        sym = p[0].split(".")[0].upper()
        try:
            close, openp = float(p[6]), float(p[3])
        except ValueError:
            continue
        out[sym] = {"price": close,
                    "pct": ((close - openp) / openp * 100) if openp else None}
    return out


def portfolio(crypto_rows):
    rows = parse_holdings(sheet_rows() or [])
    if not rows:
        return None
    spot = {c["sym"]: c for c in (crypto_rows or [])}
    etfs = [h["sym"] for h in rows if h["kind"] == "etf"]
    quotes = etf_quotes(etfs)
    for h in rows:
        if h["kind"] == "crypto":
            q = spot.get(h["sym"])
            h["price"] = q["price"] if q else None
            h["pct"] = q["chg"] if q else None
        else:
            q = quotes.get(h["sym"])
            h["price"] = q["price"] if q else None
            h["pct"] = q["pct"] if q else None
        h["value"] = (h["price"] * h["qty"]) if h["price"] else None
        h["pl"] = ((h["price"] - h["cost"]) * h["qty"]
                   if (h["price"] and h["cost"]) else None)
    return rows


# ------------------------------------------------------------------ gauges
def equity_gauge(vix):
    if vix is None:
        return {"score": 50, "label": "Equities: UNKNOWN", "sub": "VIX unavailable",
                "bullets": ["Volatility data unavailable this morning.",
                            "Treat positioning decisions as unchanged until it returns."]}
    score = max(0, min(100, (vix - 10) / 30 * 100))
    if vix < 16:
        label, bl = "LOW", [
            "Calm regime: staying invested and adding on dips is the standard playbook.",
            "Volatility is cheap — a sensible time to buy protection, not sell it.",
            "Complacency cuts both ways; keep stops honest rather than widening them."]
    elif vix < 25:
        label, bl = "MODERATE", [
            "Two-way risk: size new positions normally but avoid adding leverage.",
            "Hedges cost more than they did — prefer spreads to outright puts.",
            "Favour quality and liquidity over high-beta names until vol settles."]
    else:
        label, bl = "ELEVATED", [
            "Stress regime: preserve capital first, opportunity second.",
            "Scale into weakness in tranches rather than single large entries.",
            "Expect correlations to converge — diversification helps less than usual."]
    return {"score": score, "label": f"Equities: {label}",
            "sub": f"VIX {vix:.2f}", "bullets": bl}


CR_BUCKETS = {
 "ef": ["<b>Main coins (BTC/ETH):</b> extreme fear has historically been an accumulation zone — scale in slowly rather than all at once.",
        "<b>Alt coins (SOL/JUP):</b> highest beta in fear regimes — cut leverage and trim position size until sentiment recovers past ~40.",
        "<b>Meme coins (BONK):</b> most fragile in risk-off tape — keep the allocation small and take profits quickly."],
 "f":  ["<b>Main coins:</b> fear without capitulation — continue scheduled buys, resist the urge to time the exact bottom.",
        "<b>Alt coins:</b> wait for BTC to stabilise before rotating out of majors; alts usually lag the turn.",
        "<b>Meme coins:</b> thin liquidity here — treat any position as speculative and sized to lose."],
 "n":  ["<b>Main coins:</b> neutral tape — no edge from sentiment; stick to your plan.",
        "<b>Alt coins:</b> stock-picking matters more than beta in this zone; favour names with real volume.",
        "<b>Meme coins:</b> no sentiment tailwind — nothing here demands action."],
 "g":  ["<b>Main coins:</b> greed building — let winners run but start defining where you would take profit.",
        "<b>Alt coins:</b> this is where alts typically outperform; also where chasing gets expensive.",
        "<b>Meme coins:</b> rallies are fastest and shortest here — pre-commit an exit before entering."],
 "eg": ["<b>Main coins:</b> extreme greed historically precedes drawdowns — consider trimming into strength.",
        "<b>Alt coins:</b> late-cycle behaviour; tighten stops and bank partial profits.",
        "<b>Meme coins:</b> maximum froth — the worst risk/reward of the three buckets."],
}


def fg_bucket(v):
    return "ef" if v <= 25 else "f" if v <= 45 else "n" if v <= 55 else "g" if v <= 75 else "eg"


def crypto_gauge(fg):
    if not fg:
        return {"score": 50, "label": "Crypto: UNKNOWN", "sub": "Index unavailable",
                "bullets": ["Sentiment index unavailable — the live value will load in your browser."]}
    v, lab = fg["value"], fg["label"]
    return {"score": v, "label": f"Crypto: {lab.upper()} ({v})",
            "sub": "Fear & Greed Index", "bullets": CR_BUCKETS[fg_bucket(v)]}


# -------------------------------------------------------------------- news
def news():
    items = []
    for name, tag, url in FEEDS:
        r = get(url)
        if not r:
            continue
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError:
            continue
        count = 0
        for it in root.iter("item"):
            t = it.findtext("title")
            if not t:
                continue
            items.append({"tag": name, "cls": tag, "title": t.strip()})
            count += 1
            if count >= 3:
                break
    return items


# -------------------------------------------------------------------- html
def gauge_svg(score, zones):
    import math
    cx, cy, r = 90, 85, 70

    def pt(v):
        a = math.pi * (1 - v / 100)
        return cx + r * math.cos(a), cy - r * math.sin(a)

    segs, frm = "", 0
    for to, colour in zones:
        x1, y1 = pt(frm)
        x2, y2 = pt(to)
        segs += (f'<path d="M{x1:.1f},{y1:.1f} A{r},{r} 0 0 1 {x2:.1f},{y2:.1f}" '
                 f'stroke="{colour}" stroke-width="14" fill="none"/>')
        frm = to
    ang = -90 + score / 100 * 180
    return (f'<svg width="180" height="100" viewBox="0 0 180 100">{segs}'
            f'<g transform="rotate({ang:.1f} {cx} {cy})">'
            f'<line x1="{cx}" y1="{cy}" x2="{cx}" y2="{cy-r+20}" stroke="var(--ink)" '
            f'stroke-width="3.5" stroke-linecap="round"/></g>'
            f'<circle cx="{cx}" cy="{cy}" r="5" fill="var(--ink)"/></svg>')


EQ_ZONES = [(33, "#3fb46e"), (66, "#f0b429"), (100, "#d13b3b")]
CR_ZONES = [(25, "#d13b3b"), (45, "#f0b429"), (55, "#9aa4b2"), (75, "#8fd19e"), (100, "#3fb46e")]


def pct_html(v, suffix="%"):
    if v is None:
        return '<span class="muted">—</span>'
    cls = "up" if v >= 0 else "down"
    sign = "+" if v >= 0 else "−"
    return f'<span class="{cls}">{sign}{abs(v):.2f}{suffix}</span>'


def money(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "—"
    if v != v:                      # NaN
        return "—"
    if v >= 1000:
        return f"${v:,.0f}"
    if v >= 1:
        return f"${v:,.2f}"
    return f"${v:.8f}".rstrip("0")


# Runs inside the briefing page in the reader's browser. Every source here is
# CORS-enabled; anything that fails silently leaves the morning build's value in
# place, so this can only improve the page, never break it.
LIVE_JS = """<script>
(function(){
var COINS=['BTC','ETH','SOL','BONK','JUP'];
var FXC=['USD','EUR','JPY','GBP','SGD','AUD','CNY','HKD'];
var CRB=__CR_BUCKETS__;
var CRZ=[[25,'#d13b3b'],[45,'#f0b429'],[55,'#9aa4b2'],[75,'#8fd19e'],[100,'#3fb46e']];
var ok=0, LIVEPX={}, LIVECHG={};

function money(v){
  v = (typeof v === 'number') ? v : parseFloat(v);
  if(v==null||isNaN(v)) return '\\u2014';
  // en-US explicitly: the device locale would otherwise swap , and . in prices
  if(v>=1000) return '$'+v.toLocaleString('en-US',{maximumFractionDigits:0});
  if(v>=1) return '$'+v.toFixed(2);
  return '$'+v.toFixed(8).replace(/0+$/,'');
}
function pct(v){
  if(v==null||isNaN(v)) return '<span class="muted">\\u2014</span>';
  return '<span class="'+(v>=0?'up':'down')+'">'+(v>=0?'+':'\\u2212')+Math.abs(v).toFixed(2)+'%</span>';
}
function badge(t){ var e=document.getElementById('liveBadge'); if(e) e.textContent=t; }

async function coin(sym){
  var y=new Date(Date.now()-86400000).toISOString().slice(0,10);
  var a=await fetch('https://api.coinbase.com/v2/prices/'+sym+'-USD/spot',{cache:'no-store'});
  if(!a.ok) throw new Error('spot');
  var now=parseFloat((await a.json()).data.amount), chg=null;
  try{
    var b=await fetch('https://api.coinbase.com/v2/prices/'+sym+'-USD/spot?date='+y,{cache:'no-store'});
    if(b.ok){ var prev=parseFloat((await b.json()).data.amount); if(prev) chg=(now-prev)/prev*100; }
  }catch(e){}
  var row=document.querySelector('tr[data-coin="'+sym+'"]'); if(!row) return;
  var pc=row.querySelector('[data-live=price]'), cc=row.querySelector('[data-live=chg]');
  if(pc) pc.textContent=money(now);
  if(cc) cc.innerHTML=pct(chg);
  LIVEPX[sym]=now; LIVECHG[sym]=chg;
}

// Revalue crypto holdings from the live prices, then re-add the ETF subtotal
// the builder computed, so the Total line stays correct.
function revaluePortfolio(){
  var rows=document.querySelectorAll('tr[data-holding]');
  if(!rows.length) return;
  var sum=0, pl=0, sawPl=false;
  rows.forEach(function(r){
    var sym=r.getAttribute('data-holding');
    var qty=parseFloat(r.getAttribute('data-qty'));
    var cost=parseFloat(r.getAttribute('data-cost'));
    var px=LIVEPX[sym];
    if(px==null||isNaN(qty)) return;
    var val=px*qty; sum+=val;
    if(!isNaN(cost)){ pl+=(px-cost)*qty; sawPl=true; }
    var a=r.querySelector('[data-pf=price]'), b=r.querySelector('[data-pf=value]'),
        c=r.querySelector('[data-pf=pct]');
    if(a) a.textContent=money(px);
    if(b) b.textContent=money(val);
    if(c) c.innerHTML=pct(LIVECHG[sym]);
  });
  var tc=document.querySelector('[data-pf=total]');
  if(tc){
    var etf=parseFloat(tc.getAttribute('data-etf'))||0;
    tc.innerHTML='<b>'+money(sum+etf)+'</b>';
  }
  var pc2=document.querySelector('[data-pf=totalpl]');
  if(pc2 && pc2.getAttribute('data-anypl')==='1'){
    var etfpl=parseFloat(pc2.getAttribute('data-etfpl'))||0;
    if(sawPl||etfpl) pc2.innerHTML='<b>'+money(pl+etfpl)+'</b>';
  }
}
async function doCrypto(){
  try{ await Promise.all(COINS.map(coin)); ok++; }catch(e){}
  try{ revaluePortfolio(); }catch(e){}
}

async function doFx(){
  try{
    var r=await fetch('https://api.frankfurter.app/latest?from=PHP&to='+FXC.join(','),{cache:'no-store'});
    if(!r.ok) throw new Error('fx');
    var rates=(await r.json()).rates;
    FXC.forEach(function(k){
      var v=rates[k]; if(!v) return;
      var php=1/v; if(k==='JPY') php*=100;
      var el=document.querySelector('[data-fx="'+k+'"]');
      if(el) el.textContent=php.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
    });
    ok++;
  }catch(e){}
}

function gaugeSvg(score){
  var cx=90,cy=85,r=70,segs='',frm=0;
  function pt(v){ var a=Math.PI*(1-v/100); return [cx+r*Math.cos(a), cy-r*Math.sin(a)]; }
  CRZ.forEach(function(z){
    var p1=pt(frm), p2=pt(z[0]);
    segs+='<path d="M'+p1[0].toFixed(1)+','+p1[1].toFixed(1)+' A70,70 0 0 1 '+
          p2[0].toFixed(1)+','+p2[1].toFixed(1)+'" stroke="'+z[1]+'" stroke-width="14" fill="none"/>';
    frm=z[0];
  });
  var ang=-90+score/100*180;
  return '<svg width="180" height="100" viewBox="0 0 180 100">'+segs+
    '<g transform="rotate('+ang.toFixed(1)+' 90 85)"><line x1="90" y1="85" x2="90" y2="35" '+
    'stroke="var(--ink)" stroke-width="3.5" stroke-linecap="round"/></g>'+
    '<circle cx="90" cy="85" r="5" fill="var(--ink)"/></svg>';
}

async function doFng(){
  try{
    var r=await fetch('https://api.alternative.me/fng/',{cache:'no-store'});
    if(!r.ok) throw new Error('fng');
    var d=(await r.json()).data[0], v=parseInt(d.value,10), lab=d.value_classification;
    if(isNaN(v)) throw new Error('fng');
    var g=document.getElementById('gauge-cr');
    if(g) g.innerHTML=gaugeSvg(v)+
      '<div class="val">Crypto: '+lab.toUpperCase()+' ('+v+')</div>'+
      '<div class="lab">Fear &amp; Greed Index</div>';
    var b = v<=25?'ef' : v<=45?'f' : v<=55?'n' : v<=75?'g' : 'eg';
    var ul=document.getElementById('cr-bullets');
    if(ul&&CRB[b]) ul.innerHTML=CRB[b].map(function(x){return '<li>'+x+'</li>';}).join('');
    ok++;
  }catch(e){}
}

async function refresh(){
  ok=0; badge('refreshing\\u2026');
  await Promise.all([doCrypto(), doFx(), doFng()]);
  if(ok===0){ badge('offline \\u2014 morning build'); return; }
  var t=new Date().toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
  badge(ok===3 ? ('live \\u00b7 '+t) : ('partly live \\u00b7 '+t));
}

refresh();
var last=Date.now();
document.addEventListener('visibilitychange', function(){
  if(document.visibilityState==='visible' && Date.now()-last>120000){ last=Date.now(); refresh(); }
});
})();
</script>"""


def build_html(d):
    w, g_eq, g_cr = d["weather"], d["eq"], d["cr"]
    esc = html.escape

    def wx_slot(name, s):
        if not s:
            return f'<div class="slot"><div class="t">{name}</div><div class="e">—</div></div>'
        return (f'<div class="slot"><div class="t">{name}</div><div class="e">{s["emoji"]}</div>'
                f'<div class="d">{s["temp"]}°</div>'
                f'<div class="r">{esc(s["desc"])} · {s["pop"]}%</div></div>')

    wx = ""
    if w:
        wx = (f'<div><span class="big">{w["temp"]}°C</span> &nbsp;{esc(w["desc"])}'
              f' · Humidity {w["humidity"]}%</div>'
              f'<div class="wx">{wx_slot("Morning", w["morning"])}'
              f'{wx_slot("Afternoon", w["afternoon"])}{wx_slot("Evening", w["evening"])}</div>')
    else:
        wx = '<div class="muted">Weather unavailable.</div>'

    fx_rows = ""
    fxd = d["fx"] or {}
    order = [("USD", "USD/PHP"), ("EUR", "EUR/PHP"), ("GBP", "GBP/PHP"), ("JPY", "JPY/PHP ×100"),
             ("SGD", "SGD/PHP"), ("AUD", "AUD/PHP"), ("CNY", "CNY/PHP"), ("HKD", "HKD/PHP")]
    pairs = [(k, lbl, fxd.get(k)) for k, lbl in order]
    for i in range(0, len(pairs), 2):
        k1, l1, v1 = pairs[i]
        k2, l2, v2 = pairs[i + 1] if i + 1 < len(pairs) else ("", "", None)
        f1 = f"{v1:,.2f}" if v1 else "—"
        f2 = f"{v2:,.2f}" if v2 else "—"
        bold = ' style="font-weight:700"' if l1 == "USD/PHP" else ""
        c2 = f'<td class="num" data-fx="{k2}">{f2}</td>' if k2 else "<td></td>"
        fx_rows += (f'<tr><td>{l1}</td><td class="num" data-fx="{k1}"{bold}>{f1}</td>'
                    f'<td>{l2}</td>{c2}</tr>')

    have = {c["sym"]: c for c in (d["crypto"] or [])}
    cr_rows = "".join(
        f'<tr data-coin="{sym}"><td><b>{sym}</b> {esc(name)}</td>'
        f'<td class="num" data-live="price">{money(have[sym]["price"]) if sym in have else "—"}</td>'
        f'<td class="num" data-live="chg">{pct_html(have[sym]["chg"]) if sym in have else "—"}</td></tr>'
        for sym, name in COINS
    )

    idx = d["indices"] or {}

    def chip(name, key, fmt="{:,.2f}"):
        v = idx.get(key)
        if not v:
            return f'<div class="chip"><div class="n">{name}</div><div class="v">—</div></div>'
        return (f'<div class="chip"><div class="n">{name}</div>'
                f'<div class="v">{fmt.format(v["close"])}</div>'
                f'<div class="c">{pct_html(v["pct"])}</div></div>')

    news_items = "".join(
        f'<li><span class="tag t-{n["cls"]}">{esc(n["tag"])}</span>{esc(n["title"])}</li>'
        for n in (d["news"] or [])
    ) or '<li class="muted">No headlines retrieved.</li>'

    edition_label = "Schedule" if EDITION == "evening" else "Today"

    # calendar
    evs = d.get("calendar")
    if evs is None:
        cal_html = ('<div class="muted">Calendar not configured — add the CALENDAR_ICS_URL '
                    'secret to show your schedule here.</div>')
    elif not evs:
        cal_html = '<div class="muted">Nothing on the calendar — a clear day.</div>'
    else:
        parts, last_day = [], None
        for e in evs:
            day = e["when"].date()
            if day != last_day:
                lbl = "Today" if e["today"] else e["when"].strftime("%a %-d %b")
                parts.append(f'<tr><th colspan="2">{lbl}</th></tr>')
                last_day = day
            t = "all day" if e["allday"] else e["when"].strftime("%-I:%M %p")
            where = f'<div class="muted">{esc(e["where"][:60])}</div>' if e["where"] else ""
            parts.append(
                f'<tr><td class="num" style="white-space:nowrap;vertical-align:top">{t}</td>'
                f'<td>{esc(e["title"])}{where}</td></tr>')
        cal_html = "<table>" + "".join(parts) + "</table>"

    # portfolio
    pf = d.get("portfolio")
    if pf is None:
        pf_html = ('<div class="muted">Portfolio not configured — add the GOOGLE_SA_JSON and '
                   'SHEET_ID secrets, and share the sheet with the service account.</div>')
    elif not pf:
        pf_html = '<div class="muted">No holdings found in the sheet.</div>'
    else:
        body, tot_v, tot_pl, any_pl = [], 0.0, 0.0, False
        etf_v, etf_pl = 0.0, 0.0
        for h in pf:
            if h["value"]:
                tot_v += h["value"]
                if h["kind"] != "crypto":
                    etf_v += h["value"]
            if h["pl"] is not None:
                tot_pl += h["pl"]
                any_pl = True
                if h["kind"] != "crypto":
                    etf_pl += h["pl"]
            qty_s = f'{h["qty"]:,.6f}'.rstrip("0").rstrip(".")
            unit = "units" if h["kind"] == "crypto" else "sh"
            live = ""
            if h["kind"] == "crypto":
                cost_a = h["cost"] if h["cost"] is not None else ""
                live = f' data-holding="{h["sym"]}" data-qty="{h["qty"]}" data-cost="{cost_a}"'
            body.append(
                f'<tr{live}><td><b>{esc(h["sym"])}</b>'
                f'<div class="muted">{qty_s} {unit}</div></td>'
                f'<td class="num" data-pf="price">{money(h["price"])}</td>'
                f'<td class="num" data-pf="value">{money(h["value"])}</td>'
                f'<td class="num" data-pf="pct">{pct_html(h["pct"])}</td></tr>')
        pl_cell = f"<b>{money(tot_pl)}</b>" if any_pl else ""
        foot = (f'<tr><td><b>Total</b></td><td></td>'
                f'<td class="num" data-pf="total" data-etf="{etf_v:.10f}">'
                f'<b>{money(tot_v)}</b></td>'
                f'<td class="num" data-pf="totalpl" data-etfpl="{etf_pl:.10f}" '
                f'data-anypl="{1 if any_pl else 0}">{pl_cell}</td></tr>')
        pf_html = ('<table><tr><th>Holding</th><th class="num">Price</th>'
                   '<th class="num">Value</th><th class="num">Day</th></tr>'
                   + "".join(body) + foot + "</table>"
                   + '<div class="muted" style="margin-top:8px">Crypto revalues live on every '
                     'open; ETF prices refresh at each build. Last column is day change; the '
                     'total row shows P&amp;L where cost basis is present.</div>')

    eq_bul = "".join(f"<li>{b}</li>" for b in g_eq["bullets"])
    cr_bul = "".join(f"<li>{b}</li>" for b in g_cr["bullets"])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Daily Brief</title>
<style>
:root{{color-scheme:light;--bg:#f6f7f9;--card:#fff;--ink:#1a2233;--muted:#66707f;--line:#e6e9ee;
 --accent:#1f5eff;--up:#0a8f4d;--down:#d13b3b;--chip:#fbfcfe;
 --t-ph:#e7f0ff;--t-mk:#e8f7ee;--t-cr:#fdeeee;--t-ai:#f3ecfd;--t-sp:#fff2e2}}
[data-theme=dark]{{color-scheme:dark;--bg:#12151c;--card:#1b2029;--ink:#e8ecf3;--muted:#9aa4b2;
 --line:#2a313d;--accent:#6f9bff;--up:#4cc98a;--down:#f07a7a;--chip:#161b23;
 --t-ph:#1d2c4d;--t-mk:#15342a;--t-cr:#402024;--t-ai:#2e2247;--t-sp:#3d2e15}}
*{{box-sizing:border-box;margin:0}}
body{{font:15px/1.55 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
 background:var(--bg);color:var(--ink);padding:20px}}
.wrap{{max-width:1080px;margin:0 auto}}
header{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:14px}}
h1{{font-size:22px}} .sub{{color:var(--muted);font-size:13px}}
#themeBtn{{background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:999px;
 padding:6px 14px;font-size:13px;cursor:pointer}}
.grid{{display:grid;gap:14px;margin-bottom:14px}}
.g3{{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}}
.g2{{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}
#liveBadge{{font-weight:600;color:var(--accent)}}
.card h2{{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:10px}}
.big{{font-size:30px;font-weight:700}} .muted{{color:var(--muted);font-size:12.5px}}
.up{{color:var(--up)}} .down{{color:var(--down)}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
th{{text-align:left;color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;
 padding:6px 8px;border-bottom:1px solid var(--line)}}
td{{padding:7px 8px;border-bottom:1px solid var(--line)}}
tr:last-child td{{border-bottom:none}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
ul.news{{list-style:none}} ul.news li{{padding:7px 0;border-bottom:1px solid var(--line);font-size:13.5px}}
ul.news li:last-child{{border-bottom:none}}
.tag{{display:inline-block;font-size:10.5px;font-weight:700;padding:1px 7px;border-radius:999px;margin-right:6px}}
.t-ph{{background:var(--t-ph);color:#5b8dff}} .t-mk{{background:var(--t-mk);color:#2fae6e}}
.t-cr{{background:var(--t-cr);color:#e06a6a}} .t-ai{{background:var(--t-ai);color:#9a6cf5}}
.t-sp{{background:var(--t-sp);color:#cf9a3c}}
.gwrap{{display:flex;gap:22px;justify-content:space-around;flex-wrap:wrap}}
.gauge{{text-align:center}} .gauge .val{{font-size:15px;font-weight:700}}
.gauge .lab{{font-size:12.5px;color:var(--muted)}}
.impl{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:14px;
 border-top:1px solid var(--line);padding-top:12px}}
.impl h3{{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:6px}}
.impl ul{{margin:0;padding-left:18px;font-size:13px;line-height:1.55}}
.idx{{display:flex;gap:10px;flex-wrap:wrap}}
.idx .chip{{flex:1 1 140px;background:var(--chip);border:1px solid var(--line);border-radius:10px;padding:10px 12px}}
.chip .n{{font-size:12px;color:var(--muted)}} .chip .v{{font-size:17px;font-weight:700}}
.chip .c{{font-size:12.5px;font-weight:600}}
.wx{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:10px 0 8px}}
.wx .slot{{background:var(--chip);border:1px solid var(--line);border-radius:10px;padding:8px 6px;text-align:center}}
.wx .t{{font-size:11px;color:var(--muted);text-transform:uppercase}} .wx .e{{font-size:20px;margin:2px 0}}
.wx .d{{font-size:14px;font-weight:700}} .wx .r{{font-size:11.5px;color:var(--muted)}}
.golf{{font-size:12.5px;background:var(--chip);border:1px solid var(--line);border-radius:8px;padding:6px 10px}}
footer{{color:var(--muted);font-size:11.5px;margin-top:6px;line-height:1.6}}
.gauge svg{{max-width:100%;height:auto}}
@media (max-width:480px){{
 body{{padding:12px}}
 .grid{{gap:12px;margin-bottom:12px}}
 .card{{padding:13px;overflow-x:auto}}
 h1{{font-size:19px}}
 .big{{font-size:26px}}
 table{{font-size:12.5px}}
 td,th{{padding:6px 5px}}
 .wx .slot{{padding:7px 2px}}
 .wx .t,.wx .r{{font-size:10px}}
 .idx .chip{{flex:1 1 100%}}
 .impl{{grid-template-columns:1fr;gap:10px}}
 .impl ul{{padding-left:16px}}
 #themeBtn{{padding:9px 15px}}
 footer{{font-size:11px}}
}}
</style></head><body><div class="wrap">
<header>
 <div><h1>Good morning, Justin ☀️</h1>
 <div class="sub">{NOW.strftime('%A, %B %-d, %Y')} · {CITY['name']} (PHT) · {EDITION.capitalize()} edition {NOW.strftime('%-I:%M %p')} · <span id="liveBadge">…</span></div></div>
 <button id="themeBtn" onclick="tt()">\U0001F319 Dark</button>
</header>

<div class="grid g3">
 <div class="card"><h2>{w['emoji'] if w else ''} Weather — {CITY['name']}</h2>
  {wx}
  <div class="golf">⛳ <b>Golf outlook:</b> {esc(d['golf'])}</div></div>
 <div class="card"><h2>\U0001F4C5 {edition_label}</h2>
  {cal_html}</div>
 <div class="card"><h2>\U0001F4CA Snapshot</h2>
  <div class="idx">{chip('S&P 500','spx')}{chip('Nasdaq','ndq')}{chip('VIX','vix')}</div></div>
</div>

<div class="grid g2">
 <div class="card"><h2>\U0001F3AF Risk Gauges</h2>
  <div class="gwrap">
   <div class="gauge">{gauge_svg(g_eq['score'], EQ_ZONES)}
    <div class="val">{g_eq['label']}</div><div class="lab">{g_eq['sub']}</div></div>
   <div class="gauge" id="gauge-cr">{gauge_svg(g_cr['score'], CR_ZONES)}
    <div class="val">{g_cr['label']}</div><div class="lab">{g_cr['sub']}</div></div>
  </div>
  <div class="impl">
   <div><h3>Equities — implications</h3><ul>{eq_bul}</ul></div>
   <div><h3>Crypto — implications</h3><ul id="cr-bullets">{cr_bul}</ul></div>
  </div>
  <div class="muted" style="margin-top:10px">General directional reads from the gauges — not financial advice.</div>
 </div>
 <div class="card"><h2>\U0001F310 Policy & Macro</h2>
  <table>
   <tr><td>\U0001F1F5\U0001F1ED BSP policy rate</td><td class="num"><b>{RATES['bsp'][0]}</b> · {RATES['bsp'][1]}</td></tr>
   <tr><td>\U0001F1FA\U0001F1F8 Fed funds rate</td><td class="num"><b>{RATES['fed'][0]}</b> · {RATES['fed'][1]}</td></tr>
   <tr><td>\U0001F1EF\U0001F1F5 BoJ policy rate</td><td class="num"><b>{RATES['boj'][0]}</b> · {RATES['boj'][1]}</td></tr>
   <tr><td>\U0001F1EA\U0001F1FA ECB deposit rate</td><td class="num"><b>{RATES['ecb'][0]}</b> · {RATES['ecb'][1]}</td></tr>
  </table>
  <div class="muted" style="margin-top:8px">Policy rates are maintained in the builder config.</div>
 </div>
</div>

<div class="grid g2">
 <div class="card"><h2>\U0001F4B1 FX — Philippine Peso</h2>
  <table><tr><th>Pair</th><th class="num">Rate (₱)</th><th>Pair</th><th class="num">Rate (₱)</th></tr>
  {fx_rows}</table>
  <div class="muted" style="margin-top:8px">ECB reference rates via Frankfurter.</div></div>
 <div class="card"><h2>\U0001FA99 Crypto</h2>
  <table><tr><th>Asset</th><th class="num">Price</th><th class="num">24h</th></tr>{cr_rows}</table>
  <div class="muted" style="margin-top:8px">Coinbase spot, 24h vs same time yesterday.</div></div>
</div>

<div class="grid g2">
 <div class="card"><h2>\U0001F4C8 Portfolio</h2>{pf_html}</div>
 <div class="card"><h2>\U0001F4F0 News You Follow</h2><ul class="news">{news_items}</ul></div>
</div>

<footer>Sources: Open-Meteo, Frankfurter (ECB), Coinbase, alternative.me, Stooq, Google News.
Rebuilt automatically each morning at 7:30 AM PHT by GitHub Actions.</footer>
</div>
<script>
function ap(t){{document.documentElement.setAttribute('data-theme',t);
 document.getElementById('themeBtn').textContent=t==='dark'?'☀️ Light':'\U0001F319 Dark';
 try{{parent.postMessage({{dailyBriefTheme:t}},'*')}}catch(e){{}}}}
function tt(){{var t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
 try{{localStorage.setItem('briefing-theme',t)}}catch(e){{}} ap(t);}}
try{{ap(localStorage.getItem('briefing-theme')||'light')}}catch(e){{ap('light')}}
</script>
<!--LIVE--></body></html>""".replace("<!--LIVE-->", LIVE_JS.replace("__CR_BUCKETS__", json.dumps(CR_BUCKETS)))


# ------------------------------------------------------------------ crypto
def shell_gist_id():
    """The id hardcoded in index.html, so we can refuse to publish on a mismatch."""
    try:
        shell = io.open("index.html", encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(r"""var\s+GIST\s*=\s*['"]([0-9a-fA-F]+)['"]""", shell)
    return m.group(1) if m else None


def frozen_salt(gist_id, token):
    """Reuse the salt already in the gist's payload.

    'Remember this device' stores the derived AES key, which is bound to the salt.
    A fresh random salt every build silently invalidates it and puts the passcode
    prompt back on every publish. Reusing a salt is safe; reusing an IV is not,
    so the IV below stays random.
    """
    env = os.environ.get("BRIEF_SALT_HEX", "").strip()
    if env:
        try:
            b = bytes.fromhex(env)
            if len(b) == 16:
                print("  salt: from BRIEF_SALT_HEX")
                return b
        except ValueError:
            print("  ! BRIEF_SALT_HEX is not valid hex - ignoring", file=sys.stderr)
    r = get(f"https://api.github.com/gists/{gist_id}",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json"})
    if r:
        try:
            f = r.json().get("files", {}).get("payload.txt")
            if f:
                txt = f.get("content") or ""
                if f.get("truncated") or not txt:
                    raw_r = get(f["raw_url"])
                    txt = raw_r.text if raw_r else ""
                if txt.strip():
                    salt = base64.b64decode(txt.strip())[:16]
                    if len(salt) == 16:
                        print("  salt: reused from current payload")
                        return salt
        except Exception:
            pass
    salt = os.urandom(16)
    print(f"  salt: generated fresh - pin it by setting BRIEF_SALT_HEX={salt.hex()}")
    return salt


def encrypt(plaintext_html, passcode, salt):
    blob = gzip.compress(plaintext_html.encode("utf-8"), 9)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    key = kdf.derive(passcode.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, blob, None)
    return base64.b64encode(salt + iv + ct).decode("ascii")


def push(payload_b64, gist_id, token):
    r = requests.patch(
        f"https://api.github.com/gists/{gist_id}",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
        json={"files": {"payload.txt": {"content": payload_b64}}},
        timeout=60)
    r.raise_for_status()
    return r.json().get("updated_at")


def main():
    passcode = os.environ.get("BRIEF_PASSCODE")
    gist_id = os.environ.get("GIST_ID")
    token = os.environ.get("GIST_TOKEN")
    missing = [k for k, v in (("BRIEF_PASSCODE", passcode), ("GIST_ID", gist_id),
                              ("GIST_TOKEN", token)) if not v]
    if missing:
        sys.exit(
            "Missing required secret(s): " + ", ".join(missing) + "\n"
            "  Add them at: Settings > Secrets and variables > Actions > "
            "the 'Secrets' tab (NOT 'Variables') > New repository secret.\n"
            "  Names are case-sensitive and must have no surrounding spaces.")

    if gist_id in PROTECTED_GISTS:
        sys.exit(
            f"REFUSING TO PUBLISH: GIST_ID {gist_id} is the legacy briefing's gist.\n"
            "  That payload is maintained by a separate Claude scheduled task using a\n"
            "  locked template. Point GIST_ID at this system's own gist instead.")

    shell_id = shell_gist_id()
    if shell_id and shell_id.lower() != gist_id.lower():
        sys.exit(
            f"REFUSING TO PUBLISH: index.html reads gist {shell_id} but GIST_ID is {gist_id}.\n"
            "  The page would show a payload this builder never wrote. Update the\n"
            "  'var GIST' line in index.html so both point at the same gist.")
    print(f"Target gist {gist_id} - matches index.html" if shell_id else
          f"Target gist {gist_id} (index.html not found to cross-check)")

    print(f"Gathering data ({EDITION} edition)...")
    w = weather()
    idx = indices()
    fg = fear_greed()
    vix = idx.get("vix", {}).get("close") if idx else None

    cryp = crypto()
    data = {
        "weather": w,
        "golf": golf_line(w),
        "fx": fx(),
        "crypto": cryp,
        "indices": idx,
        "eq": equity_gauge(vix),
        "cr": crypto_gauge(fg),
        "news": news(),
        "calendar": calendar_events(),
        "portfolio": portfolio(cryp),
    }

    got = [k for k in ("weather", "fx", "crypto", "news", "calendar", "portfolio")
           if data.get(k)]
    print(f"  retrieved: {', '.join(got) or 'nothing'}")
    if not got:
        sys.exit("Every source failed - refusing to overwrite the gist with an empty briefing.")

    page = build_html(data)
    print(f"  html {len(page):,} bytes")

    payload = encrypt(page, passcode, frozen_salt(gist_id, token))
    print(f"  payload {len(payload):,} base64 chars")

    stamp = push(payload, gist_id, token)
    print(f"Pushed. Gist updated_at = {stamp}")


if __name__ == "__main__":
    main()
