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

import os, sys, io, re, time, gzip, json, base64, html, datetime as dt
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
    "bsp":  ("5.00%",        "27 Aug · next 22 Oct"),
    "fed":  ("3.75-4.00%",   "16 Sep · next 28 Oct"),
    "boj":  ("1.25%",        "18 Sep · next 30 Oct"),
    "ecb":  ("2.50%",        "10 Sep · next 29 Oct"),
}

# Slower-moving prints shown beside the policy rates. Edit when a new one lands.
# "ph_cpi" is only a fallback: ph_indicators() overwrites it from the last point of
# the inflation series in ph_data.json, so PH inflation is updated in ONE place.
PRINTS = {
    "ph_cpi":    ("PH inflation",    "7.2% (Sep)",  "from 6.1% in Aug"),
    "ph_gdp":    ("PH Q2 GDP",       "2.3%",        "Q1 was 2.8% · Q3 due 9 Nov"),
    "us_cpi":    ("US CPI (y/y)",    "3.4% (Aug)",  "same as July · Sep due 14 Oct"),
    "us_claims": ("US jobless claims", "197k",      "week to 3 Oct · 199k prior week"),
}

# The latest move in each figure above, as (signed amount, unit). It is what gets
# colour-coded, the way the Global Snapshot colours an index's day change. Edit it
# together with the figure. "ph_cpi" and "ph_jobs" are filled from ph_data.json.
MOVES = {
    "bsp": (25, "bps"), "fed": (25, "bps"), "boj": (25, "bps"), "ecb": (25, "bps"),
    "ph_cpi": (1.1, "pts"), "ph_gdp": (-0.5, "pts"), "us_cpi": (0, "pts"),
    "us_claims": (-2, "k"),
}
# Colour follows what the move means, not its direction: dearer money, faster
# inflation and more jobless are red; only for these is a rise green.
RISE_IS_GOOD = {"ph_gdp"}

CITY = {"name": "Manila", "lat": 14.5995, "lon": 120.9842}

# Gists this builder must never write to. The legacy briefing is maintained by a
# separate Claude scheduled task with its own locked template; writing here would
# silently replace it. Refusing is deliberate - do not "fix" by removing the entry.
PROTECTED_GISTS = {"fd25c59bbbab14d6ea56532bad7bfa9c"}

# Which edition this is. The 6am run shows today; the 6pm run shows what is left
# of today plus tomorrow, because by evening today's agenda is mostly spent.
EDITION = "evening" if NOW.hour >= 12 else "morning"

# Tile order for each edition. Reorder the names to reorder the page; drop a name
# to hide that block. Blocks: changed, day, portfolio, crypto_fx, news, markets,
# reference. Morning leads with the portfolio (the US session has just closed, so
# those values are fresh); evening leads with the US close and risk gauges, ahead
# of the US open at about 9:30 PM PHT.
LAYOUT = {
    "morning": ["changed", "day", "portfolio", "crypto_fx", "news", "markets", "reference"],
    "evening": ["changed", "day", "markets", "portfolio", "crypto_fx", "news", "reference"],
}

# Which provider answered for each index on this run. Filled by indices() and read
# by the template, so the page names the real source instead of assuming one.
IDX_ORIGIN = {}

def _gnews(query, region="US"):
    """A Google News RSS search limited to the last day."""
    import urllib.parse as _q
    loc = "hl=en-PH&gl=PH&ceid=PH:en" if region == "PH" else "hl=en-US&gl=US&ceid=US:en"
    return f"https://news.google.com/rss/search?q={_q.quote_plus(query + ' when:1d')}&{loc}"


# Filipino athletes competing abroad. Edit this list as careers move on; the
# generic terms after it catch anyone not named here.
PH_ATHLETES = ["Alex Eala", "EJ Obiena", "Carlos Yulo", "Kai Sotto"]

# News, weighted by interest. Each category is a list of angles, and the tile takes
# one headline from each angle in turn, so no single angle can fill the category.
# To re-weight: reorder, add or delete an angle. A category with one angle simply
# takes its top NEWS_PER_FEED headlines.
FEEDS = [
    ("PH", "ph", [
        _gnews('Philippines (BSP OR "Bangko Sentral" OR economy OR peso OR inflation OR GDP)', "PH"),
        _gnews('Philippines (Senate OR Congress OR Malacanang OR Comelec OR "Supreme Court" OR policy)', "PH"),
        _gnews('Philippines (PAGASA OR typhoon OR "tropical storm" OR flood OR earthquake OR Phivolcs)', "PH"),
    ]),
    ("Markets", "mk", [
        _gnews('"Federal Reserve" OR "Treasury yields" OR "US inflation" OR "jobs report"'),
        _gnews('"Asian markets" OR "Asia stocks" OR "Southeast Asia stocks" OR Nikkei OR "Hang Seng"'),
        _gnews('"oil prices" OR "Brent crude" OR OPEC OR "gold prices" OR commodities'),
    ]),
    ("Crypto", "cr", [
        _gnews("bitcoin OR ethereum crypto"),
    ]),
    ("Tech/AI", "ai", [
        _gnews("artificial intelligence"),
    ]),
    ("Sports", "sp", [
        _gnews("NBA"),
        _gnews('golf ("PGA Tour" OR LPGA OR "DP World Tour" OR "LIV Golf" OR "Ryder Cup" OR major)'),
        _gnews(" OR ".join(f'"{n}"' for n in PH_ATHLETES)
               + ' OR "Filipino athlete" OR "Filipina athlete" OR "Filipino Olympian"'),
    ]),
]

COINS = [("BTC", "Bitcoin"), ("ETH", "Ethereum"), ("SOL", "Solana"),
         ("BONK", "Bonk"), ("JUP", "Jupiter")]

# Coinbase's JUP feed tracks an unrelated Ethereum "Jupiter Project" token, not
# Solana's JUP. It gets outvoted by the median rather than special-cased.
CG_IDS = {"BTC": "bitcoin", "ETH": "ethereum", "SOL": "solana",
          "BONK": "bonk", "JUP": "jupiter-exchange-solana"}
BN_SYMS = {c: c + "USDT" for c, _ in COINS}
OUTLIER_TOLERANCE = 0.25      # drop a source >25% away from the median

FX = ["USD", "EUR", "JPY", "GBP", "SGD", "AUD", "CNY", "HKD"]


def get(url, headers=None, timeout=None, **kw):
    h = {"User-Agent": "daily-brief/1.0"}
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, timeout=timeout or TIMEOUT, headers=h, **kw)
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
           "&daily=weather_code,temperature_2m_max,temperature_2m_min,"
           "precipitation_probability_max,precipitation_sum,wind_speed_10m_max"
           "&timezone=Asia%2FManila&forecast_days=6")
    r = get(url)
    if not r:
        return None
    j = r.json()
    cur, hourly = j.get("current", {}), j.get("hourly", {})
    times = hourly.get("time", [])
    daily = j.get("daily", {})
    dtimes = daily.get("time", [])

    def slot(target_hour, day=0):
        want = dtimes[day] if day < len(dtimes) else None
        for i, t in enumerate(times):
            if int(t[11:13]) == target_hour and (want is None or t[:10] == want):
                code = hourly["weather_code"][i]
                desc, emoji = WMO.get(code, ("—", "\U0001F321️"))
                return {"temp": round(hourly["temperature_2m"][i]),
                        "pop": hourly["precipitation_probability"][i],
                        "desc": desc, "emoji": emoji}
        return None

    # Next five days, not today. forecast_days=6 is what makes the fifth reachable.
    days = []
    for i in range(1, min(6, len(dtimes))):
        code = daily.get("weather_code", [None] * 6)[i]
        ddesc, demoji = WMO.get(code, ("—", "\U0001F321️"))
        dd = dt.date.fromisoformat(dtimes[i])
        days.append({"name": dd.strftime("%a"), "emoji": demoji, "desc": ddesc,
                      "hi": round(daily["temperature_2m_max"][i]),
                      "lo": round(daily["temperature_2m_min"][i]),
                      "pop": daily.get("precipitation_probability_max", [None] * 6)[i],
                      "mm": daily.get("precipitation_sum", [None] * 6)[i],
                      "wind": daily.get("wind_speed_10m_max", [None] * 6)[i],
                      "code": code,
                      "label": dd.strftime("%a %-d").upper()})

    cdesc, cemoji = WMO.get(cur.get("weather_code"), ("—", "\U0001F321️"))
    return {
        "temp": round(cur.get("temperature_2m", 0)),
        "humidity": cur.get("relative_humidity_2m"),
        "desc": cdesc, "emoji": cemoji,
        "hi": round(daily.get("temperature_2m_max", [0])[0]),
        "lo": round(daily.get("temperature_2m_min", [0])[0]),
        "morning": slot(8), "afternoon": slot(14), "evening": slot(19),
        # The evening edition shows these instead: by 6 PM today's are spent.
        "tomorrow": {"morning": slot(8, 1), "afternoon": slot(14, 1), "evening": slot(19, 1)},
        "days": days,
    }


def weather_alerts(w):
    """Flag thunderstorms, heavy rain, strong wind and heat across the 5-day window.
    Open-Meteo carries no PAGASA bulletins, so tropical cyclones and LPAs cannot be
    detected here - the last line says so rather than implying an all-clear."""
    if not w or not w.get("days"):
        return []
    storm, heavy, windy, hot = [], [], [], []
    for d in w["days"]:
        nm = d["name"]
        if (d.get("code") or 0) >= 95:
            storm.append(nm)
        if (d.get("mm") or 0) >= 20 or (d.get("pop") or 0) >= 95:
            heavy.append(nm)
        if (d.get("wind") or 0) >= 40:
            windy.append(nm)
        if (d.get("hi") or 0) >= 36:
            hot.append(nm)

    def phrase(ds):
        return ds[0] if len(ds) == 1 else ", ".join(ds[:-1]) + " and " + ds[-1]

    out = []
    if storm:
        out.append("\u26C8\ufe0f Thunderstorms expected " + phrase(storm) + ".")
    if heavy:
        mx = max((d.get("mm") or 0) for d in w["days"])
        out.append("\U0001F327\ufe0f Heavy rain " + phrase(heavy)
                   + f" \u2014 up to {mx:.0f} mm in a day.")
    if windy:
        mx = max((d.get("wind") or 0) for d in w["days"])
        out.append("\U0001F32C\ufe0f Strong wind " + phrase(windy)
                   + f", peaking near {mx:.0f} km/h.")
    if hot:
        mx = max((d.get("hi") or 0) for d in w["days"])
        out.append(f"\U0001F321\ufe0f Heat reaching {mx}""\u00b0""C " + phrase(hot) + ".")
    if not out:
        out.append("No thunderstorms, damaging wind or extreme heat in the next five days.")
    out.append("Open-Meteo carries no PAGASA bulletins \u2014 check PAGASA for LPAs and "
               "tropical cyclones.")
    return out


# ----------------------------------------------------------------- markets
def fx():
    """PHP per unit, plus the move against the previous ECB fix.
    Green = peso stronger (fewer pesos per unit)."""
    frm = (NOW - dt.timedelta(days=12)).strftime("%Y-%m-%d")
    r = get(f"https://api.frankfurter.dev/v1/{frm}..?from=PHP&to=" + ",".join(FX))
    if not r:
        r = get("https://api.frankfurter.app/latest?from=PHP&to=" + ",".join(FX))
        if not r:
            return None
        rates = r.json().get("rates", {})
        return {k: {"php": (1 / v) * (100 if k == "JPY" else 1), "prev": None, "chg": None}
                for k, v in rates.items() if v}
    try:
        series = r.json().get("rates", {})
    except Exception:
        return None
    dates = sorted(series)
    if not dates:
        return None
    last, prev = dates[-1], (dates[-2] if len(dates) > 1 else None)
    out = {}
    for k in FX:
        v = series[last].get(k)
        if not v:
            continue
        mult = 100 if k == "JPY" else 1
        php = (1 / v) * mult
        pv = series.get(prev, {}).get(k) if prev else None
        php_prev = (1 / pv) * mult if pv else None
        out[k] = {"php": php, "prev": php_prev,
                  "chg": ((php - php_prev) / php_prev * 100) if php_prev else None}
    out["_asof"] = last
    print(f"  fx: {len(out)-1} pairs, ECB fix {last}")
    return out


def _median(xs):
    xs = sorted(xs)
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def cb_prices():
    """Coinbase spot, plus yesterday's spot to derive a 24h change."""
    out, y = {}, (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    for sym, _ in COINS:
        r = get(f"https://api.coinbase.com/v2/prices/{sym}-USD/spot")
        if not r:
            continue
        try:
            px = float(r.json()["data"]["amount"])
        except Exception:
            continue
        chg = None
        ry = get(f"https://api.coinbase.com/v2/prices/{sym}-USD/spot?date={y}")
        if ry:
            try:
                prev = float(ry.json()["data"]["amount"])
                if prev:
                    chg = (px - prev) / prev * 100
            except Exception:
                pass
        out[sym] = (px, chg)
    return out


def cg_prices():
    ids = ",".join(CG_IDS[c] for c, _ in COINS)
    r = get("https://api.coingecko.com/api/v3/simple/price"
            f"?ids={ids}&vs_currencies=usd&include_24hr_change=true")
    if not r:
        return {}
    out = {}
    try:
        j = r.json()
    except Exception:
        return {}
    for sym, _ in COINS:
        d = j.get(CG_IDS[sym])
        if d and d.get("usd"):
            out[sym] = (float(d["usd"]), d.get("usd_24h_change"))
    return out


def bn_prices():
    import urllib.parse as up
    syms = up.quote(json.dumps([BN_SYMS[c] for c, _ in COINS], separators=(",", ":")))
    out = {}
    for host in ("https://data-api.binance.vision", "https://api.binance.com"):
        r = get(f"{host}/api/v3/ticker/24hr?symbols={syms}")
        if not r:
            continue
        try:
            rev = {v: k for k, v in BN_SYMS.items()}
            for row in r.json():
                sym = rev.get(row.get("symbol"))
                if not sym:
                    continue
                out[sym] = (float(row["lastPrice"]), float(row["priceChangePercent"]))
            if out:
                return out
        except Exception:
            continue
    return out


def crypto():
    """Median of Coinbase, CoinGecko and Binance; sources >25% off are discarded."""
    feeds = {"CB": cb_prices(), "CG": cg_prices(), "BN": bn_prices()}
    live = [k for k, v in feeds.items() if v]
    print(f"  crypto sources reachable: {', '.join(live) if live else 'none'}")

    rows = []
    for sym, name in COINS:
        quotes = {k: v[sym] for k, v in feeds.items() if sym in v}
        if not quotes:
            rows.append({"sym": sym, "name": name, "price": None, "chg": None,
                         "srcs": 0, "total": len(feeds), "dropped": []})
            continue
        prices = [q[0] for q in quotes.values()]
        med = _median(prices)
        kept, dropped = {}, []
        for k, (px, ch) in quotes.items():
            if med and abs(px - med) / med > OUTLIER_TOLERANCE:
                dropped.append(k)
            else:
                kept[k] = (px, ch)
        if not kept:                       # everything disagreed; fall back to raw median
            kept, dropped = quotes, []
        final_px = _median([v[0] for v in kept.values()])
        chs = [v[1] for v in kept.values() if v[1] is not None]
        rows.append({"sym": sym, "name": name, "price": final_px,
                     "chg": _median(chs) if chs else None,
                     "srcs": len(kept), "total": len(quotes), "dropped": sorted(dropped)})
    for r in rows:
        if r["price"] is not None:
            note = f" (dropped {'+'.join(r['dropped'])})" if r["dropped"] else ""
            print(f"    {r['sym']}={r['price']:.8f}".rstrip("0").rstrip(".")
                  + f" [{r['srcs']}/{r['total']}]{note}")
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


FRED_TIMEOUT = 45


def fred_series(series_id, days=40):
    """FRED CSV, no API key needed. Stooq rate-limits datacenter IPs such as
    GitHub runners, which is why the index data moved here."""
    cosd = (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%d")
    url = f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}&cosd={cosd}"
    r = None
    for attempt in (1, 2):
        r = get(url, timeout=FRED_TIMEOUT)
        if r:
            break
        if attempt == 1:
            print(f"  . retrying {series_id}", file=sys.stderr)
            time.sleep(3)
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


IDX_SYMS = {
    "spx": {"stooq": "^spx", "yahoo": "^GSPC", "fred": "SP500",      "name": "S&P 500"},
    "ndq": {"stooq": "^ndq", "yahoo": "^IXIC", "fred": "NASDAQCOM",  "name": "Nasdaq"},
    "vix": {"stooq": "^vix", "yahoo": "^VIX",  "fred": "VIXCLS",     "name": "VIX"},
}


def idx_stooq():
    """No key, but Stooq throttles datacenter IPs, so this often returns nothing."""
    q = "+".join(v["stooq"] for v in IDX_SYMS.values())
    r = get(f"https://stooq.com/q/l/?s={q}&f=sd2t2ohlcv&h&e=csv", timeout=20)
    out = {}
    if not r:
        return out
    rev = {v["stooq"].lower(): k for k, v in IDX_SYMS.items()}
    for line in r.text.strip().splitlines()[1:]:
        p_ = line.split(",")
        if len(p_) < 8:
            continue
        key = rev.get(p_[0].lower())
        if not key:
            continue
        try:
            close, openp, day = float(p_[6]), float(p_[3]), p_[1]
        except ValueError:
            continue
        out[key] = {"close": close, "asof": day,
                    "pct": ((close - openp) / openp * 100) if openp else None}
    return out


def idx_yahoo():
    """No key. The chart endpoint carries the previous close, so the day move is exact."""
    out = {}
    for key, v in IDX_SYMS.items():
        r = get("https://query1.finance.yahoo.com/v8/finance/chart/"
                f"{v['yahoo']}?range=5d&interval=1d", timeout=20)
        if not r:
            continue
        try:
            meta = r.json()["chart"]["result"][0]["meta"]
            close = meta.get("regularMarketPrice")
            prev = meta.get("chartPreviousClose") or meta.get("previousClose")
            if close is None:
                continue
            ts = meta.get("regularMarketTime")
            out[key] = {
                "close": float(close),
                "pct": ((close - prev) / prev * 100) if prev else None,
                "asof": (dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")
                         if ts else ""),
            }
        except Exception:
            continue
    return out


def idx_fred_api():
    """The real FRED API. Needs a free key from
    fred.stlouisfed.org/docs/api/api_key.html - far faster than fredgraph.csv."""
    key = os.environ.get("FRED_API_KEY")
    if not key:
        return {}
    out = {}
    start_d = (NOW - dt.timedelta(days=40)).strftime("%Y-%m-%d")
    for k, v in IDX_SYMS.items():
        r = get("https://api.stlouisfed.org/fred/series/observations"
                f"?series_id={v['fred']}&api_key={key}&file_type=json"
                f"&observation_start={start_d}&sort_order=desc&limit=5", timeout=25)
        if not r:
            continue
        try:
            obs = [o for o in r.json().get("observations", []) if o.get("value") != "."]
            if not obs:
                continue
            last = float(obs[0]["value"])
            prev = float(obs[1]["value"]) if len(obs) > 1 else None
            out[k] = {"close": last, "asof": obs[0]["date"],
                      "pct": ((last - prev) / prev * 100) if prev else None}
        except Exception:
            continue
    return out


def idx_fred_csv():
    """Chart-download endpoint. Slow and timeout-prone from runners; last resort."""
    out = {}
    for k, v in IDX_SYMS.items():
        got = fred_series(v["fred"])
        if got:
            out[k] = got
    return out


def indices(prev_state=None):
    """Try each provider in turn, filling only what is still missing, then fall back
    to the previous run's cache. Logs which provider answered for each index."""
    out, origin = {}, {}
    for label, fn in (("stooq", idx_stooq), ("yahoo", idx_yahoo),
                      ("fred-api", idx_fred_api), ("fred-csv", idx_fred_csv)):
        missing = [k for k in IDX_SYMS if k not in out]
        if not missing:
            break
        try:
            got = fn() or {}
        except Exception as e:
            print(f"  . {label} errored ({type(e).__name__})", file=sys.stderr)
            continue
        for k in missing:
            if got.get(k, {}).get("close"):
                out[k] = got[k]
                origin[k] = label
        if got:
            print(f"  . {label}: {len([k for k in missing if k in got])} of {len(missing)}")

    cache = (prev_state or {}).get("idx_cache") or {}
    for k in IDX_SYMS:
        if k not in out and cache.get(k, {}).get("close"):
            c = dict(cache[k])
            c["stale"] = True
            out[k] = c
            origin[k] = "cache"

    IDX_ORIGIN.clear()
    IDX_ORIGIN.update(origin)
    if out:
        print("  indices: " + ", ".join(
            f"{k}={out[k]['close']:,.2f} [{origin.get(k, '?')}]" for k in out))
    else:
        print("  ! no index data from any provider", file=sys.stderr)
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


CAL_DAYS_AHEAD = 3      # days shown after today, in both editions


def _window():
    """Both editions cover today plus the next CAL_DAYS_AHEAD days. The evening
    edition additionally hides today's events that have already finished."""
    start = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    days = 1 + CAL_DAYS_AHEAD
    return start, start + dt.timedelta(days=days), days


def _keep(when, allday, start, end, until=None):
    """Keep anything whose RANGE overlaps the window, not just its start - a
    multi-day hotel stay begins before today and must still show. On the evening
    edition, hide single events that have already finished."""
    fin = until or when
    if fin <= start or when >= end:
        return False
    if EDITION == "evening" and not allday and fin < NOW - dt.timedelta(hours=1):
        return False
    return True


def _calendar_ids(tok):
    """Every calendar the service account can see, plus any listed in CALENDAR_ID.
    Shared and subscribed calendars only appear once they are shared with the
    service account address - sharing your primary one is not enough."""
    ids = [c.strip() for c in (os.environ.get("CALENDAR_ID") or "").split(",") if c.strip()]
    r = get("https://www.googleapis.com/calendar/v3/users/me/calendarList"
            "?minAccessRole=reader&maxResults=250",
            headers={"Authorization": f"Bearer {tok}"})
    if r:
        try:
            for c in r.json().get("items", []):
                cid = c.get("id")
                if cid and cid not in ids and not c.get("deleted"):
                    ids.append(cid)
        except Exception:
            pass
    return ids


def _parse_ev(ev, cal_name):
    def one(key):
        v = ev.get(key, {})
        if "dateTime" in v:
            return dt.datetime.fromisoformat(v["dateTime"]).astimezone(PHT), False
        if "date" in v:
            d = dt.date.fromisoformat(v["date"])
            return dt.datetime(d.year, d.month, d.day, tzinfo=PHT), True
        return None, None
    when, allday = one("start")
    if when is None:
        return None
    until, _ = one("end")
    return {"when": when, "until": until, "allday": allday,
            "today": when.date() == NOW.date(),
            "multi": bool(until and (until.date() - when.date()).days > 1),
            "title": str(ev.get("summary") or "(no title)"),
            "where": str(ev.get("location") or ""),
            "cal": cal_name}


def calendar_via_api():
    """Google expands recurring events server-side, so there is no RRULE logic here."""
    tok = _sa_token(["https://www.googleapis.com/auth/calendar.readonly"])
    if not tok:
        return None
    cal_ids = _calendar_ids(tok)
    if not cal_ids:
        return None
    start, end, _ = _window()
    # Reach back 30 days so multi-day stays that began earlier are still caught.
    lookback = start - dt.timedelta(days=30)
    import urllib.parse as up
    out, seen = [], set()
    for cid in cal_ids:
        q = up.urlencode({"timeMin": lookback.isoformat(), "timeMax": end.isoformat(),
                          "singleEvents": "true", "orderBy": "startTime",
                          "maxResults": "250"})
        r = get(f"https://www.googleapis.com/calendar/v3/calendars/{up.quote(cid)}/events?{q}",
                headers={"Authorization": f"Bearer {tok}"})
        if not r:
            print(f"  ! calendar {cid[:18]}... unreadable", file=sys.stderr)
            continue
        try:
            items = r.json().get("items", [])
        except Exception:
            continue
        nm = cid.split("@")[0][:18]
        for ev in items:
            e = _parse_ev(ev, nm)
            if not e or not _keep(e["when"], e["allday"], start, end, e["until"]):
                continue
            key = (e["title"], e["when"].isoformat())
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (not e["multi"], e["when"], e["title"]))
    print(f"  calendar (api): {len(out)} event(s) across {len(cal_ids)} calendar(s)")
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
        out.append({"when": when, "until": None, "allday": allday, "multi": False,
                    "today": when.date() == NOW.date(),
                    "title": str(ev.get("SUMMARY") or "(no title)"),
                    "where": str(ev.get("LOCATION") or ""), "cal": ""})
    out.sort(key=lambda e: (e["when"], e["title"]))
    print(f"  calendar (ics): {len(out)} event(s)")
    return out


def calendar_events():
    # None means "not configured"; an empty list means a genuinely clear day.
    # Only fall through to the iCal path when the API path is not set up at all.
    evs = calendar_via_api()
    return evs if evs is not None else calendar_via_ics()


# --------------------------------------------------------------- portfolio
# Why the portfolio tile is empty, in words the tile can show. Set by sheet_rows().
PF_WHY = {"msg": ""}
# Cash balance found on the sheet's CASH row, if any. Set by parse_holdings().
PF_META = {"cash": None}


def sheet_rows():
    """Read the holdings tab via a service account. Nothing public, nothing expiring.
    On any failure, PF_WHY says which step failed so the tile can name the fix."""
    sheet_id = (os.environ.get("SHEET_ID") or "").strip()
    # The workflow passes an unset secret as an EMPTY string, which os.environ.get's
    # default does not catch - hence "or". An empty range made every request fail.
    rng = (os.environ.get("SHEET_RANGE") or "").strip()
    if not sheet_id:
        PF_WHY["msg"] = "The SHEET_ID secret is not set."
        return None
    tok = _sa_token(["https://www.googleapis.com/auth/spreadsheets.readonly"])
    if not tok:
        PF_WHY["msg"] = ("The GOOGLE_SA_JSON secret is missing or is not a valid "
                         "service-account key.")
        return None
    import urllib.parse as _q
    url = (f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/"
           + _q.quote(rng or "A1:U20000", safe="!:"))
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"Authorization": f"Bearer {tok}"})
    except Exception as e:
        PF_WHY["msg"] = f"Google Sheets could not be reached ({type(e).__name__})."
        return None
    if not r.ok:
        PF_WHY["msg"] = {
            400: "Google rejected the range. Check that the SHEET_RANGE secret uses the "
                 "tab's exact name, for example TabName!A1:U20000.",
            403: "Google refused access. Share the sheet with the service account's email "
                 "as Viewer, and check the Google Sheets API is enabled in its project.",
            404: "No spreadsheet has that id. Check the SHEET_ID secret is the part of the "
                 "sheet's URL between /d/ and /edit.",
        }.get(r.status_code, f"Google Sheets answered HTTP {r.status_code}.")
        print(f"  ! sheet read failed: HTTP {r.status_code}", file=sys.stderr)
        return None
    rows = r.json().get("values", [])
    if not rng:
        PF_WHY["msg"] = ("The SHEET_RANGE secret is not set, so only the first tab was read. "
                         "Add it, naming the holdings tab: TabName!A1:U20000.")
    elif not rows:
        PF_WHY["msg"] = "That range is empty. Check the tab name in SHEET_RANGE."
    print(f"  sheet: {len(rows)} row(s) read" + ("" if rng else " (SHEET_RANGE unset: first tab)"))
    return rows


# Header synonyms, matched after lowercasing and stripping spaces/underscores.
ALIASES = {
    # identity
    "ticker": "sym", "symbol": "sym", "asset": "sym", "holding": "sym", "code": "sym",
    "name": "name", "description": "name",
    "type": "kind", "class": "kind", "category": "kind",
    # size
    "qty": "qty", "quantity": "qty", "shares": "qty", "units": "qty", "amount": "qty",
    "stockqty": "qty", "shareqty": "qty", "noofshares": "qty", "position": "qty",
    # cost
    "cost": "cost", "costbasis": "cost", "avgcost": "cost", "averagecost": "cost",
    "buyprice": "cost", "entry": "cost", "cost/unit": "cost",
    "avgbuyprice": "cost", "averagebuyprice": "cost", "avgprice": "cost",
    # values the sheet already computes - preferred over fetching quotes
    "curstockprice": "price", "currentprice": "price", "currentstockprice": "price",
    "price": "price", "marketprice": "price", "lastprice": "price",
    "totalcurrentvalue": "value", "currentvalue": "value", "marketvalue": "value",
    "totalbuyvalue": "buyvalue", "totalcost": "buyvalue",
    "+/-": "pl", "gainloss": "pl", "unrealised": "pl", "unrealized": "pl",
    "pershare%": "pct", "percent": "pct", "return%": "pct",
    # today's move, e.g. a column of =GOOGLEFINANCE(ticker,"changepct")
    "day%": "day", "day": "day", "daychange": "day", "daychange%": "day", "today%": "day",
    "1d%": "day", "dailychange%": "day", "changepct": "day", "change%": "day",
    "shareoftotalport": "weight", "weight": "weight", "allocation": "weight",
}

# Rows whose Type marks them as something other than a position.
NON_HOLDING_TYPES = {"cash", "dividend", "div", "deposit", "withdrawal", "transfer", "fee"}


def parse_holdings(rows):
    """Tolerant of real spreadsheets: the header can be on any of the first 15 rows,
    positions can sit anywhere below it (filtered views leave big row gaps), and the
    sheet's own computed price/value columns are used when present."""
    PF_META["cash"] = None
    if not rows:
        return []
    hdr_i, cols = None, {}
    for i, row in enumerate(rows[:15]):
        m = {}
        for j, cell in enumerate(row):
            key = str(cell).strip().lower().replace(" ", "").replace("_", "")
            if key in ALIASES and ALIASES[key] not in m:
                m[ALIASES[key]] = j
        if "sym" in m and "qty" in m:
            hdr_i, cols = i, m
            break
    if hdr_i is None:
        got = [str(c)[:18] for c in (rows[0] if rows else [])][:12]
        print(f"  ! no ticker/quantity header found. first row was: {got}", file=sys.stderr)
        return []
    print(f"  sheet header on row {hdr_i + 1}; columns found: "
          + ", ".join(sorted(cols)))

    def num(x):
        try:
            t = str(x).replace(",", "").replace("$", "").replace("\u20b1", "")
            t = t.replace("%", "").strip()
            if t.startswith("(") and t.endswith(")"):
                t = "-" + t[1:-1]
            return float(t)
        except Exception:
            return None

    def cell(row, key):
        j = cols.get(key)
        return row[j] if (j is not None and j < len(row)) else None

    found = {}
    for row in rows[hdr_i + 1:]:
        if not row:
            continue
        sym = str(cell(row, "sym") or "").strip().upper()
        if not sym or len(sym) > 12:
            continue
        kind_raw = str(cell(row, "kind") or "").strip().lower()
        if sym == "CASH" or kind_raw == "cash":
            # Not a position, but its balance feeds "Cash on hand".
            for key in ("value", "buyvalue", "qty"):
                c = num(cell(row, key))
                if c:
                    PF_META["cash"] = c
                    break
            continue
        if any(t in kind_raw for t in NON_HOLDING_TYPES):
            continue
        qty = num(cell(row, "qty"))
        if not qty:
            continue
        kind = "crypto" if ("cryp" in kind_raw or "coin" in kind_raw
                            or sym in {c[0] for c in COINS}) else "etf"
        found[sym] = {
            "sym": sym, "kind": kind,
            "name": str(cell(row, "name") or "").strip()[:42],
            "qty": qty,
            "cost": num(cell(row, "cost")),
            "price": num(cell(row, "price")),
            "value": num(cell(row, "value")),
            "pl": num(cell(row, "pl")),
            "pct": num(cell(row, "pct")),          # the sheet's own unrealised %
            "buyvalue": num(cell(row, "buyvalue")),
            "day": num(cell(row, "day")),          # today's move, if the sheet has it
        }
    out = list(found.values())
    print(f"  holdings: {len(out)} row(s) "
          f"({sum(1 for h in out if h['kind'] == 'crypto')} crypto)")
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
    """Prefer the sheet's own price and value columns - they are what Justin sees in
    his spreadsheet. Each row ends up with two separate moves: "day" (today's change,
    from the sheet if it has such a column, else from a quote) and "upct" (unrealised
    gain against cost basis). The old tile showed the second under the heading "Day"."""
    rows = parse_holdings(sheet_rows() or [])
    if not rows:
        return None
    spot = {c["sym"]: c for c in (crypto_rows or [])}
    need = [h["sym"] for h in rows
            if h["kind"] == "etf" and (h["price"] is None or h["day"] is None)]
    quotes = etf_quotes(need) if need else {}
    if need:
        print(f"  quotes for {len(quotes)}/{len(need)} holdings (price or day move)")

    for h in rows:
        q = spot.get(h["sym"]) if h["kind"] == "crypto" else quotes.get(h["sym"])
        if h["price"] is None and q:
            h["price"] = q["price"]
        if h["day"] is None and q:
            h["day"] = q.get("chg") if h["kind"] == "crypto" else q.get("pct")
        if h["value"] is None and h["price"] is not None:
            h["value"] = h["price"] * h["qty"]
        # Cost basis for the whole position: the sheet's total, else unit cost x quantity.
        h["basis"] = h["buyvalue"] if h["buyvalue"] else (
            h["cost"] * h["qty"] if h["cost"] is not None else None)
        if h["pl"] is None and h["value"] is not None and h["basis"]:
            h["pl"] = h["value"] - h["basis"]
        # Computed, not read, where possible: a sheet cell may hold 9.0 or 0.09 for 9%.
        h["upct"] = (h["pl"] / h["basis"] * 100 if (h["pl"] is not None and h["basis"])
                     else h["pct"])
    rows.sort(key=lambda h: (h["value"] or 0), reverse=True)
    print(f"  portfolio: day move on {sum(1 for h in rows if h['day'] is not None)}"
          f"/{len(rows)}, cash row {'found' if PF_META['cash'] else 'not found'}")
    return rows


def us_session_label():
    """Which US session the prices belong to, e.g. "Thursday 8 October's close", or
    None while the session is open. Weekends are stepped over; US market holidays
    are not known here, so on a holiday this names the holiday itself."""
    try:
        from zoneinfo import ZoneInfo
        ny = NOW.astimezone(ZoneInfo("America/New_York"))
    except Exception:
        return "the last US close"
    mins, day = ny.hour * 60 + ny.minute, ny.date()
    if ny.weekday() < 5 and 570 <= mins < 960:
        return None
    if ny.weekday() >= 5 or mins < 570:
        day -= dt.timedelta(days=1)
    while day.weekday() >= 5:
        day -= dt.timedelta(days=1)
    return day.strftime("%A %-d %B") + "\u2019s close"


_NUMWORD = ["none", "one", "two", "three", "four", "five", "six", "seven", "eight",
            "nine", "ten", "eleven", "twelve"]


def pf_commentary(rows, cash):
    """The short read under the portfolio, built only from the figures in the tile."""
    def nw(n):
        return _NUMWORD[n] if 0 <= n < len(_NUMWORD) else str(n)

    def sp(v, d=2):
        return ("+" if v >= 0 else "\u2212") + f"{abs(v):.{d}f}%"

    def usd(v):
        return f"${abs(v):,.2f}"

    mv = [h for h in rows if h.get("day") is not None and h.get("value")]
    label = us_session_label()
    head = ("Marked to " + label) if label else "US session in progress"
    out = []
    if mv:
        up = [h for h in mv if h["day"] > 0]
        dn = [h for h in mv if h["day"] < 0]
        head += " \u2014 " + (
            f"{nw(len(dn))} of {nw(len(mv))} holdings fell." if len(dn) > len(up) else
            f"{nw(len(up))} of {nw(len(mv))} holdings rose." if len(up) > len(dn) else
            "gainers and losers evenly split.")
        for h in mv:        # dollars this holding moved today
            h["_d"] = h["value"] - h["value"] / (1 + h["day"] / 100)
        book = sum(h["_d"] for h in mv)
        best, worst = max(mv, key=lambda h: h["day"]), min(mv, key=lambda h: h["day"])
        if len(up) == 1 and len(dn) > 1:
            lead = f'Only <b>{html.escape(up[0]["sym"])} {sp(up[0]["day"])}</b> finished green.'
        elif len(dn) == 1 and len(up) > 1:
            lead = f'Only <b>{html.escape(dn[0]["sym"])} {sp(dn[0]["day"])}</b> finished red.'
        else:
            lead = (f'Best <b>{html.escape(best["sym"])} {sp(best["day"])}</b>, worst '
                    f'<b>{html.escape(worst["sym"])} {sp(worst["day"])}</b>.')
        out.append(lead + f' The book {"added" if book >= 0 else "gave back"} about '
                          f'<b>${abs(book):,.0f}</b> on the day.')
        if len(mv) >= 3:
            big = sorted(mv, key=lambda h: abs(h["day"]), reverse=True)[:2]
            hit = max(mv, key=lambda h: abs(h["_d"]))
            out.append(
                f'<b>{html.escape(big[0]["sym"])} {sp(big[0]["day"])}</b> and '
                f'<b>{html.escape(big[1]["sym"])} {sp(big[1]["day"])}</b> were the biggest '
                f'moves \u2014 {html.escape(hit["sym"])} alone '
                f'{"added" if hit["_d"] >= 0 else "cost"} ${abs(hit["_d"]):,.0f}.')
    else:
        head += " \u2014 no day moves available for these holdings."
    # The totals line would go stale as crypto reprices live, so it is ETF-only books.
    priced = [h for h in rows if h.get("value")]
    based = [h for h in priced if h.get("basis")]
    if based and len(based) == len(priced) and not any(h["kind"] == "crypto" for h in rows):
        val, basis = sum(h["value"] for h in based), sum(h["basis"] for h in based)
        pl = val - basis
        line = (f'Value is {usd(val)} against a {usd(basis)} cost basis, so unrealised '
                f'stands at <b>{"+" if pl >= 0 else "\u2212"}{usd(pl)} '
                f'({sp(pl / basis * 100, 1)})</b>')
        line += (f'; with {usd(cash)} cash the book is {usd(val + cash)}.' if cash else ".")
        out.append(line)
    return head, out


# ------------------------------------------------------------------ gauges
def equity_gauge(vix):
    if vix is None:
        return {"score": 50, "label": "Equities: UNKNOWN", "status": "UNKNOWN",
                "sub": "VIX unavailable",
                "bullets": ["Volatility data unavailable this morning.",
                            "Treat positioning decisions as unchanged until it returns."]}
    # Shown as 100 minus the volatility score, so both gauges read the same way:
    # needle to the right is calm / risk-on, needle to the left is stress.
    score = 100 - max(0, min(100, (vix - 10) / 30 * 100))
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
    return {"score": score, "label": f"Equities: {label}", "status": label,
            "sub": f"VIX {vix:.2f} \u00b7 higher score = calmer", "bullets": bl}


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
        return {"score": 50, "label": "Crypto: UNKNOWN", "status": "UNKNOWN",
                "sub": "Index unavailable",
                "bullets": ["Sentiment index unavailable — the live value will load in your browser."]}
    v, lab = fg["value"], fg["label"]
    return {"score": v, "label": f"Crypto: {lab.upper()}", "status": lab.upper(),
            "sub": "Fear & Greed Index", "bullets": CR_BUCKETS[fg_bucket(v)]}


def _overdue(series, lag_months, release_day):
    """Short month name of a figure that should be published by now but is not in
    the series yet, else None. PSA publishes inflation about the 5th-7th of the
    following month and the Labour Force Survey about a month after that."""
    try:
        back = lag_months if NOW.day >= release_day else lag_months + 1
        want = NOW.year * 12 + NOW.month - 1 - back
        last = series[-1][0]
        have = int(last[:4]) * 12 + int(last[5:7]) - 1
        if have < want:
            return dt.date(want // 12, want % 12 + 1, 1).strftime("%b")
    except Exception:
        pass
    return None


def ph_indicators():
    """Local PSA figures. There is no public PSA API, so ph_data.json is the source."""
    try:
        d = json.loads(io.open("ph_data.json", encoding="utf-8").read())
    except Exception as e:
        print(f"  ! ph_data.json unreadable: {type(e).__name__}", file=sys.stderr)
        return None
    for k in ("inflation", "unemployment"):
        if isinstance(d.get(k), dict):
            d[k]["series"] = (d[k].get("series") or [])[-9:]     # cap at 9 months
    # Flag a series that has fallen behind PSA's release calendar, so a missed
    # manual update shows on the page instead of passing silently.
    for k, lag, day in (("inflation", 1, 8), ("unemployment", 2, 10)):
        if isinstance(d.get(k), dict):
            d[k]["due"] = _overdue(d[k].get("series") or [], lag, day)
    # The headline inflation row is taken from the series, not typed in twice.
    ser = (d.get("inflation") or {}).get("series") or []
    if ser:
        (m1, v1) = ser[-1]
        note = ""
        if len(ser) > 1:
            (m0, v0) = ser[-2]
            note = (f"same as {mon(m0)}" if v1 == v0 else f"from {v0:g}% in {mon(m0)}")
            MOVES["ph_cpi"] = (round(v1 - v0, 2), "pts")
        if d["inflation"].get("due"):
            note += ("; " if note else "") + f'{d["inflation"]["due"]} print is due'
        PRINTS["ph_cpi"] = (PRINTS["ph_cpi"][0], f"{v1:g}% ({mon(m1)})", note)
    ser = (d.get("unemployment") or {}).get("series") or []
    if len(ser) > 1:
        MOVES["ph_jobs"] = (round(ser[-1][1] - ser[-2][1], 2), "pts")
    b = d.get("barista") or {}
    try:
        hourly = b["wage_daily_php"] / b["hours_per_day"]
        d["barista"]["minutes"] = b["cappuccino_php"] / hourly * 60
        d["barista"]["hourly"] = hourly
    except Exception:
        d.setdefault("barista", {})["minutes"] = None
    ps = d.get("psei") or {}
    if ps.get("close") and ps.get("prev"):
        ps["pct"] = (ps["close"] - ps["prev"]) / ps["prev"] * 100
    print(f"  ph indicators: {len(d.get('inflation', {}).get('series', []))} inflation, "
          f"{len(d.get('unemployment', {}).get('series', []))} unemployment, "
          f"psei {ps.get('close')}, barista "
          f"{(d.get('barista') or {}).get('minutes') and round(d['barista']['minutes'])} min")
    return d


STATE_FILE = "state.json"


def load_state():
    try:
        return json.loads(io.open(STATE_FILE, encoding="utf-8").read())
    except Exception:
        return {}


def save_state(st):
    try:
        io.open(STATE_FILE, "w", encoding="utf-8").write(json.dumps(st, indent=1, sort_keys=True))
    except Exception as e:
        print(f"  ! could not write state.json: {type(e).__name__}", file=sys.stderr)


def barista_memory(ph, prev):
    """Current Barista Index plus the value it last changed from. 'barista_was' is
    carried forward between builds, so the colour persists until the next change
    instead of lasting for a single edition."""
    m = (ph.get("barista") or {}).get("minutes")
    cur = round(m, 1) if m else None
    old = prev.get("barista")
    was = old if (old is not None and cur is not None and old != cur) else prev.get("barista_was")
    return {"barista": cur, "barista_was": was}


def snapshot_state(d):
    """The handful of values worth diffing between editions."""
    idx = d.get("indices") or {}
    ph = d.get("ph") or {}
    btc = next((c for c in (d.get("crypto") or []) if c["sym"] == "BTC"), None)
    return {
        "spx": (idx.get("spx") or {}).get("close"),
        "ndq": (idx.get("ndq") or {}).get("close"),
        "vix": (idx.get("vix") or {}).get("close"),
        "psei": (ph.get("psei") or {}).get("close"),
        "fng": (d.get("fg") or {}).get("value"),
        "btc": btc["price"] if btc else None,
        "usdphp": ((d.get("fx") or {}).get("USD") or {}).get("php"),
        "rates": {k: v[0] for k, v in RATES.items()},
        "idx_cache": {k: {"close": v.get("close"), "pct": v.get("pct"),
                          "asof": v.get("asof")}
                      for k, v in (d.get("indices") or {}).items() if v.get("close")},
        "ph_cpi": PRINTS["ph_cpi"][1],
        "ph_inf_last": (((ph.get("inflation") or {}).get("series") or [None])[-1]),
        "ph_un_last": (((ph.get("unemployment") or {}).get("series") or [None])[-1]),
        **barista_memory(ph, d.get("prev_state") or {}),
        "edition": EDITION,
        "built": NOW.isoformat(),
    }


# -------------------------------------------------------------------- news
NEWS_PER_FEED = 3

# Titles that are a page, not a story: fixtures, tickers, listings, live blogs.
_NEWS_JUNK = re.compile(
    r"\b(scores?|schedules?|standings|fixtures|box score|results|live (stream|blog|updates?)"
    r"|how to watch|where to watch|odds|picks|highlights|photos|gallery|quiz|horoscope"
    r"|podcast|newsletter|stock quote|price today)\b", re.I)
_NEWS_STOP = set("a an the of to in on for and or at by with from as is are was were be "
                 "its it this that after over into amid says said new".split())


def _news_words(title):
    return {w for w in re.findall(r"[a-z0-9]+", title.lower())
            if len(w) > 2 and w not in _NEWS_STOP}


def _news_ok(title):
    """A headline you can learn something from: a full clause, not a label.
    Short titles and fixture/listing pages ("Scores & Schedule", "Eagles") fail."""
    words = title.split()
    if len(words) < 6 or len(title) < 35:
        return False
    if _NEWS_JUNK.search(title) and len(words) < 11:
        return False
    return True


def _news_same(a, b):
    """True when two headlines are the same story from different sites: most of the
    shorter headline's meaningful words appear in the other."""
    if not a or not b:
        return False
    return len(a & b) / min(len(a), len(b)) >= 0.6


def _news_candidates(url):
    """Usable headlines from one feed, in the feed's own order."""
    r = get(url)
    if not r:
        return [], 0
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError:
        return [], 0
    out, thin = [], 0
    for it in root.iter("item"):
        t = (it.findtext("title") or "").strip()
        if not t:
            continue
        # Google News titles end " - Publisher"; keep the publisher separately.
        src = (it.findtext("source") or "").strip()
        if src and t.endswith(" - " + src):
            t = t[: -len(src) - 3].strip()
        elif " - " in t:
            t, src = [x.strip() for x in t.rsplit(" - ", 1)]
        if not _news_ok(t):
            thin += 1
            continue
        out.append((t, src))
    return out, thin


def news():
    items, seen = [], []
    skipped_dup = skipped_thin = 0
    for name, tag, urls in FEEDS:
        pools = []
        for u in urls:
            cands, thin = _news_candidates(u)
            skipped_thin += thin
            pools.append(cands)
        # One headline per angle, in turn, until the category is full or all run dry.
        count = 0
        while count < NEWS_PER_FEED and any(pools):
            for pool in pools:
                while pool:
                    t, src = pool.pop(0)
                    w = _news_words(t)
                    if any(_news_same(w, o) for o in seen):
                        skipped_dup += 1
                        continue
                    seen.append(w)
                    items.append({"tag": name, "cls": tag, "title": t, "src": src})
                    count += 1
                    break
                if count >= NEWS_PER_FEED:
                    break
    print(f"  news: {len(items)} kept, {skipped_dup} duplicates and "
          f"{skipped_thin} thin titles skipped")
    return items


# -------------------------------------------------------------------- html
def zone_colour(score, zones):
    """Colour of the arc segment the score falls in - used for the status word."""
    for to, colour in zones:
        if score <= to:
            return colour
    return zones[-1][1]


def gauge_svg(score, zones):
    """Half-dial. The pointer is a short marker riding just inside the arc, with a
    card-coloured halo, so it never crosses the number in the middle."""
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
            f'<line x1="{cx}" y1="{cy-38}" x2="{cx}" y2="{cy-r+11}" stroke="var(--card)" '
            f'stroke-width="9" stroke-linecap="round"/>'
            f'<line x1="{cx}" y1="{cy-38}" x2="{cx}" y2="{cy-r+11}" stroke="var(--ink)" '
            f'stroke-width="4" stroke-linecap="round"/></g>'
            f'<text x="{cx}" y="{cy-7}" text-anchor="middle" font-size="27" '
            f'font-weight="700" fill="var(--ink)">{score:.0f}</text>'
            f'<text x="{cx}" y="{cy+6}" text-anchor="middle" font-size="9" '
            f'fill="var(--muted)">/ 100</text></svg>')


# Equities zones line up with the status thresholds: VIX above 25 is the red half,
# 16 to 25 amber, below 16 green (the score is 100 minus the volatility score).
EQ_ZONES = [(50, "#d13b3b"), (80, "#f0b429"), (100, "#3fb46e")]
CR_ZONES = [(25, "#d13b3b"), (45, "#f0b429"), (55, "#9aa4b2"), (75, "#8fd19e"), (100, "#3fb46e")]


def bar_svg(series, lo=None, hi=None, unit="%"):
    """Vertical bars with an optional shaded target band. Scales to the card."""
    if not series:
        return '<div class="muted">No data.</div>'
    vals = [v for _, v in series]
    top = max(vals + ([hi] if hi else [])) * 1.18
    W, H, PAD_B, PAD_T = 320, 110, 18, 6
    bw = W / len(series)
    body = ""
    if lo is not None and hi is not None and top:
        y1 = PAD_T + (1 - hi / top) * (H - PAD_B - PAD_T)
        y2 = PAD_T + (1 - lo / top) * (H - PAD_B - PAD_T)
        body += (f'<rect x="0" y="{y1:.1f}" width="{W}" height="{max(0,y2-y1):.1f}" '
                 f'fill="var(--up)" opacity=".12"/>')
    for i, (lbl, v) in enumerate(series):
        h = (v / top) * (H - PAD_B - PAD_T) if top else 0
        x = i * bw + bw * 0.18
        y = H - PAD_B - h
        over = (hi is not None and v > hi)
        col = "var(--down)" if over else "var(--accent)"
        body += (f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw*0.64:.1f}" height="{max(h,1):.1f}" '
                 f'rx="2" fill="{col}"/>'
                 f'<text x="{x + bw*0.32:.1f}" y="{y-2.5:.1f}" text-anchor="middle" '
                 f'font-size="8.5" fill="var(--muted)">{v:g}</text>'
                 f'<text x="{x + bw*0.32:.1f}" y="{H-6:.1f}" text-anchor="middle" '
                 f'font-size="8" fill="var(--muted)">{lbl}</text>')
    return (f'<svg viewBox="0 0 {W} {H}" style="width:100%;height:auto" '
            f'role="img" aria-label="bar chart">{body}</svg>')


def line_svg(series, unit="%"):
    if not series:
        return '<div class="muted">No data.</div>'
    vals = [v for _, v in series]
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    # PAD_X keeps the first and last dot, value and month label inside the viewBox;
    # without it they sat on the edges and were cut in half.
    W, H, PAD_B, PAD_T, PAD_X = 320, 96, 18, 16, 16
    step = (W - 2 * PAD_X) / max(len(series) - 1, 1)
    pts, dots = [], ""
    for i, (lbl, v) in enumerate(series):
        x = PAD_X + i * step
        y = PAD_T + (1 - (v - lo) / span) * (H - PAD_B - PAD_T)
        pts.append(f"{x:.1f},{y:.1f}")
        dots += (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.6" fill="var(--accent)"/>'
                 f'<text x="{x:.1f}" y="{y-6:.1f}" text-anchor="middle" font-size="8.5" '
                 f'fill="var(--muted)">{v:g}</text>'
                 f'<text x="{x:.1f}" y="{H-5:.1f}" text-anchor="middle" font-size="8" '
                 f'fill="var(--muted)">{lbl}</text>')
    return (f'<svg viewBox="0 0 {W} {H}" style="width:100%;height:auto" role="img" '
            f'aria-label="line chart"><polyline points="{" ".join(pts)}" fill="none" '
            f'stroke="var(--accent)" stroke-width="2" stroke-linejoin="round"/>{dots}</svg>')


def mon(lbl):
    try:
        return dt.date.fromisoformat(lbl + "-01").strftime("%b")
    except Exception:
        return lbl


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
var CG_IDS={BTC:'bitcoin',ETH:'ethereum',SOL:'solana',BONK:'bonk',JUP:'jupiter-exchange-solana'};
var CRB=__CR_BUCKETS__;
var CRZ=[[25,'#d13b3b'],[45,'#f0b429'],[55,'#9aa4b2'],[75,'#8fd19e'],[100,'#3fb46e']];
var TOL=0.25;
var LIVEPX={}, LIVECHG={}, ok=0;

/* ---------- formatting ---------- */
function money(v){
  v=(typeof v==='number')?v:parseFloat(v);
  if(v==null||isNaN(v)) return '\\u2014';
  if(v>=1000) return '$'+v.toLocaleString('en-US',{maximumFractionDigits:0});
  if(v>=1) return '$'+v.toFixed(2);
  return '$'+v.toFixed(8).replace(/0+$/,'');
}
function pct(v){
  if(v==null||isNaN(v)) return '<span class="muted">\\u2014</span>';
  return '<span class="'+(v>=0?'up':'down')+'">'+(v>=0?'+':'\\u2212')+Math.abs(v).toFixed(2)+'%</span>';
}
function median(a){a=a.slice().sort(function(x,y){return x-y;});var m=a.length>>1;
  return a.length%2?a[m]:(a[m-1]+a[m])/2;}
function badge(t){var e=document.getElementById('liveBadge'); if(e) e.textContent=t;}

/* ---------- edition stamp + greeting ---------- */
function ago(t){
  var m=Math.max(0,Math.round((Date.now()-t.getTime())/60000));
  if(m<1) return 'just now';
  if(m<60) return m+'m ago';
  var h=Math.floor(m/60);
  return h<24 ? h+'h ago' : Math.floor(h/24)+'d ago';
}
function builtInfo(){
  var e=document.getElementById('builtAgo'); if(!e) return null;
  var t=new Date(e.getAttribute('data-built')); if(isNaN(t.getTime())) return null;
  var ed=e.getAttribute('data-edition')||'';
  return {el:e, t:t, ed:ed.charAt(0).toUpperCase()+ed.slice(1),
          clock:t.toLocaleTimeString([],{hour:'numeric',minute:'2-digit'}),
          hours:(Date.now()-t.getTime())/3600000};
}
/* Builds run 12 hours apart, so anything older than 13 means one was missed. */
function stamp(){
  var b=builtInfo(); if(!b) return;
  b.el.textContent=b.ed+' edition \\u00b7 built '+b.clock+' ('+ago(b.t)+')';
  b.el.className=b.hours>13?'late':'';
  b.el.title=b.hours>13?'Older than one build cycle - a scheduled build may have been missed.':'';
  var g=document.getElementById('greet');
  if(g){ var h=new Date().getHours();
    g.textContent=h<12?'Good morning, Justin \\u2600\\ufe0f':
                  (h<18?'Good afternoon, Justin \\ud83c\\udf24\\ufe0f':'Good evening, Justin \\ud83c\\udf19'); }
}

/* ---------- splash ----------
   Rows are grouped by what they feed (GROUPS), not by provider, because "Crypto
   prices 3 of 3" answers the question you actually have. The per-provider rows
   (STEPS) sit underneath and open on demand, or by themselves when one fails. */
var STEPS=[['cb','Coinbase'],['cg','CoinGecko'],['bn','Binance'],
           ['fx','ECB via Frankfurter'],['fng','alternative.me']];
var GROUPS=[['crypto','Crypto prices',['cb','cg','bn']],
            ['fxg','Peso FX rates',['fx']],
            ['sent','Crypto sentiment',['fng']]];
var MARKS={wait:'\\u00b7',run:'\\u25cc',ok:'\\u2713',warn:'!',fail:'\\u2715'};
var timers={}, splashEl=null, settled=0, troubles=0, stepState={}, runNo=0;

function stepName(id){ for(var i=0;i<STEPS.length;i++) if(STEPS[i][0]===id) return STEPS[i][1]; return id; }

function buildSplash(){
  var h='<div class="sp-card" role="status" aria-live="polite">'+
    '<div class="sp-title">Refreshing live data</div>'+
    '<div class="sp-sub" id="sp-built"></div>'+
    '<div class="sp-bar"><div class="sp-fill" id="sp-fill"></div></div><ul class="sp-list">';
  GROUPS.forEach(function(g){
    h+='<li id="sp-g-'+g[0]+'"><div class="sp-step"><span class="sp-ic">\\u00b7</span>'+
       '<span class="sp-lb">'+g[1]+'</span><span class="sp-st">waiting</span></div><ul class="sp-srcs">';
    g[2].forEach(function(id){
      h+='<li class="sp-src" id="sp-'+id+'"><span class="sp-ic">\\u00b7</span>'+
         '<span class="sp-lb">'+stepName(id)+'</span><span class="sp-st">waiting</span></li>';
    });
    h+='</ul></li>';
  });
  h+='</ul><div class="sp-msg" id="sp-msg"></div>'+
     '<div class="sp-actions"><button type="button" id="sp-more">Show sources</button>'+
     '<button type="button" id="sp-retry">Retry</button></div>'+
     '<div class="sp-foot">Tap outside to dismiss</div></div>';
  var el=document.createElement('div');
  el.id='splash'; el.innerHTML=h;
  el.addEventListener('click',function(e){ if(e.target===el) closeSplash(); });
  document.body.appendChild(el);
  el.querySelector('#sp-more').onclick=function(){ showSources(!el.querySelector('.sp-card').classList.contains('sp-open')); };
  el.querySelector('#sp-retry').onclick=function(){ refresh(); };
  return el;
}
function showSources(on){
  if(!splashEl) return;
  splashEl.querySelector('.sp-card').classList.toggle('sp-open',!!on);
  splashEl.querySelector('#sp-more').textContent=on?'Hide sources':'Show sources';
}
function openSplash(){
  settled=0; troubles=0; stepState={}; runNo++;
  if(!splashEl) splashEl=buildSplash();
  STEPS.forEach(function(s){ setStep(s[0],'wait','waiting'); });
  var f=document.getElementById('sp-fill'); if(f) f.style.width='0%';
  var b=builtInfo(), sub=document.getElementById('sp-built');
  if(sub) sub.innerHTML=(b?b.ed+' edition \\u00b7 built '+b.clock+' \\u00b7 '+ago(b.t)+'<br>':'')+
    'Weather, calendar, news and ETF prices come from that build.';
  var m=document.getElementById('sp-msg'); if(m){ m.style.display='none'; m.innerHTML=''; }
  var r=document.getElementById('sp-retry'); if(r) r.style.display='none';
  showSources(false);
  splashEl.style.display='flex';
  placeSplash();
}
function closeSplash(){ if(splashEl) splashEl.style.display='none';
  Object.keys(timers).forEach(function(k){clearInterval(timers[k]);}); timers={}; }
document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeSplash(); });

function paint(row,state,txt){
  if(!row) return;
  var ic=row.querySelector('.sp-ic'), st=row.querySelector('.sp-st');
  var tone=(state==='ok'?' st-ok':state==='warn'?' st-warn':state==='fail'?' st-fail':'');
  ic.textContent=MARKS[state]||'\\u00b7';
  ic.className='sp-ic'+(state==='run'?' sp-spin':'')+tone;
  st.textContent=txt; st.className='sp-st'+tone;
}
function setStep(id,state,txt){
  stepState[id]=state;
  paint(document.getElementById('sp-'+id),state,txt);
  paintGroups();
}
function paintGroups(){
  GROUPS.forEach(function(g){
    var li=document.getElementById('sp-g-'+g[0]); if(!li) return;
    var n=g[2].length, good=0, done=0, running=0;
    g[2].forEach(function(id){ var s=stepState[id]||'wait';
      if(s==='ok') good++;
      if(s==='ok'||s==='warn'||s==='fail') done++;
      if(s==='run') running++; });
    var state, txt;
    if(done<n){
      state=(running||done)?'run':'wait';
      txt=(state==='wait')?'waiting':(n>1?done+' of '+n+' answered':'loading');
    }else if(good===n){ state='ok';   txt=n>1?n+' of '+n+' sources':'live'; }
    else if(good>0)   { state='warn'; txt=good+' of '+n+' sources'; }
    else              { state='fail'; txt='using build value'; }
    paint(li.querySelector('.sp-step'),state,txt);
  });
}
/* Says what a failure means for the page, not just that it happened. */
function explain(){
  var out=[], cr=['cb','cg','bn'];
  var bad=cr.filter(function(id){ return stepState[id]!=='ok'; });
  if(bad.length===cr.length){
    out.push('<b>Crypto:</b> no source answered, so prices and holdings show the build\\u2019s values.');
  }else if(bad.length){
    out.push('<b>Crypto:</b> '+bad.map(stepName).join(' and ')+' did not answer. The median uses '+
             (cr.length-bad.length)+' of '+cr.length+' sources.');
  }
  if(stepState.fx!=='ok')  out.push('<b>FX:</b> showing the fix from the build.');
  if(stepState.fng!=='ok') out.push('<b>Sentiment:</b> showing the reading from the build.');
  var m=document.getElementById('sp-msg');
  if(m){ m.innerHTML=out.join('<br>'); m.style.display=out.length?'block':'none'; }
  var r=document.getElementById('sp-retry'); if(r) r.style.display='inline-block';
  showSources(true);
}
function bumpBar(){
  settled++;
  var f=document.getElementById('sp-fill');
  if(f) f.style.width=Math.round(settled/STEPS.length*100)+'%';
  if(settled < STEPS.length) return;
  // Clean run: get out of the way. Anything warned or failed: stay put and say
  // what it means, because seeing which source broke is the point of this overlay.
  if(troubles===0){
    var mine=runNo;
    setTimeout(function(){ if(mine===runNo) closeSplash(); },1100);
  }else{
    explain();
  }
}

/* Runs fn, timing it and reporting ok / warn / fail to the splash.
   warn = answered but returned nothing usable; fail = threw or non-OK. */
async function track(id,fn){
  var t0=Date.now();
  setStep(id,'run','0.0s');
  timers[id]=setInterval(function(){
    setStep(id,'run',((Date.now()-t0)/1000).toFixed(1)+'s');
  },100);
  var res=null, state='ok', msg='';
  try{
    res=await fn();
    var n=res?Object.keys(res).length:0;
    if(!n){ state='warn'; msg='no data'; }
    else   { msg=n+' value'+(n===1?'':'s'); }
  }catch(e){ state='fail'; msg='failed'; }
  clearInterval(timers[id]); delete timers[id];
  if(state!=='ok') troubles++;
  setStep(id,state,msg+' \\u00b7 '+((Date.now()-t0)/1000).toFixed(1)+'s');
  bumpBar();
  if(state==='ok') ok++;
  return res||{};
}

/* ---------- sources ---------- */
async function cbAll(){
  var y=new Date(Date.now()-86400000).toISOString().slice(0,10), out={};
  await Promise.all(COINS.map(async function(sym){
    var a=await fetch('https://api.coinbase.com/v2/prices/'+sym+'-USD/spot',{cache:'no-store'});
    if(!a.ok) return;
    var px=parseFloat((await a.json()).data.amount), ch=null;
    try{
      var b=await fetch('https://api.coinbase.com/v2/prices/'+sym+'-USD/spot?date='+y,{cache:'no-store'});
      if(b.ok){ var p=parseFloat((await b.json()).data.amount); if(p) ch=(px-p)/p*100; }
    }catch(e){}
    if(!isNaN(px)) out[sym]=[px,ch];
  }));
  return out;
}
async function cgAll(){
  var out={}, ids=COINS.map(function(c){return CG_IDS[c];}).join(',');
  var r=await fetch('https://api.coingecko.com/api/v3/simple/price?ids='+ids+
                    '&vs_currencies=usd&include_24hr_change=true',{cache:'no-store'});
  if(!r.ok) throw new Error('cg');
  var j=await r.json();
  COINS.forEach(function(sym){
    var d=j[CG_IDS[sym]];
    if(d&&d.usd) out[sym]=[d.usd,(d.usd_24h_change==null?null:d.usd_24h_change)];
  });
  return out;
}
async function bnAll(){
  var out={}, syms=encodeURIComponent(JSON.stringify(COINS.map(function(c){return c+'USDT';})));
  var last=null;
  for (const host of ['https://data-api.binance.vision','https://api.binance.com']) {
    try{
      var r=await fetch(host+'/api/v3/ticker/24hr?symbols='+syms,{cache:'no-store'});
      if(!r.ok){ last=new Error('bn '+r.status); continue; }
      (await r.json()).forEach(function(row){
        var sym=row.symbol.replace(/USDT$/,'');
        if(COINS.indexOf(sym)>=0) out[sym]=[parseFloat(row.lastPrice),parseFloat(row.priceChangePercent)];
      });
      if(Object.keys(out).length) return out;
    }catch(e){ last=e; }
  }
  if(last) throw last;
  return out;
}
async function fxAll(){
  var r=await fetch('https://api.frankfurter.dev/v1/latest?from=PHP&to='+FXC.join(','),
                    {cache:'no-store'});
  if(!r.ok) throw new Error('fx');
  var j=await r.json(), out={};
  FXC.forEach(function(k){
    var v=j.rates&&j.rates[k];
    if(v) out[k]=(1/v)*(k==='JPY'?100:1);
  });
  return out;
}
async function fngAll(){
  var r=await fetch('https://api.alternative.me/fng/',{cache:'no-store'});
  if(!r.ok) throw new Error('fng');
  var d=(await r.json()).data[0], v=parseInt(d.value,10);
  if(isNaN(v)) return {};
  return {value:v,label:d.value_classification};
}

/* ---------- apply ---------- */
function mergeCrypto(feeds){
  COINS.forEach(function(sym){
    var q={};
    Object.keys(feeds).forEach(function(k){ if(feeds[k]&&feeds[k][sym]) q[k]=feeds[k][sym]; });
    var names=Object.keys(q);
    if(!names.length) return;
    var med=median(names.map(function(k){return q[k][0];}));
    var kept=[], dropped=[];
    names.forEach(function(k){
      if(med&&Math.abs(q[k][0]-med)/med>TOL) dropped.push(k); else kept.push(k);
    });
    if(!kept.length){ kept=names; dropped=[]; }
    var px=median(kept.map(function(k){return q[k][0];}));
    var chs=kept.map(function(k){return q[k][1];}).filter(function(v){return v!=null&&!isNaN(v);});
    var ch=chs.length?median(chs):null;
    LIVEPX[sym]=px; LIVECHG[sym]=ch;
    var row=document.querySelector('[data-coin="'+sym+'"]'); if(!row) return;
    var a=row.querySelector('[data-live=price]'), b=row.querySelector('[data-live=chg]'),
        c=row.querySelector('[data-live=src]'), ab=row.querySelector('[data-live=abs]');
    if(a) a.textContent=money(px);
    if(b) b.innerHTML=pct(ch);
    if(ab&&ch!=null){
      var prev=px/(1+ch/100), dl=px-prev, A=Math.abs(dl);
      ab.innerHTML='<span class="'+(dl>=0?'up':'down')+'">'+(dl>=0?'+':'\\u2212')+'$'+
        (A>=0.01?A.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})
                :A.toFixed(8).replace(/0+$/,''))+'</span>';
    }
    if(c) c.textContent=kept.length+'/'+names.length+(dropped.length?' \\u00b7 '+dropped.join('+')+' off':'');
  });
  try{ revaluePortfolio(); }catch(e){}
}
function applyFx(rates){
  Object.keys(rates||{}).forEach(function(k){
    var row=document.querySelector('[data-fx="'+k+'"]'); if(!row) return;
    var v=rates[k], prev=parseFloat(row.getAttribute('data-prev'));
    var a=row.querySelector('[data-fxc=val]'), b=row.querySelector('[data-fxc=abs]'),
        c=row.querySelector('[data-fxc=pct]');
    var f2=function(x){return x.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});};
    if(a) a.textContent=f2(v);
    if(isNaN(prev)||!prev) return;
    // Green when the peso strengthened, i.e. fewer pesos per unit than the previous fix.
    var dl=v-prev, cls=dl<0?'up':'down', pc=dl/prev*100;
    if(b) b.innerHTML='<span class="'+cls+'">'+(dl<0?'\\u2212':'+')+'\\u20b1'+f2(Math.abs(dl))+'</span>';
    if(c) c.innerHTML='<span class="'+cls+'">'+(dl<0?'\\u25bc':'\\u25b2')+' '+Math.abs(pc).toFixed(2)+'%</span>';
  });
}
function zoneColour(score){
  for(var i=0;i<CRZ.length;i++) if(score<=CRZ[i][0]) return CRZ[i][1];
  return CRZ[CRZ.length-1][1];
}
function gaugeSvg(score){
  var cx=90,cy=85,r=70,segs='',frm=0;
  function pt(v){var a=Math.PI*(1-v/100);return [cx+r*Math.cos(a),cy-r*Math.sin(a)];}
  CRZ.forEach(function(z){
    var p1=pt(frm),p2=pt(z[0]);
    segs+='<path d="M'+p1[0].toFixed(1)+','+p1[1].toFixed(1)+' A70,70 0 0 1 '+
      p2[0].toFixed(1)+','+p2[1].toFixed(1)+'" stroke="'+z[1]+'" stroke-width="14" fill="none"/>';
    frm=z[0];
  });
  var ang=-90+score/100*180;
  return '<svg width="180" height="100" viewBox="0 0 180 100">'+segs+
    '<g transform="rotate('+ang.toFixed(1)+' 90 85)">'+
    '<line x1="90" y1="47" x2="90" y2="26" stroke="var(--card)" stroke-width="9" stroke-linecap="round"/>'+
    '<line x1="90" y1="47" x2="90" y2="26" stroke="var(--ink)" stroke-width="4" stroke-linecap="round"/></g>'+
    '<text x="90" y="78" text-anchor="middle" font-size="27" font-weight="700" fill="var(--ink)">'+
    Math.round(score)+'</text>'+
    '<text x="90" y="91" text-anchor="middle" font-size="9" fill="var(--muted)">/ 100</text></svg>';
}
function applyFng(d){
  if(!d||d.value==null) return;
  var g=document.getElementById('gauge-cr');
  if(g) g.innerHTML=gaugeSvg(d.value)+
    '<div class="val">Crypto: <span style="color:'+zoneColour(d.value)+'">'+
    d.label.toUpperCase()+'</span></div>'+
    '<div class="lab">Fear &amp; Greed Index</div>';
  var b=d.value<=25?'ef':d.value<=45?'f':d.value<=55?'n':d.value<=75?'g':'eg';
  var ul=document.getElementById('cr-bullets');
  if(ul&&CRB[b]) ul.innerHTML=CRB[b].map(function(x){return '<li>'+x+'</li>';}).join('');
}

function pfnum(v){
  if(Math.abs(v)>=10000) return v.toLocaleString('en-US',{maximumFractionDigits:0});
  if(Math.abs(v)>=1) return v.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  return v.toFixed(8).replace(/0+$/,'').replace(/\\.$/,'')||'0';
}
function pfsigned(v,dec,unit,cur){
  return '<span class="'+(v>=0?'up':'down')+'">'+(v>=0?'+':'\\u2212')+(cur||'')+
    Math.abs(v).toLocaleString('en-US',{minimumFractionDigits:dec,maximumFractionDigits:dec})+
    (unit||'')+'</span>';
}
/* Reprices the crypto rows from the live medians, then rebuilds the three totals.
   A coin with no live price keeps the build's value and P&L in every total. */
function revaluePortfolio(){
  var rows=document.querySelectorAll('tr[data-holding]');
  if(!rows.length) return;
  var sum=0,pl=0;
  rows.forEach(function(r){
    var sym=r.getAttribute('data-holding');
    var qty=parseFloat(r.getAttribute('data-qty'));
    var basis=parseFloat(r.getAttribute('data-basis'));
    var px=LIVEPX[sym];
    if(px==null||isNaN(qty)){
      var bv=parseFloat(r.getAttribute('data-val')), bp=parseFloat(r.getAttribute('data-pl'));
      if(!isNaN(bv)) sum+=bv;
      if(!isNaN(bp)) pl+=bp;
      return;
    }
    var val=px*qty; sum+=val;
    var a=r.querySelector('[data-pf=price]'), d=r.querySelector('[data-pf=day]'),
        p=r.querySelector('[data-pf=pl]'), u=r.querySelector('[data-pf=upct]');
    if(a) a.textContent=pfnum(px);
    var ch=LIVECHG[sym];
    if(d&&ch!=null&&!isNaN(ch)) d.innerHTML='<span class="'+(ch>=0?'up':'down')+'">'+
      (ch>=0?'\\u25b2':'\\u25bc')+' '+Math.abs(ch).toFixed(2)+'%</span>';
    if(!isNaN(basis)&&basis){
      var g=val-basis; pl+=g;
      if(p) p.innerHTML=pfsigned(g,2);
      if(u) u.innerHTML=pfsigned(g/basis*100,1,'%');
    }
  });
  var m=document.querySelector('[data-pf=mkt]'), t=document.querySelector('[data-pf=total]'),
      u=document.querySelector('[data-pf=upl]');
  var usd=function(v){return '$'+v.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var mkt=sum+(m?parseFloat(m.getAttribute('data-etf'))||0:0);
  if(m) m.textContent=usd(mkt);
  if(t) t.textContent=usd(mkt+(parseFloat(t.getAttribute('data-cash'))||0));
  if(u){
    var tp=pl+(parseFloat(u.getAttribute('data-etfpl'))||0), tb=parseFloat(u.getAttribute('data-basis'))||0;
    u.innerHTML='<span class="'+(tp>=0?'up':'down')+'">'+(tp>=0?'+':'\\u2212')+usd(Math.abs(tp))+
      (tb?' ('+(tp>=0?'+':'\\u2212')+Math.abs(tp/tb*100).toFixed(2)+'%)':'')+'</span>';
  }
}

/* ---------- orchestration ---------- */
var busy=false, last=0;
async function refresh(){
  if(busy) return;
  busy=true; ok=0;
  stamp();
  openSplash();
  // Ask the shell to re-check the gist too, so a new edition is picked up
  // rather than only the live prices being refreshed.
  try{ parent.postMessage({dailyBriefCheck:1},'*'); }catch(e){}
  badge('refreshing\\u2026');
  try{
    var res=await Promise.all([track('cb',cbAll),track('cg',cgAll),track('bn',bnAll),
                               track('fx',fxAll),track('fng',fngAll)]);
    mergeCrypto({CB:res[0],CG:res[1],BN:res[2]});
    applyFx(res[3]);
    applyFng(res[4]);
  }catch(e){}
  var t=new Date().toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
  badge(ok===0?'offline \\u2014 last build':(ok===5?'live \\u00b7 '+t:'partly live \\u00b7 '+t));
  last=Date.now(); busy=false; stamp();
}
/* ---------- embedding ----------
   The shell makes the frame as tall as the page and scrolls its own document, so
   there is exactly one scroller and the phone's native momentum applies. The page
   reports its height; the shell reports which slice of the page is on screen (VT,
   VH), which is needed to centre the overlay and to know when we are at the top. */
var EMB=false, VT=0, VH=0;
function sayHeight(){ try{ parent.postMessage({dailyBriefHeight:document.body.offsetHeight},'*'); }catch(e){} }
function placeSplash(){
  if(!EMB||!splashEl) return;
  splashEl.style.position='absolute'; splashEl.style.bottom='auto';
  splashEl.style.top=Math.max(0,VT)+'px'; splashEl.style.height=VH+'px';
}
if(window.parent!==window){
  sayHeight();
  window.addEventListener('load',sayHeight);
  if(window.ResizeObserver) new ResizeObserver(sayHeight).observe(document.body);
  window.addEventListener('message',function(e){
    if(e.source!==window.parent) return;
    var v=e.data&&e.data.dailyBriefViewport; if(!v) return;
    if(!EMB){ EMB=true; document.documentElement.classList.add('embedded'); }
    VT=v.top; VH=v.height;
    if(splashEl&&splashEl.style.display==='flex') placeSplash();
  });
}

/* ---------- pull down to refresh ----------
   Refreshes the live figures and asks the shell to look for a new edition. It does
   not reload the page, so a device that is not remembered stays unlocked. All the
   listeners are passive: they never hold up a scroll. */
var pull=null, ptrEl=null;
function atTop(){ return EMB ? VT<=0 : (window.pageYOffset||document.documentElement.scrollTop||0)<=0; }
function ptr(txt,dy){
  if(!ptrEl){ ptrEl=document.createElement('div'); ptrEl.id='ptr'; document.body.appendChild(ptrEl); }
  if(txt==null){ ptrEl.style.display='none'; return; }
  ptrEl.textContent=txt; ptrEl.style.display='block';
  ptrEl.style.top=(8+Math.min(dy,140)*0.35)+'px';
}
document.addEventListener('touchstart',function(e){
  var open=splashEl&&splashEl.style.display==='flex';
  pull=(e.touches.length===1&&atTop()&&!open&&!busy)?
       {x:e.touches[0].clientX,y:e.touches[0].clientY,d:0}:null;
},{passive:true});
document.addEventListener('touchmove',function(e){
  if(!pull) return;
  var dy=e.touches[0].clientY-pull.y, dx=Math.abs(e.touches[0].clientX-pull.x);
  if(dy<-6||dx>Math.max(12,dy)||!atTop()){ pull=null; ptr(null); return; }
  pull.d=dy;
  if(dy>24) ptr(dy>90?'Release to refresh':'Pull to refresh',dy);
},{passive:true});
function endPull(){ if(!pull) return; var go=pull.d>90; pull=null; ptr(null); if(go) refresh(); }
document.addEventListener('touchend',endPull,{passive:true});
document.addEventListener('touchcancel',function(){ pull=null; if(ptrEl) ptr(null); },{passive:true});

/* ---------- folds remember whether you left them open ---------- */
Array.prototype.forEach.call(document.querySelectorAll('details[data-k]'),function(el){
  var key='briefing-fold-'+el.getAttribute('data-k');
  try{ var v=localStorage.getItem(key); if(v==='1') el.open=true; else if(v==='0') el.open=false; }catch(e){}
  el.addEventListener('toggle',function(){
    try{ localStorage.setItem(key,el.open?'1':'0'); }catch(e){}
  });
});

window.dbRefresh=refresh;
refresh();
document.addEventListener('visibilitychange',function(){
  if(document.visibilityState==='visible'&&Date.now()-last>120000) refresh();
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

    def day_cell(dd):
        rain = f'{dd["pop"]}%' if dd["pop"] is not None else ""
        mm = (f'<span class="mm"> · {dd["mm"]:.1f}mm</span>'
              if dd.get("mm") else "")
        return (f'<div class="d"><div class="dn">{esc(dd.get("label") or dd["name"])}</div>'
                f'<div class="dt"><span class="de">{dd["emoji"]}</span>'
                f'{dd["lo"]}–{dd["hi"]}°</div>'
                f'<div class="dr">{esc(rain)}{mm}</div></div>')

    wx = ""
    if w:
        # Evening edition: today's morning and afternoon are already spent, so the
        # three slots show tomorrow instead, under a one-line summary of the day.
        tm = (w.get("tomorrow") or {}) if EDITION == "evening" else {}
        sl = tm if any(tm.values()) else w
        tm_line = ""
        if sl is tm:
            d1 = (w.get("days") or [None])[0]
            tm_line = '<div class="fcl">Tomorrow' + (
                f' \u00b7 {esc(d1["desc"])}, {d1["lo"]}\u2013{d1["hi"]}\u00b0'
                + (f', {d1["pop"]}% rain' if d1.get("pop") is not None else "")
                if d1 else "") + "</div>"
        wx = (f'<div><span class="big">{w["temp"]}°C</span> &nbsp;{esc(w["desc"])}'
              f' · Humidity {w["humidity"]}%</div>{tm_line}'
              f'<div class="wx">{wx_slot("Morning", sl["morning"])}'
              f'{wx_slot("Afternoon", sl["afternoon"])}{wx_slot("Evening", sl["evening"])}</div>')
    wx_more = ""
    if w and w.get("days"):
        wx_more = ('<div class="fc5">' + "".join(day_cell(x) for x in w["days"])
                   + "</div>")
    else:
        wx = '<div class="muted">Weather unavailable.</div>'

    fxd = d["fx"] or {}

    def fx_move(e):
        if not e or e.get("chg") is None:
            return '<span class="muted">—</span>'
        ch = e["chg"]
        cls, arrow = ("up", "\u25bc") if ch < 0 else ("down", "\u25b2")
        return f'<span class="{cls}">{arrow} {abs(ch):.2f}%</span>'

    def fx_abs(e):
        """Move in pesos against the previous fix. Green = peso stronger."""
        if not e or not e.get("prev"):
            return '<span class="muted">—</span>'
        dlt = e["php"] - e["prev"]
        cls = "up" if dlt < 0 else "down"
        sign = "\u2212" if dlt < 0 else "+"
        return f'<span class="{cls}">{sign}\u20b1{abs(dlt):,.2f}</span>'

    def fx_row(k, lbl):
        e = fxd.get(k)
        if not e:
            return ""
        prev = e.get("prev") or ""
        return (f'<tr data-fx="{k}" data-prev="{prev}"><td><b>{lbl}</b> / PHP</td>'
                f'<td class="num" data-fxc="val">{e["php"]:,.2f}</td>'
                f'<td class="num" data-fxc="abs">{fx_abs(e)}</td>'
                f'<td class="num" data-fxc="pct">{fx_move(e)}</td></tr>')

    FX_COLS = ('<colgroup><col style="width:34%"><col style="width:22%">'
               '<col style="width:22%"><col style="width:22%"></colgroup>')
    # The lead pair is a headline figure, not a table row: it is the at-a-glance read.
    _u = fxd.get("USD")
    fx_main = (f'<div class="lead" data-fx="USD" data-prev="{_u.get("prev") or ""}">'
               f'<div><div class="lk"><b>USD</b> / PHP</div>'
               f'<div class="lv" data-fxc="val">{_u["php"]:,.2f}</div></div>'
               f'<div class="lm"><div data-fxc="pct">{fx_move(_u)}</div>'
               f'<div data-fxc="abs">{fx_abs(_u)}</div>'
               f'<div class="ls">vs previous fix</div></div></div>'
               if _u else '<div class="muted">USD rate unavailable.</div>')
    FX_HEAD = ('<tr><th>Pair</th><th class="num">PHP</th>'
               '<th class="num">24h \u20b1</th><th class="num">24h %</th></tr>')
    _fx_others = "".join(fx_row(k, lbl) for k, lbl in
                         [("EUR", "EUR"), ("GBP", "GBP"), ("JPY", "JPY (100)"), ("SGD", "SGD"),
                          ("AUD", "AUD"), ("CNY", "CNY"), ("HKD", "HKD")])
    fx_rest = (f'<table class="rest">{FX_COLS}{FX_HEAD}{_fx_others}</table>'
               if _fx_others else "")
    fx_asof = fxd.get("_asof", "")

    def abs_cell(c):
        """24h move in dollars, from the median price and median percent."""
        if not c or c.get("price") is None or c.get("chg") is None:
            return '<span class="muted">—</span>'
        prev = c["price"] / (1 + c["chg"] / 100) if (1 + c["chg"] / 100) else None
        if not prev:
            return '<span class="muted">—</span>'
        delta = c["price"] - prev
        cls = "up" if delta >= 0 else "down"
        sign = "+" if delta >= 0 else "\u2212"
        a = abs(delta)
        txt = f"{a:,.2f}" if a >= 0.01 else f"{a:.8f}".rstrip("0")
        return f'<span class="{cls}">{sign}${txt}</span>'

    def src_cell(c):
        if not c or not c.get("total"):
            return "—"
        return (f'{c["srcs"]}/{c["total"]}'
                + (f' · {"+".join(c["dropped"])} off' if c.get("dropped") else ""))

    have = {c["sym"]: c for c in (d["crypto"] or [])}
    def cr_row(sym, name):
        return (
            f'<tr data-coin="{sym}"><td><b>{sym}</b> {esc(name)}</td>'
            f'<td class="num" data-live="price">{money(have[sym]["price"]) if sym in have else "—"}</td>'
            f'<td class="num" data-live="abs">{abs_cell(have.get(sym))}</td>'
            f'<td class="num" data-live="chg">{pct_html(have[sym]["chg"]) if sym in have else "—"}</td>'
            f'<td class="num" data-live="src" style="color:var(--muted);font-size:11.5px">'
            f'{src_cell(have.get(sym))}</td></tr>')

    # Same shape as the FX card: one lead row always visible, the rest folded.
    # Both tables share a colgroup so the folded rows line up under the header.
    CR_COLS = ('<colgroup><col style="width:24%"><col style="width:21%">'
               '<col style="width:27%"><col style="width:18%"><col style="width:10%"></colgroup>')
    _b, _bn = COINS[0]
    _bh = have.get(_b)
    cr_main = (f'<div class="lead" data-coin="{_b}">'
               f'<div><div class="lk"><b>{_b}</b> {esc(_bn)}</div>'
               f'<div class="lv" data-live="price">{money(_bh["price"]) if _bh else "—"}</div></div>'
               f'<div class="lm"><div data-live="chg">{pct_html(_bh["chg"]) if _bh else "—"}</div>'
               f'<div data-live="abs">{abs_cell(_bh)}</div>'
               f'<div class="ls">sources <span data-live="src">{src_cell(_bh)}</span></div></div></div>')
    cr_rest = (f'<table class="rest">{CR_COLS}<tr><th>Coin</th><th class="num">USD (median)</th>'
               f'<th class="num">24h $</th><th class="num">24h %</th><th class="num">Src</th></tr>'
               + "".join(cr_row(sym, name) for sym, name in COINS[1:]) + '</table>')

    idx = d["indices"] or {}

    _ps = ((d.get("ph") or {}).get("psei") or {})
    _ps_asof = ""
    try:
        _ps_asof = " \u00b7 " + dt.date.fromisoformat(_ps["asof"]).strftime("%-d %b")
    except Exception:
        pass
    psei_chip = (f'<div class="chip"><div class="n">PSEi{_ps_asof}</div>'
                 f'<div class="v">{_ps["close"]:,.2f}</div>'
                 f'<div class="c">{pct_html(_ps.get("pct"))}</div></div>'
                 if _ps.get("close") else
                 '<div class="chip"><div class="n">PSEi</div><div class="v">\u2014</div></div>')

    def chip(name, key, fmt="{:,.2f}"):
        v = idx.get(key)
        if not v:
            return f'<div class="chip"><div class="n">{name}</div><div class="v">—</div></div>'
        return (f'<div class="chip"><div class="n">{name}</div>'
                f'<div class="v">{fmt.format(v["close"])}</div>'
                f'<div class="c">{pct_html(v["pct"])}</div></div>')

    import urllib.parse as _up
    news_items = "".join(
        f'<div class="newsitem"><span class="tag t-{n["cls"]}">{esc(n["tag"])}</span>'
        f'<a href="https://www.google.com/search?q={_up.quote_plus(n["title"])}" '
        f'target="_blank" rel="noopener noreferrer">{esc(n["title"])}'
        f'<span class="ext">\u2197</span></a>'
        f'{(" <span class=nsrc>" + esc(n["src"]) + "</span>") if n.get("src") else ""}</div>'
        for n in (d["news"] or [])
    ) or '<div class="muted">No headlines retrieved.</div>'

    edition_label = f"Schedule \u00b7 today + {CAL_DAYS_AHEAD} days"

    # calendar
    evs = d.get("calendar")
    if evs is None:
        cal_html = ('<div class="muted">Calendar not configured — add the GOOGLE_SA_JSON and '
                    'CALENDAR_ID secrets, and share the calendar with the service account.</div>')
    elif not evs:
        cal_html = (f'<div class="muted">Nothing on the calendar through '
                    f'{(NOW + dt.timedelta(days=CAL_DAYS_AHEAD)).strftime("%A")}.</div>')
    else:
        # Group by day. Anything that began before today (a multi-day stay) is
        # listed under Today as ongoing rather than under a date already past.
        _today = NOW.date()
        evs = sorted(evs, key=lambda e: (max(e["when"].date(), _today),
                                         not (e["allday"] or e["when"].date() < _today),
                                         e["when"], e["title"]))
        today_rows, later, later_n, last_day = [], [], 0, None
        for e in evs:
            day = max(e["when"].date(), _today)
            t = ("ongoing" if e["when"].date() < _today else
                 "all day" if e["allday"] else e["when"].strftime("%-I:%M %p"))
            where = f'<div class="muted">{esc(e["where"][:60])}</div>' if e["where"] else ""
            row = (f'<tr><td class="num" style="white-space:nowrap;vertical-align:top">{t}</td>'
                   f'<td>{esc(e["title"])}{where}</td></tr>')
            if day == _today:
                today_rows.append(row)
                continue
            if day != last_day:
                lbl = ("Tomorrow · " + day.strftime("%a %-d %b")
                       if day == _today + dt.timedelta(days=1) else day.strftime("%a %-d %b"))
                later.append(f'<tr><th colspan="2">{lbl}</th></tr>')
                last_day = day
            later.append(row)
            later_n += 1
        # Today is always on show; the days after it sit behind a fold.
        cal_html = ('<table class="cal"><tr><th colspan="2">Today</th></tr>'
                    + ("".join(today_rows) or
                       '<tr><td colspan="2" class="muted">Nothing on today.</td></tr>')
                    + "</table>")
        if later:
            cal_html += (f'<details class="coll" data-k="cal"><summary>Next {CAL_DAYS_AHEAD} '
                         f'days · {later_n} event{"" if later_n == 1 else "s"}</summary>'
                         f'<table class="cal">{"".join(later)}</table></details>')
        else:
            cal_html += (f'<div class="cap">Nothing in the {CAL_DAYS_AHEAD} days after '
                         f'today.</div>')

    # portfolio
    pf = d.get("portfolio")
    if pf is None:
        pf_html = ('<div class="muted">No holdings to show. '
                   + esc(PF_WHY["msg"] or "The sheet was read but no row had both a ticker "
                         "and a quantity under a recognised header.") + '</div>')
    else:
        def pnum(v):
            """Plain price, no currency sign: 159.64, or 0.00002 for a micro-cap coin."""
            if v is None:
                return "\u2014"
            if abs(v) >= 10000:          # keeps a five-figure coin price inside a phone
                return f"{v:,.0f}"
            return f"{v:,.2f}" if abs(v) >= 1 else (f"{v:.8f}".rstrip("0").rstrip(".") or "0")

        def day_cell(v):
            if v is None:
                return '<span class="muted">\u2014</span>'
            if abs(v) < 0.005:
                return '<span class="muted">0.00%</span>'
            return (f'<span class="{"up" if v > 0 else "down"}">'
                    f'{"\u25b2" if v > 0 else "\u25bc"} {abs(v):.2f}%</span>')

        def signed(v, pat="{:,.2f}", unit=""):
            if v is None:
                return '<span class="muted">\u2014</span>'
            return (f'<span class="{"up" if v >= 0 else "down"}">'
                    f'{"+" if v >= 0 else "\u2212"}{pat.format(abs(v))}{unit}</span>')

        cash = PF_META.get("cash")
        has_crypto = any(h["kind"] == "crypto" for h in pf)
        body = []
        mkt = etf_v = tot_pl = etf_pl = tot_basis = 0.0
        any_pl = False
        for h in pf:
            crypto = h["kind"] == "crypto"
            if h["value"]:
                mkt += h["value"]
                etf_v += 0 if crypto else h["value"]
            if h["pl"] is not None:
                tot_pl += h["pl"]
                etf_pl += 0 if crypto else h["pl"]
                any_pl = True
                tot_basis += h["basis"] or 0
            qty_s = f'{h["qty"]:,.6f}'.rstrip("0").rstrip(".")
            live = ""
            if crypto:
                # The build's own figures ride along as the fallback for any coin the
                # live layer cannot price, so a total never silently drops a holding.
                live = (f' data-holding="{h["sym"]}" data-qty="{h["qty"]}"'
                        f' data-basis="{h["basis"] if h["basis"] else ""}"'
                        f' data-val="{h["value"] if h["value"] else ""}"'
                        f' data-pl="{h["pl"] if h["pl"] is not None else ""}"')
            body.append(
                f'<tr{live}><td><b>{esc(h["sym"])}</b></td>'
                f'<td class="num">{qty_s}</td>'
                f'<td class="num" data-pf="price">{pnum(h["price"])}</td>'
                f'<td class="num" data-pf="day">{day_cell(h["day"])}</td>'
                f'<td class="num" data-pf="pl">{signed(h["pl"])}</td>'
                f'<td class="num" data-pf="upct">{signed(h["upct"], "{:.1f}", "%")}</td></tr>')

        total = mkt + (cash or 0)
        pl_txt = ""
        if any_pl:
            pct_txt = (f' ({"+" if tot_pl >= 0 else "\u2212"}{abs(tot_pl / tot_basis * 100):.2f}%)'
                       if tot_basis else "")
            pl_txt = (f'<span class="{"up" if tot_pl >= 0 else "down"}">'
                      f'{"+" if tot_pl >= 0 else "\u2212"}${abs(tot_pl):,.2f}{pct_txt}</span>')
        summ = (f'<div class="pfrow"><span>{"Holdings" if has_crypto else "Stocks"} at market</span>'
                f'<b data-pf="mkt" data-etf="{etf_v:.10f}">${mkt:,.2f}</b></div>')
        if cash:
            summ += f'<div class="pfrow"><span>Cash on hand</span><b>${cash:,.2f}</b></div>'
        summ += (f'<div class="pfrow pftot"><span><b>Total portfolio</b></span>'
                 f'<b data-pf="total" data-cash="{cash or 0:.10f}">${total:,.2f}</b></div>')
        if any_pl:
            summ += (f'<div class="pfrow"><span>Unrealized P&amp;L</span>'
                     f'<b data-pf="upl" data-etfpl="{etf_pl:.10f}" '
                     f'data-basis="{tot_basis:.10f}">{pl_txt}</b></div>')

        head, bullets = pf_commentary(pf, cash)
        # Totals and the one-line read are always on show; the full table and the
        # detail bullets sit behind a fold.
        pf_html = (f'<div class="pfsum top">{summ}</div>'
                   f'<div class="pfnote"><b>{head}</b></div>'
                   f'<details class="coll" data-k="pf"><summary>All holdings · {len(pf)}'
                   '</summary>'
                   '<table class="pft"><tr><th>Ticker</th><th class="num">Qty</th>'
                   '<th class="num">Price</th><th class="num">Day</th>'
                   '<th class="num">Unreal. $</th><th class="num">%</th></tr>'
                   + "".join(body) + "</table>"
                   + ('<div class="pfnote"><ul>' + "".join(f"<li>{x}</li>" for x in bullets)
                      + "</ul></div>" if bullets else "")
                   + "</details>"
                   + ('<div class="cap">Crypto rows and the totals reprice live on every '
                      'open; everything else is from the build.</div>' if has_crypto else ""))

    # "What changed" - diffed against the previous edition's state.json.
    prev = d.get("prev_state") or {}
    idx = d.get("indices") or {}
    phd = d.get("ph") or {}
    chg = []

    def moved(key, now, name="", pct=None):
        was = prev.get(key)
        if now is None:
            return
        if was is None:
            chg.append(f'{name} {now:,.2f}' + (f' ({pct:+.2f}%)' if pct is not None else "") + ".")
        elif abs(now - was) >= 0.005:      # ignore moves that round to +0.00
            dd = now - was
            sign = "+" if dd >= 0 else "\u2212"
            chg.append(f'{name} {now:,.2f} from {was:,.2f} ({sign}{abs(dd):,.2f}).')

    moved("spx", (idx.get("spx") or {}).get("close"), "S&P 500", (idx.get("spx") or {}).get("pct"))
    moved("ndq", (idx.get("ndq") or {}).get("close"), "Nasdaq", (idx.get("ndq") or {}).get("pct"))
    ps = phd.get("psei") or {}
    moved("psei", ps.get("close"), "PSEi", ps.get("pct"))
    moved("vix", (idx.get("vix") or {}).get("close"), "VIX")
    moved("usdphp", ((d.get("fx") or {}).get("USD") or {}).get("php"), "USD/PHP")

    # ref_changed opens the collapsed rates-and-indicators section and badges it,
    # so a monthly print is not missed just because the section is folded away.
    ref_changed = False
    for k, v in {k: v[0] for k, v in RATES.items()}.items():
        was = (prev.get("rates") or {}).get(k)
        if was not in (None, v):
            chg.append(f'{k.upper()} policy rate now {v}, was {was}.')
            ref_changed = True
    if prev.get("ph_cpi") not in (None, PRINTS["ph_cpi"][1]):
        chg.append(f'PH inflation print updated to {PRINTS["ph_cpi"][1]}.')
        ref_changed = True
    for _key, _name in (("inflation", "ph_inf_last"), ("unemployment", "ph_un_last")):
        _now = ((phd.get(_key) or {}).get("series") or [None])[-1]
        _was = prev.get(_name)
        if _now and _was and list(_now) != list(_was):
            chg.append(f'PH {_key} series updated: {mon(_now[0])} {_now[1]}%.')
            ref_changed = True

    vx = (idx.get("vix") or {}).get("close")
    pcts = [v.get("pct") for v in (idx.get("spx"), idx.get("ndq"), ps) if v and v.get("pct")]
    tone = ("risk-on" if pcts and sum(pcts) / len(pcts) > 0.25 else
            "risk-off" if pcts and sum(pcts) / len(pcts) < -0.25 else "mixed")
    vol = "calm" if (vx or 0) < 16 else ("unsettled" if (vx or 0) < 25 else "stressed")
    fgv = (d.get("fg") or {}).get("value")
    ct = ""
    if fgv is not None:
        word = "greedy" if fgv > 55 else ("fearful" if fgv < 45 else "neutral")
        ct = f', crypto sentiment {word} at {fgv}'
    sentiment = f'<b>Overall:</b> equities {tone}, volatility {vol}{ct}.'

    if not chg:
        chg = ["Nothing material moved since the previous edition."]
    tldr = ('<ul class="chg">' + "".join(f"<li>{x}</li>" for x in chg)
            + f'</ul><div class="chgsum">{sentiment}</div>')

    # Weather alerts + the 5-day strip live together behind one collapsible.
    al = d.get("alerts") or []
    _alerts = ('<div class="note"><b>Outlook</b><ul>'
               + "".join(f"<li>{esc(x)}</li>" for x in al) + "</ul></div>") if al else ""
    wx_note = ('<details class="coll" data-k="wx"><summary>Next 5 days &amp; outlook</summary>'
               + wx_more + _alerts + "</details>") if (wx_more or _alerts) else ""

    def due_cap(block):
        return (f' <b>The {block["due"]} figure should be out by now \u2014 add it to '
                f'ph_data.json.</b>' if block.get("due") else "")

    # PH indicators
    ph = d.get("ph")
    if not ph:
        ph_html = '<div class="muted">ph_data.json not found.</div>'
    else:
        ph_html = ""
        inf = ph.get("inflation") or {}
        if inf.get("series"):
            ph_html += ('<div class="chartblk"><h4>' + esc(inf.get("label", "Inflation"))
                        + "</h4>"
                        + bar_svg([(mon(k), v) for k, v in inf["series"]],
                                  lo=inf.get("target_low"), hi=inf.get("target_high"))
                        + '<div class="cap">Shaded band is the BSP 2\u20134% target. '
                          'Red bars are prints above it.' + due_cap(inf) + '</div></div>')
        un = ph.get("unemployment") or {}
        if un.get("series"):
            ph_html += ('<div class="chartblk"><h4>' + esc(un.get("label", "Unemployment"))
                        + "</h4>" + line_svg([(mon(k), v) for k, v in un["series"]])
                        + '<div class="cap">PSA Labour Force Survey.' + due_cap(un)
                        + '</div></div>')
        ba = ph.get("barista") or {}
        if ba.get("minutes"):
            mins = ba["minutes"]
            hh, mm = int(mins // 60), int(round(mins % 60))
            # Red when the index rose at its last change (coffee got dearer in
            # working time), blue when it fell, plain when there is no history yet.
            _was = barista_memory(ph, d.get("prev_state") or {})["barista_was"]
            _bcol = ("" if not _was or round(mins, 1) == _was else
                     ' style="color:var(--down)"' if mins > _was else
                     ' style="color:var(--accent)"')
            _bwas = (f' \u00b7 {"up" if mins > _was else "down"} from {_was:,.0f} min'
                     if _bcol else "")
            ph_html += ('<div class="chartblk"><h4>\u2615 Barista Index</h4>'
                        f'<div class="fxbig"><div><div class="v"{_bcol}>{mins:,.0f}'
                        '<span style="font-size:15px;font-weight:600"> min</span></div>'
                        f'<div class="muted">{hh}h {mm:02d}m of work{_bwas}</div></div></div>'
                        '<div class="cap">Minutes a barista on the NCR minimum wage must work '
                        'to afford the cappuccino they just made \u2014 '
                        f'\u20b1{ba["cappuccino_php"]:,.0f} against \u20b1{ba["hourly"]:,.2f} '
                        f'an hour.<br>{esc(ba.get("wage_note", ""))}; '
                        f'{esc(ba.get("price_note", ""))}.</div></div>')
        if not ph_html:
            ph_html = '<div class="muted">No Philippine series populated yet.</div>'

    cl = []
    rows_ok = [c for c in (d["crypto"] or []) if c.get("price") is not None
               and c.get("chg") is not None]
    if rows_ok:
        best = max(rows_ok, key=lambda c: c["chg"])
        worst = min(rows_ok, key=lambda c: c["chg"])
        ups = [c for c in rows_ok if c["chg"] > 0]
        btc = next((c for c in rows_ok if c["sym"] == "BTC"), None)
        if btc:
            cl.append(f'<b>BTC {money(btc["price"])}</b>, '
                      f'{"up" if btc["chg"] >= 0 else "down"} {abs(btc["chg"]):.2f}% on the day.')
        cl.append(f'Breadth {len(ups)} of {len(rows_ok)} higher · best {best["sym"]} '
                  f'{best["chg"]:+.2f}%, worst {worst["sym"]} {worst["chg"]:+.2f}%.')
        drop = [c["sym"] for c in (d["crypto"] or []) if c.get("dropped")]
        if drop:
            cl.append(f'{", ".join(drop)} priced on two sources — the third diverged by '
                      f'more than 25% and was discarded.')
    if d.get("cr") and "UNKNOWN" not in d["cr"]["label"]:
        cl.append(f'Fear &amp; Greed {d["cr"]["status"]} ({d["cr"]["score"]:.0f}).')
    cr_note = ('<div class="note"><b>What moved</b><ul>'
               + "".join(f"<li>{x}</li>" for x in cl) + "</ul></div>") if cl else ""

    eq_bul = "".join(f"<li>{b}</li>" for b in g_eq["bullets"])
    cr_bul = "".join(f"<li>{b}</li>" for b in g_cr["bullets"])


    # ------------------------------------------------------------------ blocks
    # Each block is one row of the page. LAYOUT (top of file) decides their order
    # for the edition being built.
    evening = EDITION == "evening"
    greet = ("Good evening, Justin \U0001F319" if evening
             else "Good morning, Justin \u2600\ufe0f")
    built_txt = f"{EDITION.capitalize()} edition \u00b7 built {NOW.strftime('%-I:%M %p')}"

    _prov = {"stooq": "Stooq", "yahoo": "Yahoo", "fred-api": "FRED", "fred-csv": "FRED"}
    _src = sorted({_prov[o] for o in IDX_ORIGIN.values() if o in _prov})
    _stale = [n for k, n in (("spx", "S&amp;P 500"), ("ndq", "Nasdaq"), ("vix", "VIX"))
              if IDX_ORIGIN.get(k) == "cache"]
    idx_note = ("US indices are the last published close"
                + (f" ({', '.join(_src)})" if _src else "") + ".")
    if _stale:
        idx_note += (f" {', '.join(_stale)} carried over from the previous build \u2014 "
                     "no provider answered this time.")
    if _ps.get("close"):
        idx_note += " PSEi is updated by hand in ph_data.json."

    card_wx = (f'<div class="card"><h2>{w["emoji"] if w else ""} Weather \u2014 {CITY["name"]}</h2>'
               f'{wx}{wx_note}</div>')
    card_cal = f'<div class="card"><h2>\U0001F4C5 {edition_label}</h2>{cal_html}</div>'

    B = {}
    B["changed"] = (f'<div class="card solo changed"><h2>\U0001F501 What changed '
                    f'{"since this morning" if evening else "overnight"}</h2>{tldr}</div>')

    # Evening leads with the schedule: tomorrow's plans matter more than tonight's weather.
    B["day"] = ('<div class="grid g2">'
                + (card_cal + card_wx if evening else card_wx + card_cal) + '</div>')

    B["portfolio"] = f'<div class="card solo"><h2>\U0001F4C8 Portfolio</h2>{pf_html}</div>'

    B["markets"] = f"""<div class="grid g2">
 <div class="card"><h2>\U0001F310 Global Snapshot</h2>
  <div class="idx">{chip('S&P 500','spx')}{chip('Nasdaq','ndq')}{chip('VIX','vix')}{psei_chip}</div>
  <div class="cap">{idx_note}</div>
 </div>
 <div class="card"><h2>\U0001F3AF Risk Gauges</h2>
  <div class="gwrap">
   <div class="gauge">{gauge_svg(g_eq['score'], EQ_ZONES)}
    <div class="val">{g_eq['label'].rsplit(": ", 1)[0]}: <span style="color:{zone_colour(g_eq['score'], EQ_ZONES)}">{g_eq['status']}</span></div><div class="lab">{g_eq['sub']}</div></div>
   <div class="gauge" id="gauge-cr">{gauge_svg(g_cr['score'], CR_ZONES)}
    <div class="val">{g_cr['label'].rsplit(": ", 1)[0]}: <span style="color:{zone_colour(g_cr['score'], CR_ZONES)}">{g_cr['status']}</span></div><div class="lab">{g_cr['sub']}</div></div>
  </div>
  <details class="coll" data-k="risk"><summary>What the gauges imply</summary>
  <div class="impl">
   <div><h3>Equities \u2014 implications</h3><ul>{eq_bul}</ul></div>
   <div><h3>Crypto \u2014 implications</h3><ul id="cr-bullets">{cr_bul}</ul></div>
  </div>
  <div class="cap">General directional reads from the gauges \u2014 not financial advice.</div>
  </details>
 </div>
</div>
"""

    B["crypto_fx"] = f"""<div class="grid g2">
 <div class="card"><h2>\U0001FA99 Crypto</h2>
  {cr_main}
  <details class="coll" data-k="coins"><summary>Other coins</summary>{cr_rest}</details>
  {cr_note}
  <div class="cap">Live on every open. Median of Coinbase, CoinGecko
  and Binance; a source more than 25% from the median is dropped and named under Src.</div></div>
 <div class="card"><h2>\U0001F4B1 FX \u2014 Philippine Peso</h2>
  {fx_main}
  <details class="coll" data-k="fx"><summary>Other currencies</summary>{fx_rest}</details>
  <div class="cap">ECB reference fix {fx_asof}; moves are against
  the previous fix. Green means the peso strengthened.</div></div>
</div>
"""

    B["news"] = f"""<div class="card solo"><h2>\U0001F4F0 News You Follow</h2>
 <div class="newsgrid">{news_items}</div>
 <div class="cap">Headlines open a Google search in a new tab.
 Refreshed at each build.</div></div>
"""

    PH, US, JP, EU = ("\U0001F1F5\U0001F1ED", "\U0001F1FA\U0001F1F8",
                      "\U0001F1EF\U0001F1F5", "\U0001F1EA\U0001F1FA")

    def move_html(key):
        """Coloured last move for a rate or print, e.g. a red "▲ 25 bps"."""
        mv = MOVES.get(key)
        if not mv:
            return ""
        amt, unit = mv
        if not amt:
            return '<span class="muted">unchanged</span>'
        good = (amt > 0) == (key in RISE_IS_GOOD)
        return (f'<span class="{"up" if good else "down"}">'
                f'{"▲" if amt > 0 else "▼"} {abs(amt):g}'
                f'{"" if unit == "k" else " "}{unit}</span>')

    def ref_chip(name, value, key):
        """Same component as the Global Snapshot chips: name, figure, coloured move."""
        return (f'<div class="chip"><div class="n">{esc(name)}</div>'
                f'<div class="v">{esc(value)}</div>'
                f'<div class="c">{move_html(key) or "&nbsp;"}</div></div>')

    def ref_row(flag, key, label, value, note):
        """Name in semibold, figure large and bold, then the coloured move and the
        commentary small on their own line. The flag already says the country, so a
        leading "PH "/"US " in the label is dropped (on Windows the flag renders as
        those same two letters)."""
        for pre in ("PH ", "US "):
            if label.startswith(pre):
                label = label[len(pre):]
        label = label[:1].upper() + label[1:]
        mv = move_html(key)
        return (f'<tr><td class="rl"><span class="fl">{flag}</span>{esc(label)}</td>'
                f'<td class="num"><div class="rv">{esc(value)}</div>'
                + (f'<div class="rn rm">{mv}</div>' if mv else "")
                + f'<div class="rn">{esc(note)}</div></td></tr>')

    _cpi_v, _, _cpi_m = PRINTS["ph_cpi"][1].partition(" (")
    _un = (((d.get("ph") or {}).get("unemployment") or {}).get("series") or [])
    jobs_chip = (ref_chip(f"PH jobless · {mon(_un[-1][0])}", f"{_un[-1][1]:g}%", "ph_jobs")
                 if _un else "")

    # Slow-moving figures: one always-visible summary line, detail folded beneath.
    # The fold opens itself, and the heading is badged, on a build where one changed.
    B["reference"] = f"""<div class="card solo"><h2>\U0001F3DB\ufe0f Rates &amp; PH indicators{' <span class="newdot">Updated</span>' if ref_changed else ''}</h2>
 <div class="idx">{ref_chip("BSP rate", RATES['bsp'][0], "bsp")}{ref_chip("Fed funds", RATES['fed'][0], "fed")}{ref_chip("PH inflation" + (" \u00b7 " + _cpi_m.rstrip(")") if _cpi_m else ""), _cpi_v, "ph_cpi")}{jobs_chip}</div>
 <div class="cap">Moves are the latest change in each figure. Red means dearer money, faster
 inflation, more jobless or slower growth; green the reverse.</div>
 <details class="coll"{' open' if ref_changed else ' data-k="ref"'}><summary>Policy rates, prints and charts</summary>
  <table class="reft">
   <tr><th colspan="2">Policy rates</th></tr>
   {ref_row(PH, "bsp", "BSP policy rate", *RATES['bsp'])}
   {ref_row(US, "fed", "Fed funds rate", *RATES['fed'])}
   {ref_row(JP, "boj", "BoJ policy rate", *RATES['boj'])}
   {ref_row(EU, "ecb", "ECB deposit rate", *RATES['ecb'])}
   <tr><th colspan="2">Latest prints</th></tr>
   {ref_row(PH, "ph_cpi", *PRINTS['ph_cpi'])}
   {ref_row(PH, "ph_gdp", *PRINTS['ph_gdp'])}
   {ref_row(US, "us_cpi", *PRINTS['us_cpi'])}
   {ref_row(US, "us_claims", *PRINTS['us_claims'])}
  </table>
  <div class="cap">Maintained by hand: policy rates and US prints in the builder config,
  PH inflation and jobs in ph_data.json.</div>
  <div class="refcharts">{ph_html}</div>
 </details></div>
"""

    body = "\n".join(B[name] for name in LAYOUT.get(EDITION, LAYOUT["morning"]) if name in B)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Daily Brief</title>
<style>
:root{{color-scheme:light;--cap:#8a6a12;--bg:#f6f7f9;--card:#fff;--ink:#1a2233;--muted:#66707f;--line:#e6e9ee;
 --accent:#1f5eff;--up:#0a8f4d;--down:#d13b3b;--chip:#fbfcfe;
 --t-ph:#e7f0ff;--t-mk:#e8f7ee;--t-cr:#fdeeee;--t-ai:#f3ecfd;--t-sp:#fff2e2;
 --warn:#fff8e6;--warn-bd:#e9c46a;--warn-ink:#6b5518}}
[data-theme=dark]{{color-scheme:dark;--cap:#d8bd72;--bg:#12151c;--card:#1b2029;--ink:#e8ecf3;--muted:#9aa4b2;
 --line:#2a313d;--accent:#6f9bff;--up:#4cc98a;--down:#f07a7a;--chip:#161b23;
 --t-ph:#1d2c4d;--t-mk:#15342a;--t-cr:#402024;--t-ai:#2e2247;--t-sp:#3d2e15;
 --warn:#2e2714;--warn-bd:#6b5518;--warn-ink:#e3c884}}
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
#refreshBtn{{background:var(--card);color:var(--ink);border:1px solid var(--line);
 border-radius:999px;padding:6px 12px;font-size:13px;cursor:pointer;margin-right:6px}}
#splash{{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;
 justify-content:center;background:rgba(0,0,0,.45)}}
.sp-card{{background:var(--card);border:1px solid var(--line);border-radius:14px;
 padding:17px 19px;width:min(340px,90vw);box-shadow:0 18px 50px rgba(0,0,0,.35)}}
.sp-title{{font-size:15px;font-weight:700}}
.sp-sub{{font-size:11.5px;color:var(--muted);margin-bottom:11px}}
.sp-bar{{height:4px;background:var(--line);border-radius:3px;overflow:hidden;margin-bottom:11px}}
.sp-fill{{height:100%;width:0;background:var(--accent);transition:width .25s}}
.sp-list{{list-style:none;margin:0;padding:0}}
.sp-step{{display:flex;align-items:center;gap:9px;padding:4px 0;font-size:12.5px}}
.sp-ic{{width:15px;text-align:center;font-weight:700}}
.sp-lb{{flex:1}}
.sp-st{{color:var(--muted);font-size:11.5px;font-variant-numeric:tabular-nums}}
.sp-foot{{margin-top:10px;font-size:10.5px;color:var(--muted);text-align:center}}
.st-ok{{color:var(--up)}} .st-warn{{color:#d9a21b}} .st-fail{{color:var(--down)}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.sp-spin{{display:inline-block;animation:spin .9s linear infinite}}
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
.note{{background:var(--warn);border:1px solid var(--warn-bd);color:var(--warn-ink);
 border-radius:9px;padding:9px 12px;margin-top:11px;font-size:12.5px;line-height:1.5}}
.note ul{{margin:4px 0 0;padding-left:16px}} .note li{{margin-bottom:3px}}
.chartblk{{margin-bottom:12px}}
.chartblk h4{{font-size:12px;font-weight:600;color:var(--muted);margin-bottom:2px}}
/* Every explanatory caption on the page: small, amber, out of the way of the data. */
.cap{{font-size:11px;line-height:1.5;color:var(--cap);margin-top:8px}}
.nsrc{{font-size:11px;color:var(--muted);white-space:nowrap}}
.chartblk .cap{{margin-top:2px}}
details.coll .cap{{margin-bottom:12px}}
ul.news li a{{color:inherit;text-decoration:none}}
ul.news li a:hover{{color:var(--accent);text-decoration:underline}}
.ext{{color:var(--muted);font-size:11px;margin-left:3px}}
.fcl{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:10px 0 5px}}
.fc5{{display:grid;grid-template-columns:repeat(5,1fr);gap:4px}}
.fc5 .d{{background:var(--chip);border:1px solid var(--line);border-radius:8px;
 padding:7px 2px;text-align:center;line-height:1.3}}
.fc5 .dn{{font-size:9.5px;font-weight:700;color:var(--muted);text-transform:uppercase}}
.fc5 .de{{font-size:17px;display:block;margin:2px 0}}
.fc5 .dt{{font-size:11.5px;font-weight:700;white-space:nowrap}}
.fc5 .dr{{font-size:9px;color:var(--muted);white-space:nowrap}}
@media (max-width:480px){{.fc5 .mm{{display:none}}}}
details.coll{{margin-top:11px;border-top:1px solid var(--line);padding-top:9px}}
details.coll>summary{{cursor:pointer;font-size:12px;font-weight:600;color:var(--muted);
 list-style:none;display:flex;justify-content:space-between;align-items:center}}
details.coll>summary::-webkit-details-marker{{display:none}}
/* The marker is a chevron drawn from two borders, so it cannot depend on a font
   glyph or on an escape sequence surviving the Python template. */
details.coll>summary::after{{content:"";width:7px;height:7px;flex:none;margin:0 4px 3px 8px;
 border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);
 transform:rotate(45deg);transition:transform .15s}}
details.coll[open]>summary::after{{transform:rotate(-135deg);margin-bottom:-3px}}
.newsgrid{{display:grid;gap:0}}
.newsitem{{padding:8px 0;border-bottom:1px solid var(--line);font-size:13.5px;line-height:1.45}}
.newsitem:last-child{{border-bottom:none}}
.newsitem a{{color:inherit;text-decoration:none;font-weight:600}}
.newsitem a:hover{{color:var(--accent);text-decoration:underline}}
.lead{{display:flex;justify-content:space-between;align-items:flex-end;gap:10px}}
.lead .lk{{font-size:12.5px;color:var(--muted)}} .lead .lk b{{color:var(--ink)}}
.lead .lv{{font-size:32px;font-weight:700;line-height:1.15;font-variant-numeric:tabular-nums}}
.lead .lm{{text-align:right;font-size:14.5px;font-weight:600;line-height:1.45;
 font-variant-numeric:tabular-nums}}
.lead .ls{{font-size:11px;font-weight:400;color:var(--muted)}}
table.rest{{table-layout:fixed;margin-top:4px}}
table.rest td,table.rest th{{padding:7px 4px;font-size:13px;overflow-wrap:anywhere}}
table.rest th{{font-size:10.5px}}
table.rest td.num{{white-space:nowrap}}
table.rest td[data-live=abs],table.rest td[data-live=src]{{white-space:normal}}
.fxrow{{display:flex;justify-content:space-between;align-items:baseline;gap:8px;
 padding:7px 0;border-bottom:1px solid var(--line);font-size:13.5px}}
.fxrow:last-child{{border-bottom:none}}
.fxrow .pair{{color:var(--muted)}}
.fxrow .val{{font-variant-numeric:tabular-nums;font-weight:600}}
.fxbig{{display:flex;justify-content:space-between;align-items:baseline;gap:10px}}
.fxbig .v{{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums}}
footer{{color:var(--muted);font-size:11.5px;margin-top:6px;line-height:1.6}}
.solo{{margin-bottom:14px}}
table.pft th,table.pft td{{padding:8px 4px;white-space:nowrap}}
table.pft th{{font-size:10.5px;letter-spacing:.04em}}
table.pft td{{font-size:13px}}
.pfsum{{border-top:1px solid var(--line);margin-top:2px;padding-top:8px}}
.pfsum.top{{border-top:none;margin-top:0;padding-top:0}}
details.coll .pfnote{{margin-top:6px}}
table.cal th{{padding-top:10px}} table.cal tr:first-child th{{padding-top:2px}}
/* One scroller only. Inside the app shell the frame is as tall as the page and the
   shell's own document scrolls, which is what gives native momentum on a phone. */
html.embedded,html.embedded body{{overflow:hidden}}
#ptr{{position:fixed;left:50%;top:8px;transform:translateX(-50%);z-index:9998;display:none;
 background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:999px;
 padding:6px 14px;font-size:12px;font-weight:600;box-shadow:0 6px 18px rgba(0,0,0,.25);
 pointer-events:none;white-space:nowrap}}
html.embedded #ptr{{position:absolute}}
.pfrow{{display:flex;justify-content:space-between;align-items:baseline;gap:10px;
 padding:4px 4px;font-size:13.5px;font-variant-numeric:tabular-nums}}
.pfrow.pftot{{border-top:1px solid var(--line);margin-top:6px;padding-top:10px}}
.pfnote{{color:var(--cap);font-size:12px;line-height:1.5;margin-top:10px}}
.pfnote ul{{margin:4px 0 0;padding-left:18px}} .pfnote li{{margin-bottom:3px}}
#builtAgo.late{{color:#d9a21b;font-weight:600}}
.changed ul.chg{{margin:0;padding-left:18px;font-size:13.5px;line-height:1.55}}
.changed ul.chg li{{margin-bottom:2px}}
.changed .chgsum{{margin-top:9px;padding-top:9px;border-top:1px solid var(--line);font-size:13px}}
table.reft{{margin-top:6px}}
table.reft th{{padding-top:12px;font-size:10.5px;letter-spacing:.06em}}
table.reft td{{vertical-align:middle;padding:8px 4px}}
.reft .rl{{font-weight:600;font-size:13.5px;white-space:nowrap}}
.reft .fl{{display:inline-block;min-width:1.7em;font-weight:400}}
.reft .rv{{font-size:17px;font-weight:700;line-height:1.2;font-variant-numeric:tabular-nums;
 white-space:nowrap}}
.reft .rm{{font-weight:600;font-size:12.5px}}
.reft .rn{{font-size:11.5px;color:var(--muted);line-height:1.35;margin-top:1px;
 text-wrap:balance}}
.refcharts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:4px 22px}}
.newdot{{display:inline-block;margin-left:6px;padding:1px 7px;border-radius:999px;
 background:var(--warn);border:1px solid var(--warn-bd);color:var(--warn-ink);
 font-size:10px;letter-spacing:.03em;vertical-align:middle}}
.sp-list li{{list-style:none}}
.sp-srcs{{display:none;list-style:none;margin:0 0 4px;padding:0 0 0 24px}}
.sp-open .sp-srcs{{display:block}}
.sp-src{{display:flex;align-items:center;gap:9px;padding:2px 0;font-size:11.5px;color:var(--muted)}}
.sp-msg{{display:none;background:var(--warn);border:1px solid var(--warn-bd);color:var(--warn-ink);
 border-radius:9px;padding:8px 11px;margin-top:10px;font-size:12px;line-height:1.5}}
.sp-actions{{display:flex;gap:8px;justify-content:center;margin-top:11px}}
.sp-actions button{{background:var(--card);color:var(--ink);border:1px solid var(--line);
 border-radius:999px;padding:7px 14px;font-size:12px;cursor:pointer}}
#sp-retry{{display:none;border-color:var(--accent);color:var(--accent);font-weight:600}}
.gauge svg{{max-width:100%;height:auto}}
@media (max-width:480px){{
 body{{padding:12px}}
 .grid{{gap:12px;margin-bottom:12px}}
 .card{{padding:13px;min-width:0}}
 .solo{{margin-bottom:12px}}
 table.pft th,table.pft td{{padding:7px 3px}}
 table.pft td{{font-size:12.5px}} table.pft th{{font-size:9.5px}}
 h1{{font-size:19px}}
 .big{{font-size:26px}}
 table{{font-size:12.5px}}
 td,th{{padding:6px 5px}}
 .wx .slot{{padding:7px 2px}}
 .wx .t,.wx .r{{font-size:10px}}
 .idx .chip{{flex:1 1 calc(50% - 5px);padding:9px 10px}}
 .impl{{grid-template-columns:1fr;gap:10px}}
 .impl ul{{padding-left:16px}}
 #themeBtn{{padding:9px 15px}}
 footer{{font-size:11px}}
}}
</style></head><body><div class="wrap">
<header>
 <div><h1 id="greet">{greet}</h1>
 <div class="sub">{NOW.strftime('%A, %B %-d, %Y')} · {CITY['name']} (PHT) · <span id="builtAgo" data-built="{NOW.isoformat()}" data-edition="{EDITION}">{built_txt}</span> · <span id="liveBadge">…</span></div></div>
 <div style="white-space:nowrap"><button id="refreshBtn"
  onclick="if(window.dbRefresh)window.dbRefresh()" title="Refetch live prices">\u27f3</button>
 <button id="themeBtn" onclick="tt()">\U0001F319 Dark</button></div>
</header>

{body}

<footer>Sources: Open-Meteo, FRED, Frankfurter (ECB), Coinbase, CoinGecko, Binance,
alternative.me, PSA (via ph_data.json), Google News.
Rebuilt by GitHub Actions at about 6 AM and 6 PM PHT; crypto, FX and sentiment refresh
on every open.</footer>
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
        shell = io.open("index.html", encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"  ! cannot read index.html ({type(e).__name__}). cwd holds: "
              + ", ".join(sorted(os.listdir("."))[:25]), file=sys.stderr)
        return None
    m = re.search(r"""var\s+GIST\s*=\s*['"]([0-9a-fA-F]+)['"]""", shell)
    if not m:
        print("  ! index.html has no recognisable \"var GIST = '...'\" line",
              file=sys.stderr)
        return None
    return m.group(1)


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
    prev_state = load_state()
    idx = indices(prev_state)
    fg = fear_greed()
    vix = idx.get("vix", {}).get("close") if idx else None

    cryp = crypto()
    data = {
        "weather": w,
        "fx": fx(),
        "crypto": cryp,
        "indices": idx,
        "eq": equity_gauge(vix),
        "cr": crypto_gauge(fg),
        "news": news(),
        "fg": fg,
        "prev_state": prev_state,
        "alerts": weather_alerts(w),
        "ph": ph_indicators(),
        "calendar": calendar_events(),
        "portfolio": portfolio(cryp),
    }

    got = [k for k in ("weather", "fx", "crypto", "news", "calendar", "portfolio")
           if data.get(k)]
    print(f"  retrieved: {', '.join(got) or 'nothing'}")
    if not got:
        sys.exit("Every source failed - refusing to overwrite the gist with an empty briefing.")

    save_state(snapshot_state(data))
    page = build_html(data)
    print(f"  html {len(page):,} bytes")

    payload = encrypt(page, passcode, frozen_salt(gist_id, token))
    print(f"  payload {len(payload):,} base64 chars")

    stamp = push(payload, gist_id, token)
    print(f"Pushed. Gist updated_at = {stamp}")


if __name__ == "__main__":
    main()
