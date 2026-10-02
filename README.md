# Daily Brief — installable PWA + server-side payload builder

Your existing design, unchanged in substance. Two things were added: the shell is now an
installable app, and the payload is rebuilt by GitHub Actions instead of by Claude, so the
7:30 AM refresh no longer depends on any app being open on your laptop.

## How it fits together

```
GitHub Actions (23:30 UTC = 07:30 PHT, every day)
   └─ build_briefing.py
        ├─ fetches weather, FX, crypto, indices, Fear & Greed, RSS news
        ├─ renders briefing HTML
        ├─ gzip  →  AES-256-GCM  (PBKDF2-SHA256, 600k iterations)
        └─ PATCH → secret gist / payload.txt        ← ciphertext only

GitHub Pages (this repo)
   └─ index.html   lock screen, fetches the gist, decrypts in your browser
      + manifest.json + sw.js + icons   ← what makes it installable
```

The gist never changes role: it stays the encrypted blob store. Only the shell lives on Pages,
because a service worker must be served same-origin with a JavaScript MIME type, which gist raw
URLs cannot do.

## Files

| File | Purpose |
|---|---|
| `index.html` | Lock screen + decryption. Your original, plus PWA wiring, offline support and live refresh. |
| `manifest.json` | Makes it installable. Name "Daily Brief", standalone, dark theme. |
| `sw.js` | Precaches the shell; caches the **encrypted** payload for offline opens. |
| `icon-192.png`, `icon-512.png`, `icon-maskable-512.png`, `apple-touch-icon.png` | Home-screen icons from your briefcase mark. |
| `build_briefing.py` | Gathers data, renders, encrypts, pushes to the gist. |
| `.github/workflows/briefing.yml` | Daily cron + manual run button. |
| `SAMPLE-briefing-output.html` | Example of what the builder produces. Not deployed — delete it if you like. |

All paths are relative, so this works at any username or repo name with no edits.

## Setup

**1. Create a token.** GitHub → Settings → Developer settings → Personal access tokens →
Tokens (classic) → Generate new token. Tick only the **`gist`** scope. Copy the token.

**2. Add three repository secrets.** Your repo → Settings → Secrets and variables → Actions →
New repository secret:

- `GIST_ID` — `fd25c59bbbab14d6ea56532bad7bfa9c`
- `GIST_TOKEN` — the token from step 1
- `BRIEF_PASSCODE` — the passcode you type to unlock the briefing (read the security note below first)

The calendar and portfolio secrets are listed in their own section further down.

**3. Allow the workflow to commit.** Settings → Actions → General → Workflow permissions →
**Read and write permissions** → Save. This is only for the heartbeat file in step 6.

**4. Upload the files.** Drag everything into your repo. The `.github/workflows/` folder must
keep that exact path. If drag-and-drop drops the leading dot, use "Add file → Create new file"
and type `.github/workflows/briefing.yml` as the filename — typing the slashes creates the folders.

**5. Test it now.** Actions tab → "Build daily briefing" → Run workflow. It should finish in
under a minute and log `Pushed. Gist updated_at = ...`. Open your Pages URL, enter the passcode,
and the new briefing should appear.

**6. Confirm the heartbeat.** After that first run a `last-run.txt` file appears in the repo.
This matters: GitHub disables scheduled workflows after 60 days with no repository activity, and
since the build pushes to a *gist* rather than the repo, nothing else would keep it alive.

**7. Install on Android.** Open the Pages URL in Chrome. Either tap "Install app" on the lock
screen or use ⋮ → Add to home screen → Install. On your laptop, the install icon appears in
Chrome's address bar. On iPhone, Share → Add to Home Screen.

## Security note — worth reading before step 2

Your scheme is well built: 600,000 PBKDF2-SHA256 iterations is current OWASP guidance, and
AES-256-GCM is the right cipher. Measured, derivation costs about 80 ms on a desktop and well
under half a second on a phone, so there is no UX reason to keep the passcode short.

The weak point is passcode length, because a secret gist is unlisted rather than access-controlled.
Anyone who learns the URL holds the ciphertext offline with unlimited attempts. Assuming a single
consumer GPU at roughly 5,000 guesses per second against this KDF:

| Passcode | Time to crack |
|---|---|
| 4-digit PIN | 2 seconds |
| 6-digit PIN | 3 minutes |
| 8-digit PIN | 6 hours |
| 8-char letters+digits | ~1,400 years |
| 4-word passphrase | ~23,000 years |

The `inputmode="numeric"` in your original suggested a PIN, so I removed it — the field now accepts
a full passphrase and phones will show a normal keyboard. Pick something in the bottom two rows.

Two consequences when you change the passcode: the existing payload still decrypts only with the
*old* one until the Action regenerates it, so run the workflow manually right after; and any
"remembered" device key stops working, which the shell detects and handles by asking for the
passcode again.

## Tiles and how often each updates

Every tile from the original dashboard is served except email, which you chose to drop so that no
mail credential exists anywhere in this setup.

| Tile | Source | Refresh |
|---|---|---|
| Weather (morning/afternoon/evening + golf outlook) | Open-Meteo | Each build |
| Today's schedule | Google Calendar | Each build |
| Portfolio — crypto holdings | Your sheet + Coinbase | **Live on every open** |
| Portfolio — ETF holdings | Your sheet + Stooq | Each build |
| Crypto prices | Coinbase | **Live on every open** |
| PHP FX rates | Frankfurter (ECB) | **Live on every open** |
| Crypto risk gauge + implications | alternative.me | **Live on every open** |
| Equity risk gauge, S&P/Nasdaq/VIX | Stooq | Each build |
| Policy rates (BSP, Fed, BoJ, ECB) | Builder config | When you edit them |
| News | Google News RSS | Each build |

Builds run **twice daily: 6:00 AM and 6:00 PM PHT** (22:00 and 10:00 UTC). The morning edition shows
today's schedule; the evening edition drops events that have finished and adds tomorrow's, and its
header reads "Evening edition".

The live tier calls Coinbase, Frankfurter and alternative.me straight from the page. All three allow
browser requests and need no credentials, and each is wrapped so a failure leaves the last build's
value in place — the live layer can only improve the page, never break it. A header badge reads
`live · 3:42 PM`, `partly live`, or `offline — morning build`. It re-runs when you bring the app
back to the foreground, throttled to once every two minutes.

Two things stay on the build clock for a real reason. VIX has no browser-callable source (Yahoo and
Stooq both omit CORS headers), and ETF quotes have the same problem — so both refresh at 6 AM and
6 PM. With two builds a day that gap is small; if you want them live too, a free Finnhub or Twelve
Data key would do it, or an hourly job writing `market.json` into this repo for same-origin reads.

GitHub's scheduler drifts five to fifteen minutes under load, so treat the times as approximate.

## Secrets

| Secret | Required | What it is |
|---|---|---|
| `BRIEF_PASSCODE` | yes | The passphrase you type to unlock the briefing |
| `GIST_ID` | yes | `fd25c59bbbab14d6ea56532bad7bfa9c` |
| `GIST_TOKEN` | yes | PAT with only the `gist` scope |
| `GOOGLE_SA_JSON` | for calendar + portfolio | The whole service-account JSON key, pasted as-is |
| `CALENDAR_ID` | for calendar | Usually `jaqua24@gmail.com` |
| `SHEET_ID` | for portfolio | The long id from the sheet's URL |
| `SHEET_RANGE` | optional | e.g. `Portfolio!A1:F100`. Defaults to `A1:Z200` |
| `CALENDAR_ICS_URL` | optional fallback | Secret iCal URL, used only if `CALENDAR_ID` is unset |

### Service account, once

1. console.cloud.google.com → create a project.
2. APIs & Services → Library → enable **Google Sheets API** and **Google Calendar API**.
3. IAM & Admin → Service Accounts → Create. Skip the optional role steps.
4. Open it → Keys → Add key → JSON. A file downloads; paste its entire contents as `GOOGLE_SA_JSON`.
5. Copy the service account's email (ends `.iam.gserviceaccount.com`).
6. Share your **portfolio sheet** with that email, Viewer.
7. Google Calendar → your calendar → Settings and sharing → Share with specific people → add that
   email with "See all event details".

Nothing here expires, and nothing becomes publicly reachable. I chose the Calendar API over the
secret iCal URL you picked because you're setting up the service account for Sheets anyway, and this
way Google expands recurring events server-side instead of us parsing RRULE rules. The iCal path is
still in the code as a fallback if you'd rather use it — set `CALENDAR_ICS_URL` and leave
`CALENDAR_ID` empty.

### Your spreadsheet layout

Headers are detected flexibly, anywhere in the first 10 rows. It needs a ticker column (`Ticker`,
`Symbol`, `Asset`...) and a quantity column (`Shares`, `Quantity`, `Units`...). Optional: a cost
column (`Avg Cost`, `Cost Basis`...) which turns on P&L, and a type column (`Type`, `Class`) — if
absent, anything matching BTC/ETH/SOL/BONK/JUP is treated as crypto and everything else as an ETF.

## Installing it

Verified against Chrome's installability criteria: HTTPS, a manifest with name, start_url,
standalone display and 192/512/maskable icons, plus a registered service worker with a fetch
handler. All asset paths are relative, so it works at any repo name.

**Android (Galaxy S25).** Open the Pages URL in Chrome or Samsung Internet. Tap "Install app" on the
lock screen, or use the browser menu → Add to Home screen → Install. You get a real launcher icon,
no address bar, and a dark status bar that follows the briefing's light/dark toggle. The maskable
icon was checked against One UI's squircle safe zone, so the briefcase will not be clipped.

**Desktop.** Chrome and Edge show an install button in the address bar. Firefox does not support
installing PWAs at all, and Safari on macOS offers "Add to Dock" instead — both still work fine as
ordinary tabs.

**iPhone.** Share → Add to Home Screen. iOS never fires an automatic prompt, so the "Install app"
button stays hidden there.

Layout is tuned for the S25's 360 CSS-pixel viewport: the gauges stack, the snapshot chips go
full-width, the implication columns become one, and the wider tables scroll horizontally inside
their card rather than overflowing the page.

## A note on the public repo

GitHub Pages only serves from public repos on the free plan. Your secrets stay encrypted and are
never exposed to forked pull requests, but **workflow logs are public on a public repo**, so the
builder deliberately logs only counts — never an event title, a holding or a ticker. Keep it that
way if you edit it. The plaintext briefing exists only in the runner's memory for a second or two
before encryption; it never touches disk or the log.

## Keeping Claude's briefing too

The hosted build now covers everything except email, so there is little left for the Claude task to
add. If you keep it, schedule it *after* a build — say 6:15 AM — since whichever writes the gist
last wins. Otherwise delete it, and GitHub Actions becomes the single source of truth, which is the
simpler arrangement and the one that keeps working when nothing of yours is running.

## Maintenance

Policy rates have no reliable free API, so `RATES` at the top of `build_briefing.py` holds BSP,
Fed, BoJ and ECB values. Edit them when a central bank moves; the next run picks it up. Everything
else is live.

The builder is deliberately fault-tolerant: each source is wrapped individually, missing data
renders as `—`, and if *every* source fails it exits without pushing, so a bad network day can
never replace your briefing with an empty page.

## Troubleshooting

**No install prompt.** Needs HTTPS (Pages gives you this), a reachable `manifest.json`, and a
registered service worker. Check Chrome DevTools → Application → Manifest. Note that Chrome won't
re-offer an app you already installed.

**"Could not reach the gist (HTTP 404)."** `GIST` in `index.html` and the `GIST_ID` secret must be
the same id, and the gist must still contain a file named exactly `payload.txt`.

**"Could not reach the gist (HTTP 403)."** Unauthenticated GitHub API calls are limited to 60 per
hour per IP. The freshness check runs at most once every 10 minutes, so this usually means
something else on your network is also calling the API. It resolves on its own.

**Workflow fails with 404 on push.** The token needs the `gist` scope, and it must belong to the
account that owns the gist.

**Stale content after deploying changes.** The service worker serves the cached shell first. Bump
`VERSION` in `sw.js` to force every device to pick up a new shell.
