<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="theme-color" content="#0e1420">
<meta name="color-scheme" content="dark">
<title>Daily Brief</title>

<link rel="manifest" href="manifest.json">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Daily Brief">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect x='6' y='20' width='52' height='34' rx='5' fill='%232563eb'/%3E%3Cpath d='M24 20v-5a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4v5' fill='none' stroke='%232563eb' stroke-width='4' stroke-linecap='round'/%3E%3Crect x='6' y='30' width='52' height='6' fill='%231e40af'/%3E%3Crect x='27' y='28' width='10' height='10' rx='2' fill='%23f8fafc'/%3E%3C/svg%3E">
<style>
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;
  background:#0e1420;color:#e6edf6;
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;padding:20px;
  padding-top:max(20px,env(safe-area-inset-top));padding-bottom:max(20px,env(safe-area-inset-bottom))}
.lock{width:100%;max-width:370px;background:#161e2c;border:1px solid #263144;
  border-radius:16px;padding:30px 28px;text-align:center;
  box-shadow:0 10px 40px rgba(0,0,0,.45)}
.ico{width:52px;height:52px;margin:0 auto 16px;display:block}
h1{font-size:19px;margin:0 0 5px;font-weight:600;letter-spacing:-.2px}
.sub{color:#93a3b8;font-size:13px;margin-bottom:22px}
input{width:100%;padding:11px 14px;font-size:17px;text-align:center;letter-spacing:.32em;
  background:#0e1420;border:1px solid #2e3a4e;border-radius:10px;color:#e6edf6;
  outline:none;font-family:inherit}
input:focus{border-color:#3b82f6}
input::placeholder{letter-spacing:.1em;color:#5b6b82}
button{width:100%;margin-top:11px;padding:11px;font-size:15px;font-weight:600;
  background:#2563eb;color:#fff;border:0;border-radius:10px;cursor:pointer;font-family:inherit}
button:hover:not(:disabled){background:#1d4ed8}
button:disabled{opacity:.55;cursor:default}
#installBtn{background:transparent;color:#93a3b8;border:1px solid #2e3a4e;display:none}
#installBtn:hover{color:#e6edf6;border-color:#3b82f6;background:transparent}
.msg{margin-top:13px;font-size:12.5px;min-height:17px;color:#93a3b8}
.msg.err{color:#f87171}
.rem{display:flex;align-items:center;justify-content:center;gap:7px;margin-top:12px;
  font-size:12.5px;color:#93a3b8;cursor:pointer;user-select:none}
.rem input{width:auto;margin:0;cursor:pointer;accent-color:#2563eb}
.foot{margin-top:20px;font-size:11px;color:#5b6b82;line-height:1.6}
/* Opening sequence. Same rows-with-timings pattern as the briefing's live-data
   card, so unlock -> decrypt -> live refresh reads as one continuous load. */
.steps{list-style:none;margin:16px 0 0;padding:0;text-align:left;display:none}
.lock.busy .steps{display:block}
.steps li{display:flex;align-items:center;gap:9px;padding:4px 0;font-size:12.5px;color:#93a3b8}
.steps .ic{width:15px;text-align:center;font-weight:700}
.steps .lb{flex:1}
.steps .st{font-size:11.5px;font-variant-numeric:tabular-nums}
.steps li.run,.steps li.ok{color:#e6edf6}
.steps li.ok .ic,.steps li.ok .st{color:#4cc98a}
.steps li.fail .ic,.steps li.fail .st{color:#f87171}
.steps li.run .ic{display:inline-block;animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* A remembered device skips the form entirely and shows only the sequence. */
.lock.auto form,.lock.auto #installBtn,.lock.auto .foot{display:none !important}
#view{position:fixed;inset:0;width:100%;height:100%;border:0;display:none;background:#0e1420;z-index:1}
#chrome{position:fixed;right:14px;z-index:2147483647;display:none;flex-direction:column;gap:8px;align-items:flex-end;
  bottom:max(14px,env(safe-area-inset-bottom))}
#chrome button,#chrome .pill{width:auto;margin:0;font:600 12px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#161e2c;color:#e6edf6;border:1px solid #2e3a4e;border-radius:999px;padding:9px 14px;cursor:pointer;opacity:.8;
  box-shadow:0 4px 14px rgba(0,0,0,.4)}
#chrome button:hover{opacity:1;border-color:#f87171;color:#f87171;background:#161e2c}
#stale{display:none;cursor:default;border-color:#7a6a3a;color:#e3c884}
#toast{position:fixed;left:50%;transform:translateX(-50%);top:max(14px,env(safe-area-inset-top));z-index:2147483647;
  background:#161e2c;border:1px solid #2e3a4e;color:#e6edf6;border-radius:999px;padding:8px 16px;
  font:600 12px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:none;
  box-shadow:0 4px 14px rgba(0,0,0,.4)}
</style>
</head>
<body>
<div class="lock" id="lock">
  <svg class="ico" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <rect x="6" y="20" width="52" height="34" rx="5" fill="#2563eb"/>
    <path d="M24 20v-5a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4v5" fill="none" stroke="#2563eb" stroke-width="4" stroke-linecap="round"/>
    <rect x="6" y="30" width="52" height="6" fill="#1e40af"/>
    <rect x="27" y="28" width="10" height="10" rx="2" fill="#f8fafc"/>
  </svg>
  <h1>Daily Brief</h1>
  <div class="sub" id="sub">Enter your passcode to unlock.</div>
  <form id="f" autocomplete="off">
    <input id="pw" type="password" placeholder="Passcode"
           autocomplete="current-password" aria-label="Passcode">
    <button id="go" type="submit">Unlock</button>
    <label class="rem"><input type="checkbox" id="rem"> Remember this device for 90 days</label>
  </form>
  <button id="installBtn" type="button">Install app</button>
  <div class="msg" id="msg"></div>
  <ul class="steps" id="steps" role="status" aria-live="polite">
    <li id="s-fetch"><span class="ic">&middot;</span><span class="lb">Fetch latest edition</span><span class="st"></span></li>
    <li id="s-dec"><span class="ic">&middot;</span><span class="lb">Decrypt</span><span class="st"></span></li>
    <li id="s-open"><span class="ic">&middot;</span><span class="lb">Open briefing</span><span class="st"></span></li>
  </ul>
  <div class="foot">Contents are encrypted with AES-256-GCM.<br>Decrypted and decompressed entirely in your browser.
    <br><span style="color:#7a6a3a">&ldquo;Remember&rdquo; stores the decryption key in this browser. Use only on
    devices you control.</span></div>
</div>

<div id="chrome">
  <div class="pill" id="stale"></div>
  <button id="forgetBtn" type="button">&#128274; Lock &amp; forget device</button>
</div>
<div id="toast"></div>

<script>
/* ---------- config ----------
   EDIT THIS ONE LINE and nothing else when you point the app at a gist.
   It must match the GIST_ID secret in the repo, or the build refuses to publish.
   Do NOT set it back to fd25c59bbbab14d6ea56532bad7bfa9c - that is the legacy
   briefing, maintained separately by a Claude scheduled task.               */
var GIST = '0d760e83001c29c6333f75cef619a7fe';
var API  = 'https://api.github.com/gists/' + GIST;

/* ---------- state ---------- */
var cached = null;          // base64 payload text
var liveKey = null;         // CryptoKey held in memory for silent refresh
var editionStamp = null;    // gist updated_at
var servedOffline = false;
var lastCheck = 0, CHECK_AFTER = 45000;   // debounce only; GitHub allows 60 req/hr

var msg = document.getElementById('msg');
var pw  = document.getElementById('pw');
var go  = document.getElementById('go');

var lockEl = document.getElementById('lock');
var subEl  = document.getElementById('sub');

function say(t, isErr){ msg.textContent = t; msg.className = isErr ? 'msg err' : 'msg'; }

/* ---------- opening sequence ---------- */
var MARKS = { wait:'\u00b7', run:'\u25cc', ok:'\u2713', fail:'\u2715' };
function step(id, state, txt){
  var li = document.getElementById('s-' + id); if (!li) return;
  li.className = state === 'wait' ? '' : state;
  li.querySelector('.ic').textContent = MARKS[state] || MARKS.wait;
  li.querySelector('.st').textContent = txt || '';
}
function resetSteps(){ ['fetch','dec','open'].forEach(function(id){ step(id, 'wait', ''); }); }

/* Runs the three stages, timing each. The error it throws carries .stage so the
   caller can tell "could not reach the gist" from "wrong key" - they need
   different handling, and only the second should ever discard a stored key. */
async function openBrief(decryptFn){
  lockEl.classList.add('busy');
  resetSteps();
  var t0 = Date.now(), html;
  step('fetch', 'run', '');
  try { await getPayload(); }
  catch (e) { step('fetch', 'fail', 'failed'); e.stage = 'fetch'; throw e; }
  step('fetch', 'ok', servedOffline ? 'offline copy' : ((Date.now() - t0) / 1000).toFixed(1) + 's');

  t0 = Date.now();
  step('dec', 'run', '');
  try { html = await decryptFn(); }
  catch (e) { step('dec', 'fail', 'failed'); e.stage = 'dec'; throw e; }
  step('dec', 'ok', ((Date.now() - t0) / 1000).toFixed(1) + 's');

  step('open', 'run', '');
  return html;
}

function toast(t){
  var el = document.getElementById('toast');
  el.textContent = t; el.style.display = 'block';
  setTimeout(function(){ el.style.display = 'none'; }, 2600);
}

/* ---------- status bar follows the briefing's theme (Android standalone) ---------- */
window.addEventListener('message', function(e){
  var d = e && e.data;
  if (!d) return;
  if (d.dailyBriefTheme) {
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', d.dailyBriefTheme === 'dark' ? '#12151c' : '#f6f7f9');
  }
  // The briefing's refresh button asks the shell to re-check for a new edition.
  if (d.dailyBriefCheck) checkFresh(true);
});

/* ---------- service worker ---------- */
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function(){
    navigator.serviceWorker.register('sw.js').catch(function(){});
  });
}

/* ---------- install prompt ---------- */
var deferredPrompt = null;
window.addEventListener('beforeinstallprompt', function(e){
  e.preventDefault();
  deferredPrompt = e;
  var b = document.getElementById('installBtn');
  b.style.display = 'block';
  b.onclick = function(){
    b.style.display = 'none';
    deferredPrompt.prompt();
    deferredPrompt = null;
  };
});
window.addEventListener('appinstalled', function(){
  var b = document.getElementById('installBtn'); if (b) b.style.display = 'none';
});

/* ---------- payload ---------- */
async function getPayload(force){
  if (cached && !force) return cached;
  var r = await fetch(API + '?t=' + Date.now(), {
    headers: { 'Accept': 'application/vnd.github+json' }, cache: 'no-store'
  });
  if (!r.ok) throw new Error('Could not reach the gist (HTTP ' + r.status + ').');
  servedOffline = r.headers.get('X-Daily-Brief-Offline') === '1';
  var j = await r.json();
  try { editionStamp = j.updated_at; } catch(e){}
  var fl = j.files && j.files['payload.txt'];
  if (!fl) throw new Error('payload.txt is missing from the gist.');
  var txt = fl.content;
  if (fl.truncated || !txt) txt = await (await fetch(fl.raw_url, {cache:'no-store'})).text();
  cached = txt.trim();
  return cached;
}

function b64ToBytes(b64){
  var bin = atob(b64);
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64FromBytes(b){
  var s=''; var a=new Uint8Array(b);
  for(var i=0;i<a.length;i++) s+=String.fromCharCode(a[i]);
  return btoa(s);
}

var K_KEY='briefing-device-key', K_EXP='briefing-device-exp';
var DAYS90 = 90*24*60*60*1000;

function forgetDevice(){
  try{ localStorage.removeItem(K_KEY); localStorage.removeItem(K_EXP); }catch(e){}
}
function storedKeyB64(){
  try{
    var exp=parseInt(localStorage.getItem(K_EXP)||'0',10);
    if(!exp || Date.now()>exp){ forgetDevice(); return null; }
    return localStorage.getItem(K_KEY);
  }catch(e){ return null; }
}

async function toHtml(buf){
  var b = new Uint8Array(buf);
  if (b.length>2 && b[0]===0x1f && b[1]===0x8b) {
    if (typeof DecompressionStream === 'undefined')
      throw new Error('This browser cannot decompress the briefing. Please use a current browser.');
    var st = new Blob([b]).stream().pipeThrough(new DecompressionStream('gzip'));
    return await new Response(st).text();
  }
  return new TextDecoder().decode(b);
}

async function decryptWith(keyObj){
  var raw = b64ToBytes(await getPayload());
  if (raw.length < 29) throw new Error('Payload looks malformed.');
  var iv = raw.subarray(16, 28), body = raw.subarray(28);
  var plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv: iv }, keyObj, body);
  return await toHtml(plain);
}

async function unlock(pass){
  var raw = b64ToBytes(await getPayload());
  if (raw.length < 29) throw new Error('Payload looks malformed.');
  var salt = raw.subarray(0, 16);
  var iv   = raw.subarray(16, 28);
  var body = raw.subarray(28);

  var km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  var key = await crypto.subtle.deriveKey(
    { name:'PBKDF2', salt: salt, iterations: 600000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, true, ['decrypt']
  );
  var plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv: iv }, key, body);

  liveKey = key;
  if (document.getElementById('rem') && document.getElementById('rem').checked) {
    try{
      var rawKey = await crypto.subtle.exportKey('raw', key);
      localStorage.setItem(K_KEY, b64FromBytes(rawKey));
      localStorage.setItem(K_EXP, String(Date.now() + DAYS90));
    }catch(e){}
  }
  return await toHtml(plain);
}

/* ---------- render ---------- */
function render(html){
  var fr = document.getElementById('view');
  if (!fr) {
    fr = document.createElement('iframe');
    fr.id = 'view';
    fr.setAttribute('title', 'Daily Brief');
    document.body.appendChild(fr);
  }
  fr.srcdoc = html;
  step('open', 'ok', '');
  fr.style.display = 'block';
  document.getElementById('lock').style.display = 'none';
  document.body.style.padding = '0';
  document.getElementById('chrome').style.display = 'flex';
  updateStale();
}

function updateStale(){
  var el = document.getElementById('stale');
  if (!el) return;
  var showOffline = servedOffline || !navigator.onLine;
  if (!showOffline) { el.style.display = 'none'; return; }
  var when = '';
  if (editionStamp) {
    var age = Date.now() - new Date(editionStamp).getTime();
    var hrs = Math.floor(age/3600000);
    when = hrs < 1 ? 'just now' : (hrs < 24 ? hrs + 'h ago' : Math.floor(hrs/24) + 'd ago');
    when = ' — updated ' + when;
  }
  el.textContent = '⚡ Offline' + when;
  el.style.display = 'block';
}
window.addEventListener('online',  updateStale);
window.addEventListener('offline', updateStale);

document.getElementById('forgetBtn').onclick = function(){
  forgetDevice();
  liveKey = null;
  location.reload();
};

/* ---------- freshness: refresh in place, no re-prompt ---------- */
async function checkFresh(force){
  if (!liveKey) return;
  if (document.visibilityState !== 'visible') return;
  if (!force && Date.now() - lastCheck < CHECK_AFTER) return;
  lastCheck = Date.now();
  try {
    var r = await fetch(API + '?t=' + Date.now(),
                        { headers: {'Accept':'application/vnd.github+json'}, cache: 'no-store' });
    if (!r.ok) return;
    servedOffline = r.headers.get('X-Daily-Brief-Offline') === '1';
    var j = await r.json();
    if (j && j.updated_at && j.updated_at !== editionStamp) {
      cached = null;
      var html = await decryptWith(liveKey);
      render(html);
      toast('New edition loaded');
    } else {
      updateStale();
    }
  } catch(e){ updateStale(); }
}
window.addEventListener('focus', checkFresh);
window.addEventListener('pageshow', checkFresh);
document.addEventListener('visibilitychange', checkFresh);

/* ---------- entry points ---------- */
document.getElementById('f').addEventListener('submit', async function(e){
  e.preventDefault();
  var pass = pw.value;
  if (!pass) { say('Enter your passcode.', true); return; }
  go.disabled = true; pw.disabled = true;
  say('');
  try {
    var html = await openBrief(function(){ return unlock(pass); });
    lastCheck = Date.now();
    render(html);
  } catch (err) {
    var net = (err && err.stage === 'fetch') ||
              /gist|payload|HTTP|Failed to fetch|NetworkError/i.test(err && err.message || '');
    say(net ? ((err && err.message) || 'Network error.') : 'Incorrect passcode.', true);
    go.disabled = false; pw.disabled = false;
    if (!net) pw.value = '';
    pw.focus();
  }
});

(async function tryDevice(){
  var b64 = storedKeyB64();
  if(!b64) { pw.focus(); getPayload().catch(function(){}); return; }
  lockEl.classList.add('auto');
  subEl.textContent = 'Remembered device. Opening your brief…';
  go.disabled = true; pw.disabled = true;
  try{
    var kb = b64ToBytes(b64);
    var key = await crypto.subtle.importKey('raw', kb, {name:'AES-GCM'}, true, ['decrypt']);
    var html = await openBrief(function(){ return decryptWith(key); });
    liveKey = key;
    lastCheck = Date.now();
    render(html);
    var left = Math.ceil((parseInt(localStorage.getItem(K_EXP),10) - Date.now())/86400000);
    var fb = document.getElementById('forgetBtn');
    if (fb) fb.title = 'Device remembered for ' + left + ' more day' + (left===1?'':'s');
  }catch(e){
    lockEl.classList.remove('auto');
    subEl.textContent = 'Enter your passcode to unlock.';
    if (e && e.stage === 'fetch') {
      // The network failed, not the key. Keep the device remembered: reopening
      // with a connection will work without the passcode.
      say('Could not reach the briefing. Check your connection and reopen, or enter your passcode to retry.', true);
    } else {
      forgetDevice();
      say('Saved device key no longer works — enter your passcode.', true);
    }
    go.disabled = false; pw.disabled = false; pw.focus();
  }
})();
</script>
</body>
</html>
