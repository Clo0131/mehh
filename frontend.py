#!/usr/bin/env python3
"""
CoolStock - front end (screens + web server)
============================================
Run:    python app.py            then open  http://localhost:8000
Option: python app.py --lan      lets other devices on your Wi-Fi/LAN connect
        python app.py --port 9000 --no-browser

Keep this file and logic.py (and coolstock.db) in the same folder.
This file holds the HTML/CSS/JavaScript screens, the URL routes and the HTTP server.
All of the real work (database, rules, algorithms) is in logic.py.
"""
import json
import os
import sys
import threading
import traceback
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from logic import *            # noqa: F401,F403  (handlers, db helpers, constants)
from logic import _t

PUBLIC, OWNER, OP, OE = "public", {"owner"}, {"owner", "purchasing"}, {"owner", "employee"}
ROUTES = [
    ("POST", r"/api/movements", h_move, None), ("POST", r"/api/reorder", h_reorder, OP),
    ("POST", r"/api/login", h_login, PUBLIC), ("POST", r"/api/register", h_register, PUBLIC), ("GET", r"/api/login-info", h_login_info, PUBLIC), ("GET", r"/api/shops", h_shops, PUBLIC),
    ("POST", r"/api/logout", h_logout, None), ("GET", r"/api/me", h_me, None), ("POST", r"/api/password", h_password, None),
    ("PUT", r"/api/settings", h_settings_put, OWNER),
    ("GET", r"/api/dashboard", h_dashboard, None),
    ("GET", r"/api/products", h_products, None), ("POST", r"/api/products", h_product_create, OWNER),
    ("GET", r"/api/products/(\d+)/detail", h_product_detail, None),
    ("PUT", r"/api/products/(\d+)", h_product_update, OWNER), ("DELETE", r"/api/products/(\d+)", h_product_archive, OWNER),
    ("POST", r"/api/promo", h_promo, OWNER),
    ("GET", r"/api/lowstock", h_lowstock, None), ("GET", r"/api/deadstock", h_deadstock, OWNER),
    ("GET", r"/api/substitutes", h_substitutes, None),
    ("GET", r"/api/sales", h_sales, OE), ("POST", r"/api/sales", h_sale_create, OE),
    ("GET", r"/api/sales/(\d+)", h_sale_get, OE), ("POST", r"/api/sales/(\d+)/void", h_sale_void, OWNER),
    ("GET", r"/api/reports", h_reports, OWNER), ("GET", r"/api/alerts", h_alerts, OWNER), ("GET", r"/api/audit", h_audit, OWNER),
    ("GET", r"/api/users", h_users, OWNER), ("POST", r"/api/users", h_user_save, OWNER), ("PUT", r"/api/users/(\d+)", h_user_save, OWNER),
    ("POST", r"/api/users/(\d+)/(approve|reject)", h_user_approve, OWNER),
]


# ================================================================ http server
class Handler(BaseHTTPRequestHandler):
    server_version = "CoolStock"

    def log_message(self, *a):
        pass

    def reply(self, code, data, ctype="application/json", headers=None):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") or ctype == "application/json" else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def handle_any(self, method):
        url = urlparse(self.path)
        path = url.path
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        sid = ck["sid"].value if "sid" in ck else None
        c = db()
        _t.shop = None
        try:
            user = session_user(c, sid)
            _t.shop = user["shop"] if user else None
            if method == "GET":
                if path in ("/", "/index.html"):
                    return self.reply(200, (APP_HTML if user else LOGIN_HTML).replace("__APP__", APP_NAME).encode(), "text/html")
                if path == "/login":
                    return self.redirect("/") if user else self.reply(200, LOGIN_HTML.replace("__APP__", APP_NAME).encode(), "text/html")
                m = re.fullmatch(r"/invoice/(\d+)", path)
                if m:
                    if not user or user["role"] not in ("owner", "employee"):
                        return self.redirect("/")
                    s = c.execute("SELECT user FROM sales WHERE id=? AND shop_id=?", (int(m.group(1)), user["shop"])).fetchone()
                    if not s:
                        return self.reply(404, b"Invoice not found", "text/plain")
                    if user["role"] == "employee" and s["user"] != user["username"]:
                        return self.reply(403, b"Not your sale", "text/plain")
                    return self.reply(200, invoice_html(c, int(m.group(1))).encode(), "text/html")
            for m_, pattern, fn, roles in ROUTES:
                mt = re.fullmatch(pattern, path)
                if m_ != method or not mt:
                    continue
                if roles != PUBLIC:
                    if not user:
                        return self.reply(401, {"error": "Please sign in."})
                    if roles and user["role"] not in roles:
                        return self.reply(403, {"error": "Your role is not allowed to do this."})
                if method != "GET" and self.headers.get("X-Requested-With") != "fetch":
                    return self.reply(403, {"error": "Blocked: missing request header."})
                body = {}
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    try:
                        body = json.loads(self.rfile.read(n))
                        if not isinstance(body, dict):
                            raise ValueError
                    except ValueError:
                        return self.reply(400, {"error": "Invalid JSON"})
                ctx = dict(user or {}, ip=self.client_address[0])
                write = method != "GET"
                try:
                    if write:
                        c.execute("BEGIN IMMEDIATE")
                    data = fn(c, ctx, parse_qs(url.query), body, *mt.groups())
                    if write:
                        c.execute("COMMIT")
                except BaseException:
                    if c.in_transaction:
                        c.execute("ROLLBACK")
                    raise
                if isinstance(data, Resp):
                    return self.reply(data.code, data.data, data.ctype, data.headers)
                if user and user["role"] == "employee":
                    data = redact(data)
                return self.reply(200, data)
            self.reply(404, {"error": "Not found"})
        except ApiError as e:
            self.reply(e.code, {"error": e.msg})
        except Exception as e:
            traceback.print_exc()
            self.reply(500, {"error": f"Server error: {e}"})
        finally:
            c.close()

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")
    def do_PUT(self): self.handle_any("PUT")
    def do_DELETE(self): self.handle_any("DELETE")


LOGIN_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in - __APP__</title>
<style>
*{box-sizing:border-box}
:root{--bg:#f5f5f7;--panel:#fff;--ink:#1d1d1f;--mut:#6e6e73;--line:rgba(60,60,67,.18);--pri:#007aff;--pri2:#0063d1}
@media(prefers-color-scheme:dark){:root{--bg:#000;--panel:#1c1c1e;--ink:#f5f5f7;--mut:#98989d;--line:rgba(235,235,245,.18);--pri:#0a84ff;--pri2:#409cff}}
body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue","Segoe UI",system-ui,sans-serif;color:var(--ink);background:var(--bg);-webkit-font-smoothing:antialiased}
.card{width:min(410px,92vw);background:var(--panel);border-radius:22px;box-shadow:0 2px 4px rgba(0,0,0,.04),0 18px 50px rgba(0,0,0,.10);padding:32px 30px 26px}
.logo{font-size:28px;font-weight:700;letter-spacing:-.025em}
.sub{color:var(--mut);margin:2px 0 20px;font-size:14px}
label{display:block;font-size:12px;color:var(--mut);margin:12px 0 4px;font-weight:500}
input,select{width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:12px;font:inherit;background:var(--panel);color:var(--ink)}
input:focus,select:focus{outline:3px solid color-mix(in srgb,var(--pri) 30%,transparent);border-color:var(--pri)}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:980px;background:var(--pri);color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:var(--pri2)}button:disabled{opacity:.5}
.err{background:rgba(215,0,21,.1);color:#d70015;border-radius:12px;padding:9px 13px;margin-top:14px;display:none;font-size:14px}
.sw{margin-top:16px;text-align:center;color:var(--mut);font-size:14px}.sw a{color:var(--pri);cursor:pointer}
.hint{font-size:12px;color:var(--mut);margin-top:5px}.hide{display:none}
.roles{display:grid;gap:8px;margin-top:4px}.role{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:12px;padding:10px 12px;cursor:pointer;margin:0;font-size:14px;color:var(--ink)}
.role input{width:auto;margin-top:3px}.role b{display:block;font-weight:600}.role small{color:var(--mut);font-size:12px}.role:has(input:checked){border-color:var(--pri);background:color-mix(in srgb,var(--pri) 8%,var(--panel))}
.okmsg{background:rgba(36,138,61,.12);color:#248a3d;border-radius:12px;padding:10px 13px;font-size:14px;margin-bottom:8px}.welcome{background:color-mix(in srgb,var(--pri) 9%,var(--panel));border-radius:12px;padding:10px 13px;font-size:13px;margin-bottom:6px}
.card{width:min(420px,92vw);background:rgba(255,255,255,.6);border:1px solid rgba(255,255,255,.8);border-radius:34px;-webkit-backdrop-filter:blur(36px) saturate(190%);backdrop-filter:blur(36px) saturate(190%);box-shadow:0 20px 60px rgba(40,60,120,.18),inset 0 1px 0 rgba(255,255,255,.9);padding:34px 30px 28px}
@media(prefers-color-scheme:dark){.card{background:rgba(44,44,52,.55);border-color:rgba(255,255,255,.14);box-shadow:0 20px 60px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.14)}}
body{background:radial-gradient(900px 600px at 8% 0%,#cfe4ff 0,transparent 60%),radial-gradient(800px 600px at 100% 10%,#e9d8ff 0,transparent 60%),radial-gradient(900px 700px at 70% 100%,#ffe3d6 0,transparent 60%),#eef1f8 fixed}
@media(prefers-color-scheme:dark){body{background:radial-gradient(900px 600px at 8% 0%,#14284d 0,transparent 60%),radial-gradient(800px 600px at 100% 10%,#2c1a4a 0,transparent 60%),radial-gradient(900px 700px at 70% 100%,#3a1f2a 0,transparent 60%),#05060a fixed}}
input,select{background:rgba(255,255,255,.5);border-radius:14px}
input[type=number]{-moz-appearance:textfield}input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none}
select{-webkit-appearance:none;appearance:none;padding-right:34px;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'><path d='M2.5 4.5 6 8l3.5-3.5' fill='none' stroke='%238e8e93' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>");background-repeat:no-repeat;background-position:right 13px center;background-size:12px}
@media(prefers-color-scheme:dark){input,select{background:rgba(255,255,255,.08)}}
</style></head><body>
<form class="card" id="f" autocomplete="on">
  <div class="logo">__APP__</div>
  <div class="sub" id="shop">Aircon Inventory, Sales &amp; Purchasing</div>
  <div id="welcome" class="welcome hide">No accounts yet. Create the first account to get started.</div>
  <div id="ok" class="okmsg hide"></div>
  <div id="rn" class="hide"><label for="n">Full name</label><input id="n" name="name" autocomplete="name"></div>
  <label for="u">Username</label><input id="u" name="username" autofocus required autocomplete="username">
  <label for="p">Password</label><input id="p" name="password" type="password" required autocomplete="current-password">
  <div id="rc" class="hide"><label for="c">Confirm password</label><input id="c" name="confirm" type="password" autocomplete="new-password">
    <label style="margin-top:12px">Your role</label>
    <div class="roles" id="roles">
      <label class="role"><input type="radio" name="role" value="owner" checked><span><b>Shop Owner</b><small>Creates your own shop. You add the stock and manage everything.</small></span></label>
      <label class="role"><input type="radio" name="role" value="employee"><span><b>Sales staff</b><small>Works for a shop owner: sells and searches stock</small></span></label>
      <label class="role"><input type="radio" name="role" value="purchasing"><span><b>Purchasing</b><small>Works for a shop owner: restock planning</small></span></label>
    </div>
    <div id="rs"><label for="sn">Shop name</label><input id="sn" name="shop_name" placeholder="e.g. Santos Aircon Center"><div class="hint">Your shop starts empty. You add the products after signing in.</div></div>
    <div id="ro" class="hide"><label for="ow">Which shop owner do you work for?</label><select id="ow"></select>
      <div class="hint" id="owhint">The owner has to approve your account before you can sign in. You will then see that shop's stock.</div></div>
  </div>
  <div class="err" id="err"></div>
  <button id="go">Sign in</button>
  <div class="sw" id="sw"></div>
</form>
<script>
const $=s=>document.querySelector(s);
let REG=false,INFO={users:1},SHOPS=[];
const role=()=>{const r=document.querySelector('#roles input:checked');return r?r.value:''};
function roleUI(){
  const own=role()==='owner';
  $('#rs').classList.toggle('hide',!own);$('#ro').classList.toggle('hide',own);
}
function mode(r){
  REG=r;$('#rn').classList.toggle('hide',!r);$('#rc').classList.toggle('hide',!r);$('#go').textContent=r?'Create account':'Sign in';
  $('#p').autocomplete=r?'new-password':'current-password';$('#err').style.display='none';
  $('#welcome').classList.toggle('hide',!(r&&INFO.users===0));
  $('#sw').innerHTML=INFO.users>0?(r?'Already have an account? <a data-m="in">Sign in</a>':"Don't have an account? <a data-m='up'>Create one</a>"):'';
  roleUI();
}
$('#sw').onclick=e=>{const a=e.target.closest('a[data-m]');if(a){$('#ok').classList.add('hide');mode(a.dataset.m==='up')}};
$('#roles').onchange=roleUI;
Promise.all([fetch('/api/login-info').then(r=>r.json()),fetch('/api/shops').then(r=>r.json())]).then(([d,sh])=>{
  INFO=d;SHOPS=sh;
  const sel=$('#ow');
  sel.innerHTML=sh.length?sh.map(x=>`<option value="${x.id}">${(x.shop||'Unnamed shop').replace(/</g,'&lt;')} - owner: ${x.owner.replace(/</g,'&lt;')}</option>`).join(''):'<option value="">No shop owners yet</option>';
  if(!sh.length){$('#owhint').textContent='There are no shop owners yet. The shop owner has to create an account first.'}
  mode(d.users===0);
}).catch(()=>mode(false));
$('#f').onsubmit=async e=>{
  e.preventDefault();const b=$('#go');b.disabled=true;$('#err').style.display='none';
  try{
    const body={username:$('#u').value,password:$('#p').value};
    if(REG){
      body.name=$('#n').value;body.confirm=$('#c').value;body.role=role();
      if(body.role==='owner')body.shop_name=$('#sn').value;else body.owner_id=$('#ow').value;
    }
    const r=await fetch(REG?'/api/register':'/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'fetch'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Something went wrong');
    if(d.pending){
      const m=$('#ok');m.textContent='Request sent. '+d.owner+' has to approve your account. You can sign in after that.';m.classList.remove('hide');
      mode(false);$('#p').value='';b.disabled=false;return;
    }
    location.href='/';
  }catch(x){$('#err').textContent=x.message;$('#err').style.display='block';b.disabled=false}
};
</script>
</body></html>
"""
APP_HTML = r"""<!doctype html>
<html lang="en" data-theme="light"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__APP__</title>
<style>
:root{--bg:#f5f5f7;--panel:#fff;--ink:#1d1d1f;--mut:#6e6e73;--line:rgba(60,60,67,.14);--pri:#007aff;--pri2:#0063d1;--ok:#248a3d;--warn:#b25000;--bad:#d70015;
--ice:#f2f2f7;--hov:#f5f5f7;--c1:#007aff;--c2:#34c759;--c3:#ff9f0a;--c4:#af52de;--side:rgba(246,246,248,.72);--sideink:#1d1d1f;--r:14px;--sh:0 1px 2px rgba(0,0,0,.04),0 6px 20px rgba(0,0,0,.05)}
[data-theme=dark]{--bg:#000;--panel:#1c1c1e;--ink:#f5f5f7;--mut:#98989d;--line:rgba(235,235,245,.16);--pri:#0a84ff;--pri2:#409cff;--ok:#30d158;--warn:#ff9f0a;--bad:#ff453a;
--ice:#2c2c2e;--hov:#2c2c2e;--c1:#0a84ff;--c2:#30d158;--c3:#ff9f0a;--c4:#bf5af2;--side:rgba(28,28,30,.72);--sideink:#f5f5f7;--sh:none}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Helvetica Neue","Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased;letter-spacing:-.006em}
.app{display:grid;grid-template-columns:236px 1fr;min-height:100vh}
#side{background:var(--side);-webkit-backdrop-filter:saturate(180%) blur(28px);backdrop-filter:saturate(180%) blur(28px);color:var(--sideink);position:sticky;top:0;height:100vh;overflow-y:auto;padding:18px 12px;border-right:1px solid var(--line)}
.logo{font-size:19px;font-weight:700;letter-spacing:-.02em;padding:2px 10px 14px}.logo small{display:block;font-size:12px;font-weight:400;color:var(--mut);margin-top:2px;letter-spacing:0}
#nav h6{margin:16px 10px 5px;font-size:11px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
#nav a{display:block;padding:7px 10px;margin:1px 0;color:var(--sideink);text-decoration:none;cursor:pointer;border-radius:9px;font-weight:500}
#nav a:hover{background:rgba(120,120,128,.12)}#nav a.on{background:var(--pri);color:#fff}
.main{min-width:0}
.top{display:flex;gap:10px;align-items:center;padding:10px 26px;position:sticky;top:0;z-index:20;background:var(--side);-webkit-backdrop-filter:saturate(180%) blur(24px);backdrop-filter:saturate(180%) blur(24px);border-bottom:1px solid var(--line)}
.gs{position:relative;flex:1;max-width:420px}.gs input{width:100%;background:rgba(120,120,128,.12);border:0;border-radius:10px;padding:8px 12px}
#gsr{position:absolute;top:100%;left:0;right:0;background:var(--panel);border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,.18);margin-top:6px;display:none;z-index:30;overflow:hidden}
#gsr a{display:flex;justify-content:space-between;gap:10px;padding:9px 14px;cursor:pointer;border-bottom:1px solid var(--line)}#gsr a:hover{background:var(--hov)}
.grow{flex:1}#burger{display:none}
.ib{background:rgba(120,120,128,.12);border:0;border-radius:980px;padding:6px 13px;cursor:pointer;color:var(--ink);font:inherit;font-size:13px;font-weight:500}.ib:hover{background:rgba(120,120,128,.2)}
.ib b{background:var(--bad);color:#fff;border-radius:980px;padding:0 6px;font-size:11px;margin-left:5px;font-weight:600}
.me{display:flex;align-items:center;gap:8px;padding-left:6px}.me div{line-height:1.2;text-align:right}.me small{color:var(--mut);display:block;font-size:12px}
.page{padding:26px 28px 60px;max-width:1360px}
.ph{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-end;margin-bottom:18px}
.ph h2{margin:0;font-size:28px;font-weight:700;letter-spacing:-.025em}.mut{color:var(--mut)}.ph p{margin:3px 0 0;font-size:14px}.pa{display:flex;gap:8px;flex-wrap:wrap}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}
.kpi{padding:16px 18px;background:var(--panel);border-radius:var(--r);box-shadow:var(--sh)}
.kpi .l{color:var(--mut);font-size:12px;font-weight:500}.kpi .v{font-size:26px;font-weight:700;margin-top:2px;letter-spacing:-.02em}.kpi .s{font-size:12px;color:var(--mut);margin-top:1px}
.panel{background:var(--panel);border-radius:var(--r);box-shadow:var(--sh);padding:18px;margin-bottom:16px;overflow-x:auto}
.panel h3{margin:0 0 10px;font-size:17px;font-weight:600;letter-spacing:-.015em}.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.g3{display:grid;grid-template-columns:2fr 1fr;gap:16px}
.panel .tw{margin:0 -18px -18px}
table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
th{font-size:11px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.05em}th.srt{cursor:pointer;user-select:none}th.srt:hover{color:var(--pri)}
tbody tr:last-child td{border-bottom:0}
td.r,th.r{text-align:right}tbody tr:hover td{background:var(--hov)}td.wrap{white-space:normal;min-width:200px}td.act{white-space:normal;min-width:176px;max-width:210px}
.sub{color:var(--mut);font-size:12px}.empty,.load{padding:28px;text-align:center;color:var(--mut)}
.badge{display:inline-block;padding:2px 9px;border-radius:980px;font-size:12px;font-weight:600;white-space:nowrap}
.OK,.IN,.RECEIVED,.PAID,.RELEASED,.low-sev{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}
.LOW,.ADJUST,.PARTIAL,.ORDERED,.ACTIVE,.A,.med{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)}
.OUT,.VOID,.CANCELLED,.high,.overdue{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad)}
.SALE,.DRAFT,.B,.C{background:color-mix(in srgb,var(--pri) 13%,transparent);color:var(--pri)}
.neg{color:var(--bad)}.pos{color:var(--ok)}.warn{color:var(--warn)}.promo{color:var(--bad)}
.b{background:var(--pri);color:#fff;border:0;border-radius:980px;padding:8px 16px;cursor:pointer;font:inherit;font-size:13px;font-weight:500;white-space:nowrap;text-decoration:none;display:inline-block;transition:background .15s,transform .05s}
.b:hover{background:var(--pri2)}.b:active{transform:scale(.97)}.b.g{background:rgba(120,120,128,.14);color:var(--pri)}.b.g:hover{background:rgba(120,120,128,.24)}
.b.d{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad)}.b.sm{padding:3px 10px;font-size:12px;margin:0 3px 3px 0}.b:disabled{opacity:.4;cursor:not-allowed}
input,select,textarea{padding:8px 11px;border:1px solid var(--line);border-radius:10px;font:inherit;background:var(--panel);color:var(--ink)}
input:focus,select:focus,textarea:focus{outline:3px solid color-mix(in srgb,var(--pri) 30%,transparent);outline-offset:0;border-color:var(--pri)}
.bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center}.bar input[type=search]{flex:1;min-width:220px}
.chip{background:rgba(120,120,128,.12);border:0;border-radius:980px;padding:6px 13px;cursor:pointer;font:inherit;font-size:13px;font-weight:500;color:var(--ink)}
.chip.on{background:var(--ink);color:var(--panel)}
dialog{border:0;border-radius:20px;padding:0;width:min(500px,94vw);background:var(--panel);color:var(--ink);box-shadow:0 24px 80px rgba(0,0,0,.35)}
dialog.wide{width:min(920px,96vw)}dialog::backdrop{background:rgba(0,0,0,.35);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px)}
.mh{display:flex;justify-content:space-between;align-items:center;padding:16px 20px 8px}.mh h3{margin:0;font-size:19px;font-weight:600;letter-spacing:-.02em}
.x{background:rgba(120,120,128,.16);border:0;border-radius:50%;width:28px;height:28px;font-size:18px;line-height:1;cursor:pointer;color:var(--mut)}.mb{padding:4px 20px;max-height:72vh;overflow:auto}
.acts{display:flex;justify-content:flex-end;gap:8px;padding:12px 20px 18px}
label{display:block;font-size:12px;color:var(--mut);margin:11px 0 4px;font-weight:500}.mb input,.mb select,.mb textarea{width:100%}
.r2{display:grid;grid-template-columns:1fr 1fr;gap:10px}.r3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.note{background:color-mix(in srgb,var(--pri) 9%,var(--panel));border-radius:12px;padding:11px 15px;margin-bottom:14px;font-size:13px}
.note.bad{background:color-mix(in srgb,var(--bad) 10%,var(--panel))}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}.card{background:var(--panel);border-radius:var(--r);box-shadow:var(--sh);padding:14px}
.card b{display:block}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(125px,1fr));gap:8px;margin:10px 0}
.stats div{padding:9px 12px;background:var(--ice);border-radius:12px}
.stats small{display:block;color:var(--mut);font-size:12px}.stats b{font-size:16px;font-weight:600}
.posg{display:grid;grid-template-columns:1.25fr 1fr;gap:16px;align-items:start}.cartp{position:sticky;top:70px}
.pi{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:10px 2px;border-bottom:1px solid var(--line)}
.pi:last-child{border:0}.pi.dis{opacity:.55}#plist{margin-top:10px;max-height:66vh;overflow:auto}
.cl{display:grid;grid-template-columns:1fr 60px 104px 26px;gap:6px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}
.cl input{padding:5px 7px;width:100%;text-align:right}.tot{margin-top:12px}.tot div{display:flex;justify-content:space-between;padding:3px 0}
.tot .big{font-size:20px;font-weight:700;border-top:1px solid var(--line);margin-top:6px;padding-top:8px}
.ln{display:grid;grid-template-columns:1fr 80px 110px 30px;gap:6px;margin:5px 0}
.cartp input,.cartp select{width:100%}
.chart{width:100%;height:auto}.chart text{fill:var(--mut);font-size:11px}.chart .gl{stroke:var(--line)}
.chart .ln1{stroke:var(--c1)}.chart .ln2{stroke:var(--c2)}.chart path{fill:none;stroke-width:2.5;stroke-linejoin:round;stroke-linecap:round}.chart .ar{fill:var(--c1);opacity:.1;stroke:none}
.chart circle.d1{fill:var(--c1)}.chart circle.d2{fill:var(--c2)}.lgd{display:flex;gap:14px;font-size:12px;color:var(--mut);margin-bottom:6px}.lgd i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:middle}
.hbs{display:flex;flex-direction:column;gap:9px}.hb{display:grid;grid-template-columns:130px 1fr 90px;gap:10px;align-items:center;font-size:13px}
.hl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hbar{background:var(--ice);height:8px;border-radius:980px;overflow:hidden}.hbar i{display:block;height:100%;background:var(--c1);border-radius:980px}
.hbar i.c2{background:var(--c2)}.hbar i.c3{background:var(--c3)}.hb b{text-align:right;font-weight:600}
.don{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.don svg{width:130px;height:130px}.don circle{fill:none}.dc{font-size:22px;font-weight:700;fill:var(--ink)!important}
.leg div{margin:3px 0;font-size:13px}.leg i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.al{padding:12px 16px;border-radius:12px;border-left:4px solid var(--mut);background:var(--panel);box-shadow:var(--sh);margin-bottom:8px;cursor:pointer}
.al.high{border-left-color:var(--bad)}.al.med{border-left-color:var(--warn)}.al.low{border-left-color:var(--ok)}.al:hover{background:var(--hov)}.al b{display:block;font-weight:600}
#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:rgba(40,40,44,.92);color:#fff;padding:11px 20px;border-radius:980px;display:none;z-index:99;max-width:420px;-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px)}#toast.err{background:rgba(215,0,21,.94)}
#banner .note{margin:12px 28px 0}
@media(max-width:1000px){.g2,.g3,.posg{grid-template-columns:1fr}.cartp{position:static}}
@media(max-width:820px){.app{grid-template-columns:1fr}#side{position:fixed;left:-260px;width:250px;z-index:50;transition:left .2s}#side.open{left:0}#burger{display:inline-block}.page{padding:16px}.top{padding:8px 14px}.me div{display:none}}
@media print{#side,.top,.pa,.bar{display:none!important}.app{display:block}}
/* ---- Liquid Glass layer ---- */
:root{--glass:rgba(255,255,255,.55);--glass2:rgba(255,255,255,.72);--gb:rgba(255,255,255,.75);--gsh:0 8px 32px rgba(40,60,120,.12),inset 0 1px 0 rgba(255,255,255,.9),inset 0 -1px 0 rgba(255,255,255,.25);
--wall:radial-gradient(900px 600px at 8% 0%,#cfe4ff 0,transparent 60%),radial-gradient(800px 600px at 100% 10%,#e9d8ff 0,transparent 60%),radial-gradient(900px 700px at 70% 100%,#ffe3d6 0,transparent 60%),#eef1f8}
[data-theme=dark]{--glass:rgba(44,44,52,.50);--glass2:rgba(58,58,68,.6);--gb:rgba(255,255,255,.14);--gsh:0 8px 32px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.14),inset 0 -1px 0 rgba(255,255,255,.04);
--wall:radial-gradient(900px 600px at 8% 0%,#14284d 0,transparent 60%),radial-gradient(800px 600px at 100% 10%,#2c1a4a 0,transparent 60%),radial-gradient(900px 700px at 70% 100%,#3a1f2a 0,transparent 60%),#05060a}
body{background:var(--wall) fixed}
.app{grid-template-columns:272px 1fr}
#side{margin:14px 0 14px 14px;height:calc(100vh - 28px);top:14px;border-radius:30px;background:var(--glass);border:1px solid var(--gb);box-shadow:var(--gsh);-webkit-backdrop-filter:blur(36px) saturate(190%);backdrop-filter:blur(36px) saturate(190%);padding:20px 12px}
#nav a{border-radius:999px;padding:8px 14px}
#nav a:hover{background:var(--glass2)}
#nav a.on{background:linear-gradient(180deg,color-mix(in srgb,var(--pri) 92%,#fff),var(--pri));color:#fff;box-shadow:0 4px 14px color-mix(in srgb,var(--pri) 45%,transparent),inset 0 1px 0 rgba(255,255,255,.45)}
.top{margin:14px 18px 0;border-radius:999px;padding:8px 14px 8px 18px;background:var(--glass);border:1px solid var(--gb);box-shadow:var(--gsh);-webkit-backdrop-filter:blur(30px) saturate(190%);backdrop-filter:blur(30px) saturate(190%)}
.gs input{background:var(--glass2);border:1px solid var(--gb);border-radius:999px;padding:8px 16px}
.ib{background:var(--glass2);border:1px solid var(--gb);box-shadow:inset 0 1px 0 rgba(255,255,255,.6)}
.page{padding:22px 24px 60px}
.panel,.kpi,.card,.al{background:var(--glass);border:1px solid var(--gb);border-radius:26px;box-shadow:var(--gsh);-webkit-backdrop-filter:blur(26px) saturate(180%);backdrop-filter:blur(26px) saturate(180%)}
.panel{padding:20px}.panel .tw{margin:0 -20px -20px}
.kpi{padding:18px 20px}
th{background:transparent}
tbody tr:hover td{background:var(--glass2)}
.stats div{background:var(--glass2);border:1px solid var(--gb);border-radius:16px}
.b{background:linear-gradient(180deg,color-mix(in srgb,var(--pri) 88%,#fff),var(--pri));box-shadow:0 4px 14px color-mix(in srgb,var(--pri) 38%,transparent),inset 0 1px 0 rgba(255,255,255,.45)}
.b:hover{background:linear-gradient(180deg,var(--pri),var(--pri2))}
.b.g{background:var(--glass2);border:1px solid var(--gb);box-shadow:inset 0 1px 0 rgba(255,255,255,.6);color:var(--pri)}
.b.d{background:color-mix(in srgb,var(--bad) 16%,var(--glass2));box-shadow:none}
.chip{background:var(--glass2);border:1px solid var(--gb);box-shadow:inset 0 1px 0 rgba(255,255,255,.5)}
.chip.on{background:var(--ink);color:var(--panel)}
input,select,textarea{background:var(--glass2);border:1px solid var(--gb);border-radius:14px}
dialog{border-radius:34px;background:var(--glass2);border:1px solid var(--gb);box-shadow:0 30px 90px rgba(0,0,0,.35),inset 0 1px 0 rgba(255,255,255,.7);-webkit-backdrop-filter:blur(40px) saturate(200%);backdrop-filter:blur(40px) saturate(200%)}
.mh{padding:20px 24px 8px}.mb{padding:4px 24px}.acts{padding:14px 24px 22px}
.note{background:color-mix(in srgb,var(--pri) 12%,var(--glass));border:1px solid var(--gb);border-radius:18px}
#gsr{background:var(--glass2);border:1px solid var(--gb);border-radius:20px;-webkit-backdrop-filter:blur(30px);backdrop-filter:blur(30px)}
#toast{background:var(--glass2);color:var(--ink);border:1px solid var(--gb);box-shadow:var(--gsh)}#toast.err{background:color-mix(in srgb,var(--bad) 30%,var(--glass2))}
/* ---- form control polish ---- */
input[type=number]{-moz-appearance:textfield;appearance:textfield}
input[type=number]::-webkit-inner-spin-button,input[type=number]::-webkit-outer-spin-button{-webkit-appearance:none;margin:0}
select{-webkit-appearance:none;-moz-appearance:none;appearance:none;padding-right:34px;cursor:pointer;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'><path d='M2.5 4.5 6 8l3.5-3.5' fill='none' stroke='%238e8e93' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>");background-repeat:no-repeat;background-position:right 13px center;background-size:12px}
input[type=search]::-webkit-search-cancel-button{-webkit-appearance:none;height:14px;width:14px;border-radius:50%;cursor:pointer;background:rgba(142,142,147,.55) url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'><path d='M4.5 4.5l5 5m0-5l-5 5' stroke='white' stroke-width='1.6' stroke-linecap='round'/></svg>")}
input[type=date]{min-height:38px}
input[type=date]::-webkit-calendar-picker-indicator{opacity:.55;cursor:pointer;border-radius:6px}
[data-theme=dark] input[type=date]::-webkit-calendar-picker-indicator{filter:invert(1)}
input[type=checkbox],input[type=radio]{accent-color:var(--pri)}
/* ---- number stepper + scrollbars ---- */
.numw{position:relative;display:inline-block;vertical-align:middle}.mb .numw,.r2 .numw,.r3 .numw{display:block}
.numw input{padding-right:36px}
.stp{position:absolute;right:7px;top:50%;transform:translateY(-50%);display:flex;flex-direction:column;gap:2px}
.stp button{width:22px;height:13px;border:0;padding:0;border-radius:6px;cursor:pointer;background:rgba(142,142,147,.2);display:grid;place-items:center;color:var(--mut);transition:background .12s,color .12s}
.stp button:hover{background:var(--pri);color:#fff}.stp button:active{transform:scale(.92)}
.stp svg{width:9px;height:9px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
::-webkit-scrollbar{width:12px;height:12px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(120,120,128,.38);border:3px solid transparent;background-clip:content-box;border-radius:999px}
::-webkit-scrollbar-thumb:hover{background:rgba(120,120,128,.6);background-clip:content-box;border:3px solid transparent}
::-webkit-scrollbar-corner{background:transparent}
@supports not selector(::-webkit-scrollbar){*{scrollbar-width:thin;scrollbar-color:rgba(120,120,128,.5) transparent}}
@media(max-width:820px){.app{grid-template-columns:1fr}#side{position:fixed;left:-300px;top:0;margin:10px;height:calc(100vh - 20px);width:270px}#side.open{left:0}.top{margin:10px}}
/* ---- chart hover ---- */
.chart{cursor:crosshair;touch-action:pan-y;-webkit-user-select:none;user-select:none}
.chart .xh{stroke:var(--mut);stroke-width:1;stroke-dasharray:4 4;opacity:.7;visibility:hidden;pointer-events:none}
.chart circle.hv{stroke:var(--panel);stroke-width:2.5;visibility:hidden;pointer-events:none}
.chart circle.hv1{fill:var(--c1)}.chart circle.hv2{fill:var(--c2)}
.don circle.seg{cursor:pointer;transition:stroke-width .12s}.don circle.seg:hover{stroke-width:27}
.leg div{cursor:default}
.hb{padding:3px 6px;margin:-3px -6px;border-radius:10px;cursor:default;transition:background .12s}.hb:hover{background:var(--glass2)}
#tip{position:fixed;z-index:120;left:0;top:0;display:none;pointer-events:none;min-width:150px;max-width:280px;padding:10px 13px;border-radius:16px;font-size:12.5px;line-height:1.5;color:var(--ink);
background:color-mix(in srgb,var(--panel) 90%,transparent);border:1px solid var(--gb);box-shadow:0 10px 36px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.4);-webkit-backdrop-filter:blur(24px) saturate(180%);backdrop-filter:blur(24px) saturate(180%)}
#tip .th{font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:7px}
#tip .tr{display:flex;justify-content:space-between;gap:18px;color:var(--mut)}#tip .tr b{color:var(--ink);font-weight:600;white-space:nowrap}
#tip i{display:inline-block;width:9px;height:9px;border-radius:50%;flex:none}#tip .tr i{margin-right:6px}
</style></head><body>
<div class="app">
  <aside id="side"><div class="logo">__APP__<small id="shop"></small></div><nav id="nav"></nav></aside>
  <div class="main">
    <header class="top">
      <button class="ib" id="burger" data-act="burger">Menu</button>
      <div class="gs"><input id="gs" type="search" placeholder="Quick search products (Ctrl+K)" autocomplete="off" style="width:100%"><div id="gsr"></div></div>
      <span class="grow"></span>
      <button class="ib" id="bell" data-act="go" data-id="alerts" style="display:none" title="Risk Center">Alerts <b id="belln">0</b></button>
      <button class="ib" data-act="theme" title="Dark / light">Dark mode</button>
      <div class="me" id="me"></div>
    </header>
    <div id="banner"></div>
    <main id="view" class="page"></main>
  </div>
</div>
<dialog id="dlg"><form id="dform"></form></dialog>
<div id="toast"></div>
<div id="tip"></div>
<script>
'use strict';
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const peso=n=>'₱'+Number(n||0).toLocaleString('en-PH',{maximumFractionDigits:2});
const num=n=>Number(n||0).toLocaleString('en-PH');
const dtm=s=>s?String(s).slice(0,16):'', d10=s=>s?String(s).slice(0,10):'';
const kfmt=v=>v>=1e6?(v/1e6).toFixed(v%1e6?1:0)+'M':v>=1e3?(v/1e3).toFixed(v%1e3?1:0)+'k':String(v);
let ME=null; const ACT={},CHG={},V={},TBL={}; let _tid=0,PC={};
const can=(...r)=>r.includes(ME.role);
const cacheP=l=>{l.forEach(p=>PC[p.id]=p)};

async function api(path,method='GET',body){
  const o={method,headers:{'X-Requested-With':'fetch'}};
  if(method!=='GET'){o.headers['Content-Type']='application/json';o.body=JSON.stringify(body||{})}
  const r=await fetch('/api'+path,o);
  if(r.status===401){location.href='/';throw new Error('Signed out')}
  let d={};try{d=await r.json()}catch(e){}
  if(!r.ok)throw new Error(d.error||'Something went wrong');
  return d;
}
function toast(m,err){const t=$('#toast');t.textContent=m;t.className=err?'err':'';t.style.display='block';clearTimeout(t._t);t._t=setTimeout(()=>t.style.display='none',4200)}
async function run(fn){try{return await fn()}catch(e){toast(e.message,true)}}
function closeModal(){const d=$('#dlg');if(d.open)d.close()}
function modal(title,html,onSubmit,okText,wide){
  const f=$('#dform'); $('#dlg').className=wide?'wide':'';
  f.innerHTML=`<div class="mh"><h3>${title}</h3><button type="button" class="x" data-act="close">×</button></div><div class="mb">${html}</div><div class="acts">${onSubmit?`<button type="button" class="b g" data-act="close">Cancel</button><button type="submit" class="b">${okText||'Save'}</button>`:`<button type="button" class="b g" data-act="close">Close</button>`}</div>`;
  f.onsubmit=ev=>{ev.preventDefault();if(!onSubmit)return;const o=Object.fromEntries(new FormData(f));run(async()=>{const r=await onSubmit(o,f);if(r!==false)closeModal()})};
  if(!$('#dlg').open)$('#dlg').showModal();
}
/* ---------- tiny UI kit ---------- */
const head=(t,sub,act)=>`<div class="ph"><div><h2>${t}</h2>${sub?`<p class="mut">${sub}</p>`:''}</div><div class="pa">${act||''}</div></div>`;
const kpi=(l,v,s,c)=>`<div class="kpi"><div class="l">${l}</div><div class="v ${c||''}">${v}</div>${s?`<div class="s">${s}</div>`:''}</div>`;
const badge=(s,t)=>`<span class="badge ${esc(s)}">${esc(t||s)}</span>`;
const stTxt={OK:'In stock',LOW:'Low stock',OUT:'Out of stock'};
const pbadge=p=>badge(p.status,stTxt[p.status]);
const pname=p=>`<b>${esc(p.brand)}</b> ${esc(p.model)}<div class="sub">${esc(p.sku)} · ${p.hp}HP · ${esc(p.type)}</div>`;
const priceCell=p=>p.promo_price?`<s class="mut">${peso(p.price)}</s> <b class="promo">${peso(p.promo_price)}</b>`:peso(p.price);
const coverCell=p=>p.days_cover==null?'<span class="mut">no sales yet</span>':`<span class="${p.days_cover<p.lead_days?'neg':p.days_cover<p.lead_days*2?'warn':''}">${p.days_cover} days</span>`;
const words=q=>String(q||'').toLowerCase().replace(/hp/g,' ').split(/\s+/).filter(Boolean);
const hay=p=>`${p.brand} ${p.model} ${p.sku} ${p.type} ${p.hp} ${p.location||''}`.toLowerCase();
const sel=(name,opts,cur,extra)=>`<select name="${name}" ${extra||''}>${opts.map(o=>{const [v,t]=Array.isArray(o)?o:[o,o];return `<option value="${esc(v)}" ${String(v)===String(cur)?'selected':''}>${esc(t)}</option>`}).join('')}</select>`;

function dtable(cols,rows,o={}){
  const id='t'+(++_tid);TBL[id]={cols,rows,sort:o.sort??null,dir:o.dir??1,empty:o.empty||'Nothing to show.'};
  return `<div class="tw" id="${id}">${tblHTML(id)}</div>`;
}
function tblHTML(id){
  const t=TBL[id];let rows=t.rows.slice();
  if(t.sort!=null){const g=t.cols[t.sort].s;if(g)rows.sort((a,b)=>{const x=g(a),y=g(b);return (x>y?1:x<y?-1:0)*t.dir})}
  if(!rows.length)return `<div class="empty">${t.empty}</div>`;
  return `<table><thead><tr>${t.cols.map((c,i)=>`<th data-ts="${id}:${i}" class="${c.cls||''} ${c.s?'srt':''}">${c.h}${t.sort===i?(t.dir>0?' ▲':' ▼'):''}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${t.cols.map(c=>`<td class="${c.cls||''}">${c.f(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
const TIP=$('#tip'),LC={};let _lc=0,_hc=null;
const trow=(l,v,c)=>`<div class="tr"><span>${c?`<i style="background:${c}"></i>`:''}${esc(l)}</span><b>${v}</b></div>`;
const fdate=l=>{const d=new Date(l+'T00:00:00');return isNaN(d)?l:d.toLocaleDateString('en-PH',{weekday:'short',month:'short',day:'numeric',year:'numeric'})};

function lineChart(labels,series,counts){
  const W=760,H=230,L=48,R=14,T=14,B=28,iw=W-L-R,ih=H-T-B,id='lc'+(++_lc);
  let mx=Math.max(1,...series.flatMap(s=>s.vals));const p=Math.pow(10,Math.floor(Math.log10(mx))),f=mx/p;mx=(f<=1?1:f<=2?2:f<=5?5:10)*p;
  const x=i=>L+(labels.length>1?i*iw/(labels.length-1):iw/2),y=v=>T+ih-(v/mx)*ih;
  LC[id]={labels,series,counts:counts||null,W,xs:labels.map((_,i)=>x(i)),y};
  let g='';for(let k=0;k<=4;k++){const v=mx*k/4;g+=`<line class="gl" x1="${L}" x2="${W-R}" y1="${y(v)}" y2="${y(v)}"/><text x="${L-6}" y="${y(v)+4}" text-anchor="end">${kfmt(v)}</text>`}
  const st=Math.ceil(labels.length/8);labels.forEach((l,i)=>{if(i%st===0||i===labels.length-1)g+=`<text x="${x(i)}" y="${H-8}" text-anchor="middle">${l.slice(5)}</text>`});
  const paths=series.map((s,si)=>{const d=s.vals.map((v,i)=>`${i?'L':'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
    const area=si===0?`<path class="ar" d="${d}L${x(labels.length-1)},${y(0)}L${x(0)},${y(0)}Z"/>`:'';
    const dots=labels.length>40?'':s.vals.map((v,i)=>`<circle class="d${si+1}" cx="${x(i)}" cy="${y(v)}" r="3"/>`).join('');
    return `${area}<path class="ln${si+1}" d="${d}"/>${dots}`}).join('');
  const hov=`<line class="xh" x1="0" x2="0" y1="${T}" y2="${T+ih}"/>`+series.map((s,si)=>`<circle class="hv hv${si+1}" r="5.5" cx="0" cy="0"/>`).join('');
  return `<div class="lgd">${series.map((s,i)=>`<span><i style="background:var(--c${i+1})"></i>${s.name}</span>`).join('')}</div><svg class="chart" id="${id}" data-lc="${id}" viewBox="0 0 ${W} ${H}">${g}${paths}${hov}</svg>`;
}
function hbars(items,cls,vl){
  const mx=Math.max(1,...items.map(i=>i.value)),tot=items.reduce((a,i)=>a+i.value,0)||1;
  return `<div class="hbs">${items.map(i=>{
    const tip=esc(`<div class="th">${esc(i.title||i.label)}</div>`+trow(vl||'Value',i.text)+trow('Share',Math.round(i.value/tot*100)+'%')+(i.extra||''));
    return `<div class="hb" data-tip="${tip}"><span class="hl">${esc(i.label)}</span><div class="hbar"><i class="${cls||''}" style="width:${Math.max(2,i.value/mx*100)}%"></i></div><b>${i.text}</b></div>`}).join('')}</div>`}
function donut(parts,center,unit){const tot=parts.reduce((a,p)=>a+p.value,0)||1,R=54,C=2*Math.PI*R;let off=0;
  const tip=p=>esc(`<div class="th"><i style="background:${p.color}"></i>${esc(p.label)}</div>`+trow(unit||'Count',p.value)+trow('Share',Math.round(p.value/tot*100)+'%')+(p.extra||''));
  const segs=parts.filter(p=>p.value>0).map(p=>{const len=p.value/tot*C;const s=`<circle class="seg" r="${R}" cx="70" cy="70" style="stroke:${p.color}" stroke-width="22" stroke-dasharray="${len} ${C-len}" stroke-dashoffset="${-off}" transform="rotate(-90 70 70)" data-tip="${tip(p)}"/>`;off+=len;return s}).join('');
  return `<div class="don"><svg viewBox="0 0 140 140">${segs}<text x="70" y="76" text-anchor="middle" class="dc">${center}</text></svg><div class="leg">${parts.map(p=>`<div data-tip="${tip(p)}"><i style="background:${p.color}"></i>${esc(p.label)} <b>${p.value}</b></div>`).join('')}</div></div>`}

/* ---------- chart hover tooltip ---------- */
function tipShow(html,cx,cy,mid){
  if(TIP._h!==html){TIP.innerHTML=html;TIP._h=html}
  TIP.style.display='block';
  const w=TIP.offsetWidth,h=TIP.offsetHeight;
  let x=cx+16,y=mid?cy-h/2:cy+16;
  if(x+w>innerWidth-8)x=cx-w-16;
  x=Math.max(8,x);y=Math.max(8,Math.min(y,innerHeight-h-8));
  TIP.style.left=x+'px';TIP.style.top=y+'px';
}
function tipHide(){
  if(_hc){const xh=$('.xh',_hc);if(xh)xh.style.visibility='hidden';$$('.hv',_hc).forEach(d=>d.style.visibility='hidden');_hc=null}
  TIP.style.display='none';
}
function tipMove(e){
  const t=e.target;if(!t||!t.closest)return;
  const lc=t.closest('svg[data-lc]');
  if(_hc&&_hc!==lc)tipHide();
  if(lc){
    const c=LC[lc.dataset.lc];if(!c||!c.xs.length)return;
    const r=lc.getBoundingClientRect(),k=c.W/r.width,n=c.xs.length;
    const step=n>1?(c.xs[n-1]-c.xs[0])/(n-1):1;
    const i=n>1?Math.max(0,Math.min(n-1,Math.round(((e.clientX-r.left)*k-c.xs[0])/step))):0;
    const px=c.xs[i];_hc=lc;
    const xh=$('.xh',lc);xh.setAttribute('x1',px);xh.setAttribute('x2',px);xh.style.visibility='visible';
    $$('.hv',lc).forEach((d,si)=>{d.setAttribute('cx',px);d.setAttribute('cy',c.y(c.series[si].vals[i]));d.style.visibility='visible'});
    const top=Math.min(...c.series.map(s=>c.y(s.vals[i])));
    tipShow(`<div class="th">${esc(fdate(c.labels[i]))}</div>`+c.series.map((s,si)=>trow(s.name,peso(s.vals[i]),`var(--c${si+1})`)).join('')+(c.counts?trow('Invoices',num(c.counts[i])):''),r.left+px/k,r.top+top/k,true);
    return;
  }
  const el=t.closest('[data-tip]');
  if(el)tipShow(el.dataset.tip,e.clientX,e.clientY);else TIP.style.display='none';
}
document.addEventListener('pointermove',tipMove);
document.addEventListener('pointerdown',tipMove);
document.documentElement.addEventListener('mouseleave',tipHide);
window.addEventListener('scroll',tipHide,{passive:true});

/* ---------- navigation ---------- */
const ALL=['owner','employee','purchasing'],O=['owner'],OE=['owner','employee'],OP=['owner','purchasing'];
const NAV=[['#','Overview'],['dash','Dashboard','◧',ALL],['#','Sell'],['pos','New Sale','＋',OE],['sales','Sales History','☰',OE],['sub','Substitute Finder','⇄',ALL],
 ['#','Stock'],['inv','Inventory','▤',ALL],['low','Restock Radar','◔',ALL],['dead','Dead Stock Recovery','▽',O],
 ['#','Buy'],['reorder','Reorder Simulator','₱',OP],
 ['#','Control'],['rep','Reports','▥',O],['alerts','Risk Center','⚠',O],['audit','Audit Trail','✎',O],['users','Users & Settings','⚙',O]];
function go(t){if(location.hash==='#'+t)render();else location.hash='#'+t}
async function render(){
  const t=(location.hash||'#dash').slice(1);const n=NAV.find(x=>x[0]===t&&x[0]!=='#'&&x[3].includes(ME.role));const tab=n?t:'dash';
  $$('#nav a').forEach(a=>a.classList.toggle('on',a.dataset.id===tab));$('#side').classList.remove('open');
  tipHide();$('#view').innerHTML='<div class="load">Loading…</div>';window.scrollTo(0,0);
  try{await V[tab]()}catch(e){$('#view').innerHTML=`<div class="panel"><b>Could not load this page.</b><p class="mut">${esc(e.message)}</p></div>`}
}
window.addEventListener('hashchange',render);
document.addEventListener('click',e=>{
  const th=e.target.closest('th[data-ts]');
  if(th){const [id,i]=th.dataset.ts.split(':');const t=TBL[id];if(!t||!t.cols[i].s)return;if(t.sort==+i)t.dir*=-1;else{t.sort=+i;t.dir=1}$('#'+id).innerHTML=tblHTML(id);return}
  const b=e.target.closest('[data-act]');
  if(b&&ACT[b.dataset.act]){e.preventDefault();run(()=>ACT[b.dataset.act](b.dataset.id,b,e))}
  if(!e.target.closest('.gs'))$('#gsr').style.display='none';
});
document.addEventListener('change',e=>{const el=e.target.closest('[data-chg]');if(el&&CHG[el.dataset.chg])run(()=>CHG[el.dataset.chg](el,e))});
Object.assign(ACT,{
  go:id=>go(id),close:()=>closeModal(),burger:()=>$('#side').classList.toggle('open'),
  theme:()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;try{localStorage.setItem('cs-theme',t)}catch(e){}},
  logout:async()=>{await api('/logout','POST');location.href='/'},
  pw:()=>modal('Change my password',`<label>Current password</label><input name="old" type="password" required autocomplete="current-password"><label>New password (min 6 characters)</label><input name="new" type="password" minlength="6" required autocomplete="new-password">`,
    async o=>{await api('/password','POST',o);toast('Password changed');$('#banner').innerHTML=''},'Change password'),
});

/* ---------- global search ---------- */
let gst;
$('#gs').addEventListener('input',e=>{clearTimeout(gst);const q=e.target.value.trim();if(!q){$('#gsr').style.display='none';return}
  gst=setTimeout(()=>run(async()=>{const ps=await api('/products?limit=7&q='+encodeURIComponent(q));cacheP(ps);const b=$('#gsr');
    b.innerHTML=ps.length?ps.map(p=>`<a data-act="detail" data-id="${p.id}"><span>${pname(p)}</span><span style="text-align:right">${priceCell(p)}<div class="sub">${p.available} available</div></span></a>`).join(''):'<div class="empty">No match</div>';b.style.display='block'}),180)});
$('#gs').addEventListener('keydown',e=>{if(e.key==='Escape'){$('#gsr').style.display='none';e.target.blur()}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();$('#gs').focus();$('#gs').select()}});

/* ---------- product detail & forms ---------- */
ACT.detail=async id=>{
  $('#gsr').style.display='none';
  const d=await api('/products/'+id+'/detail'),p=d.product,cost=can('owner','purchasing');
  const mrg=cost&&p.price?`${Math.round((p.eff_price-p.cost)/p.eff_price*100)}%`:'';
  modal(esc(p.brand+' '+p.model),`<div class="sub" style="margin-bottom:6px">${esc(p.sku)} · ${p.hp}HP · ${esc(p.type)} · shelf ${esc(p.location||'-')} · warranty ${p.warranty_months} mo</div>
   <div class="stats"><div><small>On hand</small><b>${p.qty}</b></div><div><small>Available</small><b>${p.available}</b></div>
   <div><small>Sold (30 days)</small><b>${d.sold_30}</b></div><div><small>Avg / day</small><b>${p.per_day}</b></div><div><small>Days of cover</small><b>${p.days_cover==null?'-':p.days_cover}</b></div><div><small>Reorder point</small><b>${p.rop}</b></div>
   <div><small>Suggested order</small><b>${p.suggest_qty}</b></div><div><small>Price</small><b>${priceCell(p)}</b></div>${cost?`<div><small>Unit cost</small><b>${peso(p.cost)}</b></div><div><small>Margin</small><b>${mrg}</b></div>`:''}
   <div><small>Last sale</small><b style="font-size:13px">${d10(d.last_sale)||'never'}</b></div></div>
   <h3 style="font-size:14px;margin:14px 0 4px">Stock card (latest 25 movements)</h3>${dtable([
    {h:'When',f:r=>dtm(r.ts)},{h:'Type',f:r=>badge(r.kind)},{h:'Qty',cls:'r',f:r=>`<b class="${r.delta<0?'neg':'pos'}">${r.delta>0?'+':''}${r.delta}</b>`},{h:'Note',cls:'wrap',f:r=>esc(r.note)},{h:'By',f:r=>esc(r.user)}],d.movements)}`,null,'',true);
};
ACT.add=()=>productForm();
ACT.edit=id=>productForm(PC[id]);
async function productForm(p){
  const v=k=>esc(p?(p[k]??''):'');
  modal(p?'Edit product':'Add product',`<div class="r2"><div><label>SKU</label><input name="sku" required value="${v('sku')}"></div><div><label>Brand</label><input name="brand" required value="${v('brand')}"></div></div>
   <label>Model</label><input name="model" required value="${v('model')}">
   <div class="r3"><div><label>Horsepower (HP)</label><input name="hp" type="number" step="0.25" min="0.25" required value="${v('hp')}"></div>
   <div><label>Type</label>${sel('type',['Window','Window Inverter','Split','Split Inverter','Floor Standing','Cassette','Portable'],p?p.type:'Split Inverter')}</div>
   <div><label>Shelf / location</label><input name="location" value="${v('location')}"></div></div>
   <div class="r3"><div><label>Unit cost (₱)</label><input name="cost" type="number" step="0.01" min="0" required value="${v('cost')}"></div>
   <div><label>Selling price (₱)</label><input name="price" type="number" step="0.01" min="0" required value="${v('price')}"></div>
   <div><label>Promo price (optional)</label><input name="promo_price" type="number" step="0.01" min="0" value="${v('promo_price')}"></div></div>
   <div class="r3"><div><label>Minimum quantity</label><input name="min_qty" type="number" min="0" required value="${p?p.min_qty:2}"></div>
   <div><label>Warranty (months)</label><input name="warranty_months" type="number" min="0" value="${p?p.warranty_months:12}"></div>
   ${p?'<div></div>':'<div><label>Opening stock</label><input name="qty" type="number" min="0" value="0"></div>'}</div>
   ${p?'<p class="sub">Quantity changes only through stock-in, sales, stock-out and counts so everything is traceable. Price and cost edits are written to the audit trail.</p>':''}`,
   async o=>{await api(p?'/products/'+p.id:'/products',p?'PUT':'POST',o);toast('Saved');drawInvRefresh()},'Save product');
}
ACT.archive=async id=>{const p=PC[id];if(!confirm(`Archive ${p.brand} ${p.model}? History is kept; it just disappears from lists.`))return;await api('/products/'+id,'DELETE');toast('Archived');drawInvRefresh()};
ACT.stockin=id=>{const p=PC[id];modal('Stock in: '+esc(p.brand+' '+p.model),`<p class="sub">On hand ${p.qty} · available ${p.available}</p>
  <label>Quantity received</label><input name="qty" type="number" min="1" required autofocus><label>Supplier / delivery receipt no.</label><input name="note" required placeholder="Required for the audit trail">`,
  async o=>{await api('/movements','POST',{product_id:p.id,kind:'IN',...o});toast('Stock received');drawInvRefresh()},'Record stock in')};
ACT.stockout=id=>{const p=PC[id];modal('Stock out (not a sale): '+esc(p.brand+' '+p.model),`<div class="note">For customer sales use <b>New Sale</b>. Use this only for damage, display units, transfers or losses. Every stock-out is flagged in the Risk Center.</div>
  <p class="sub">On hand ${p.qty} · available ${p.available}</p><label>Quantity</label><input name="qty" type="number" min="1" max="${p.available}" required>
  <label>Reason</label>${sel('reason',ME.out_reasons,'')}<label>Details</label><input name="note" required placeholder="What happened?">`,
  async o=>{await api('/movements','POST',{product_id:p.id,kind:'OUT',...o});toast('Stock-out recorded');drawInvRefresh()},'Record stock-out')};
ACT.promoclear=async id=>{await api('/promo','POST',{items:[{product_id:+id,price:null}]});toast('Promo cleared');drawInvRefresh()};

/* ---------- dashboard ---------- */
V.dash=async()=>{
  const d=await api('/dashboard'),o=can('owner'),p=ME.role==='purchasing',e=ME.role==='employee';cacheP(d.low);
  const k=[];
  if(o)k.push(kpi('Sales today',peso(d.today_revenue),d.today_count+' invoice(s)'),kpi('This month',peso(d.month_revenue),d.month_count+' invoices · profit '+peso(d.month_profit),'pos'));
  else if(!p)k.push(kpi('My sales today',peso(d.my_today),d.my_today_count+' invoice(s)'));
  k.push(kpi('Units on hand',num(d.units),d.models+' models'));
  k.push(kpi('Restock needed',d.low_count,d.out_count+' out of stock · '+d.soon_count+' running low soon',d.low_count?'neg':''));
  if(d.value!==undefined)k.push(kpi('Inventory value (cost)',peso(d.value)));
  if(o)k.push(kpi('Dead-stock capital',peso(d.dead_capital),d.dead_count+' model(s) idle 90+ days'),kpi('Risk alerts',d.alerts,'Open the Risk Center',d.alerts?'warn':''));
  const notes=(d.models?'':(o?`<div class="note"><b>Your shop has no stock yet.</b> Add your first product to start selling. <button class="b sm" data-act="add">Add product</button></div>`:`<div class="note"><b>No stock yet.</b> The shop owner needs to add products before anything can be sold.</div>`))
   +(o&&d.pending_users?`<div class="note bad"><b>${d.pending_users} staff request(s)</b> waiting for your approval. <button class="b sm" data-act="go" data-id="users">Review</button></div>`:'');
  const ser=[{name:e?'My revenue':'Revenue',vals:d.series.revenue}];if(d.series.profit)ser.push({name:'Gross profit',vals:d.series.profit});
  $('#view').innerHTML=head('Dashboard','',can('owner','employee')?`<button class="b" data-act="go" data-id="pos">＋ New sale</button>`:`<button class="b" data-act="go" data-id="reorder">Plan restock</button>`)+
   `${notes}<div class="kpis">${k.join('')}</div>
   <div class="g3"><div class="panel"><h3>${e?'My sales':'Sales'} · last 14 days</h3>${lineChart(d.series.labels,ser,d.series.count)}</div>
   <div class="panel"><h3>Stock health</h3>${donut([{label:'In stock',value:d.ok_count,color:'var(--ok)'},{label:'Low',value:d.low_count-d.out_count,color:'var(--warn)'},{label:'Out',value:d.out_count,color:'var(--bad)'}],d.models,'Models')}
   <h3 style="margin-top:18px">Best sellers · 30 days</h3>${d.top.length?hbars(d.top.map(t=>({label:t.label.split(' - ')[1]||t.label,title:t.label,value:t.units,text:t.units+' unit(s)',extra:trow('Revenue',peso(t.revenue))})),'c2','Units sold'):'<p class="mut">No sales yet.</p>'}</div></div>
   <div class="g2"><div class="panel"><h3>Needs restocking</h3>${dtable([{h:'Product',f:r=>pname(r)},{h:'Avail.',cls:'r',f:r=>r.available},{h:'Cover',f:r=>coverCell(r)},{h:'Status',f:r=>pbadge(r)}],d.low,{empty:'Everything is above its minimum.'})}</div>
   <div class="panel"><h3>Recent activity</h3>${dtable([{h:'When',f:r=>dtm(r.ts).slice(5)},{h:'Item',cls:'wrap',f:r=>esc(r.label.split(' - ')[1]||r.label)},{h:'Type',f:r=>badge(r.kind)},{h:'Qty',cls:'r',f:r=>`<b class="${r.delta<0?'neg':'pos'}">${r.delta>0?'+':''}${r.delta}</b>`},{h:'By',f:r=>esc(r.user)}],d.recent)}</div></div>`;
};

/* ---------- inventory ---------- */
let INV={q:'',st:'ALL',brand:'',type:''},INVL=[];
V.inv=async()=>{
  INVL=await api('/products');cacheP(INVL);
  const brands=[...new Set(INVL.map(p=>p.brand))].sort(),types=[...new Set(INVL.map(p=>p.type))].sort();
  const chips=[['ALL','All'],['OK','In stock'],['LOW','Low'],['OUT','Out'],['SOON','Reorder soon'],['PROMO','On promo']];
  $('#view').innerHTML=head('Inventory','Search by brand, model, SKU, HP or shelf.',`${can('owner')?'<button class="b" data-act="add">+ Add product</button>':''}`)+
   `<div class="bar"><input type="search" id="iq" placeholder='Try "lg 1.5", "carrier window", "B1" …' value="${esc(INV.q)}">
   ${chips.map(c=>`<button class="chip ${INV.st===c[0]?'on':''}" data-act="invst" data-id="${c[0]}">${c[1]}</button>`).join('')}
   <select id="ib">${[['','All brands'],...brands].map(b=>{const [v,t]=Array.isArray(b)?b:[b,b];return `<option value="${esc(v)}" ${INV.brand===v?'selected':''}>${esc(t)}</option>`}).join('')}</select>
   <select id="it">${[['','All types'],...types].map(b=>{const [v,t]=Array.isArray(b)?b:[b,b];return `<option value="${esc(v)}" ${INV.type===v?'selected':''}>${esc(t)}</option>`}).join('')}</select></div><div class="panel" id="invt"></div>`;
  $('#iq').oninput=e=>{INV.q=e.target.value;drawInv()};$('#ib').onchange=e=>{INV.brand=e.target.value;drawInv()};$('#it').onchange=e=>{INV.type=e.target.value;drawInv()};
  drawInv();
};
ACT.invst=id=>{INV.st=id;$$('.chip').forEach(c=>c.classList.toggle('on',c.dataset.id===id));drawInv()};
async function drawInvRefresh(){if((location.hash||'#dash')==='#inv'){INVL=await api('/products');cacheP(INVL);drawInv()}else render()}
function drawInv(){
  const w=words(INV.q),cost=can('owner','purchasing');
  const rows=INVL.filter(p=>(INV.st==='ALL'||(INV.st==='SOON'?p.reorder_soon:INV.st==='PROMO'?!!p.promo_price:p.status===INV.st))&&(!INV.brand||p.brand===INV.brand)&&(!INV.type||p.type===INV.type)&&w.every(x=>hay(p).includes(x)));
  const cols=[{h:'Product',f:p=>pname(p).replace('</div>',` · shelf ${esc(p.location||'-')}</div>`),s:p=>p.brand+p.model},{h:'On hand',cls:'r',f:p=>p.qty,s:p=>p.qty},
   {h:'Available',cls:'r',f:p=>`<b>${p.available}</b>`,s:p=>p.available},{h:'Cover',f:coverCell,s:p=>p.days_cover==null?9999:p.days_cover}];
  if(cost)cols.push({h:'Cost',cls:'r',f:p=>peso(p.cost),s:p=>p.cost});
  cols.push({h:'Price',cls:'r',f:priceCell,s:p=>p.eff_price},{h:'Status',f:p=>pbadge(p)+(p.reorder_soon?' <span class="sub">reorder soon</span>':''),s:p=>p.status},
   {h:'',cls:'act',f:p=>`<button class="b sm g" data-act="detail" data-id="${p.id}">Details</button>${can('owner','purchasing')?`<button class="b sm" data-act="stockin" data-id="${p.id}">Stock in</button>`:''}${can('owner','employee')?`<button class="b sm g" data-act="stockout" data-id="${p.id}">Stock out</button>`:''}${can('owner')?`<button class="b sm g" data-act="edit" data-id="${p.id}">Edit</button>${p.qty===0?`<button class="b sm d" data-act="archive" data-id="${p.id}">Archive</button>`:''}`:''}`});
  $('#invt').innerHTML=`<div class="sub" style="margin-bottom:8px">${rows.length} of ${INVL.length} models · click a column header to sort</div>`+dtable(cols,rows,{empty:INVL.length?'No matching products.':(can('owner')?'No products yet. Click "+ Add product" to add your first one.':'The shop owner has not added any stock yet.')});
}

/* ---------- point of sale ---------- */
let CART=[],PRE=null,POSP=[],POSQ='',POSF={customer:'',phone:'',payment:'Cash',note:''};
V.pos=async()=>{
  const ps=await api('/products');POSP=ps;cacheP(ps);
  $('#view').innerHTML=head('New Sale','Add items to the cart, then print the invoice.')+
   `<div class="posg"><div class="panel"><input type="search" id="pq" style="width:100%" placeholder="Scan SKU or type brand, model, HP…" value="${esc(POSQ)}"><div id="plist"></div></div><div class="panel cartp" id="cartbox"></div></div>`;
  $('#pq').oninput=e=>{POSQ=e.target.value;drawPList()};
  $('#pq').onkeydown=e=>{if(e.key==='Enter'){const m=POSP.filter(p=>p.sku.toLowerCase()===POSQ.trim().toLowerCase()||(words(POSQ).length&&words(POSQ).every(w=>hay(p).includes(w))&&p.available>0));if(m.length===1){ACT.padd(m[0].id);POSQ='';e.target.value='';drawPList()}}};
  $('#pq').focus();drawPList();drawCart();
};
function drawPList(){
  const w=words(POSQ),rows=POSP.filter(p=>w.every(x=>hay(p).includes(x))).slice(0,60);
  $('#plist').innerHTML=rows.map(p=>`<div class="pi ${p.available<=0?'dis':''}"><div>${pname(p)}</div><div style="text-align:right;white-space:nowrap">${priceCell(p)}<div class="sub">${p.available>0?p.available+' available':'out of stock'}</div></div>
   <div>${p.available>0?`<button class="b sm" data-act="padd" data-id="${p.id}">Add</button>`:`<button class="b sm g" data-act="subfor" data-id="${p.id}">Alternatives</button>`}</div></div>`).join('')||'<div class="empty">No matching products.</div>';
}
ACT.padd=id=>{const p=PC[id],held=PRE&&PRE.product_id==p.id?PRE.qty:0,max=p.available+held,ex=CART.find(i=>i.id==p.id);
  if(ex){if(ex.qty<ex.max)ex.qty++;else return toast('No more units available.',true)}else{if(max<=0)return toast('Out of stock.',true);CART.push({id:p.id,label:p.brand+' '+p.model,sku:p.sku,list:p.eff_price,unit:p.eff_price,qty:1,max,cost:p.cost})}
  drawCart()};
ACT.subfor=id=>{SUBID=id;go('sub')};
ACT.prm=i=>{CART.splice(+i,1);drawCart()};
CHG.cartq=el=>{const it=CART[+el.dataset.id];it.qty=Math.max(1,Math.min(parseInt(el.value)||1,it.max));drawCart()};
CHG.cartp=el=>{CART[+el.dataset.id].unit=Math.max(0,parseFloat(el.value)||0);drawCart()};
CHG.posf=el=>{POSF[el.name]=el.value};
function drawCart(){
  const tot=CART.reduce((a,i)=>a+i.unit*i.qty,0),list=CART.reduce((a,i)=>a+i.list*i.qty,0),dep=0,lim=ME.max_emp_discount;
  const lines=CART.map((i,ix)=>{let w='';const off=i.list?1-i.unit/i.list:0;
    if(i.cost!==undefined&&i.unit<i.cost)w=`<div class="sub neg">Below cost${can('owner')?' (owner override)':' - owner must approve'}</div>`;
    else if(!can('owner')&&off>lim+.0005)w=`<div class="sub neg">Over ${Math.round(lim*100)}% discount - owner approval needed</div>`;
    else if(off>.0005)w=`<div class="sub warn">${(off*100).toFixed(1)}% off list</div>`;
    return `<div class="cl"><div><b>${esc(i.label)}</b><div class="sub">${esc(i.sku)} · list ${peso(i.list)}</div>${w}</div><input type="number" min="1" max="${i.max}" value="${i.qty}" data-chg="cartq" data-id="${ix}"><input type="number" min="0" step="0.01" value="${i.unit}" data-chg="cartp" data-id="${ix}"><button class="x" data-act="prm" data-id="${ix}">×</button></div>`}).join('');
  const profit=can('owner')&&CART.length?CART.reduce((a,i)=>a+(i.unit-i.cost)*i.qty,0):null;
  $('#cartbox').innerHTML=`<h3>Current sale</h3>
   <div class="r2"><div><label>Customer</label><input name="customer" data-chg="posf" value="${esc(POSF.customer)}" placeholder="Walk-in"></div><div><label>Phone</label><input name="phone" data-chg="posf" value="${esc(POSF.phone)}"></div></div>
   <label>Payment method</label>${sel('payment',ME.payments,POSF.payment,'data-chg="posf"')}
   <div style="margin-top:12px">${lines||'<div class="empty">Cart is empty. Add a product from the list.</div>'}</div>
   <div class="tot"><div><span class="mut">List total</span><span>${peso(list)}</span></div><div><span class="mut">Discount</span><span>${peso(list-tot)}</span></div>
   ${profit!==null?`<div><span class="mut">Est. profit</span><span class="${profit<0?'neg':'pos'}">${peso(profit)}</span></div>`:''}<div class="big"><span>Amount due</span><span>${peso(tot-dep)}</span></div></div>
   <button class="b" style="width:100%;margin-top:14px;padding:12px" data-act="pay" ${CART.length?'':'disabled'}>Complete sale</button>
   ${CART.length?`<button class="b g" style="width:100%;margin-top:8px" data-act="clearcart">Clear cart</button>`:''}`;
}
ACT.clearcart=()=>{CART=[];PRE=null;POSF.res='';drawCart()};
ACT.pay=async()=>{
  const r=await api('/sales','POST',{customer:POSF.customer,phone:POSF.phone,payment:POSF.payment,items:CART.map(i=>({product_id:i.id,qty:i.qty,price:i.unit}))});
  CART=[];PRE=null;POSF={customer:'',phone:'',payment:'Cash',note:''};
  modal('Sale complete',`<div class="note"><b>${esc(r.invoice_no)}</b> · total ${peso(r.total)}</div><p>Stock was deducted and the sale was added to the ledger.</p>
   <p><a class="b" href="/invoice/${r.id}" target="_blank">Print invoice</a></p>`,null);
  await V.pos();
};

/* ---------- sales history ---------- */
let SF={from:'',to:'',status:'',q:'',user:''},SALES=[];
V.sales=async()=>{
  const users=can('owner')?await api('/users'):[];
  $('#view').innerHTML=head('Sales History',ME.role==='employee'?'Your invoices only.':'All invoices.')+
   `<div class="bar"><input type="search" id="sq" placeholder="Invoice no. or customer" value="${esc(SF.q)}"><label style="margin:0">From</label><input type="date" id="sfrom" value="${SF.from}"><label style="margin:0">To</label><input type="date" id="sto" value="${SF.to}">
   <select id="sst"><option value="">All statuses</option><option value="PAID" ${SF.status==='PAID'?'selected':''}>Paid</option><option value="VOID" ${SF.status==='VOID'?'selected':''}>Void</option></select>
   ${can('owner')?`<select id="su"><option value="">All cashiers</option>${users.map(u=>`<option value="${esc(u.username)}" ${SF.user===u.username?'selected':''}>${esc(u.name)}</option>`).join('')}</select>`:''}</div><div class="panel" id="sl"></div>`;
  const ch=()=>{SF={q:$('#sq').value,from:$('#sfrom').value,to:$('#sto').value,status:$('#sst').value,user:$('#su')?$('#su').value:''};run(loadSales)};
  ['#sq','#sfrom','#sto','#sst','#su'].forEach(s=>{const el=$(s);if(el)el.onchange=ch});$('#sq').oninput=()=>{clearTimeout(window._sq);window._sq=setTimeout(ch,250)};
  await loadSales();
};
async function loadSales(){
  const qs=Object.entries(SF).filter(([k,v])=>v).map(([k,v])=>k+'='+encodeURIComponent(v)).join('&');SALES=await api('/sales?'+qs);
  const paid=SALES.filter(s=>s.status==='PAID'),cost=can('owner');
  const cols=[{h:'Invoice',f:s=>`<b>${esc(s.invoice_no)}</b>`,s:s=>s.invoice_no},{h:'Date',f:s=>dtm(s.ts),s:s=>s.ts},{h:'Customer',f:s=>esc(s.customer),s:s=>s.customer},{h:'Items',cls:'wrap',f:s=>esc(s.items)},{h:'Payment',f:s=>esc(s.payment)},{h:'Cashier',f:s=>esc(s.user),s:s=>s.user},
   {h:'Total',cls:'r',f:s=>peso(s.total),s:s=>s.total}];
  if(cost)cols.push({h:'Profit',cls:'r',f:s=>`<span class="${s.profit<0?'neg':''}">${peso(s.profit)}</span>`,s:s=>s.profit});
  cols.push({h:'Status',f:s=>badge(s.status)},{h:'',cls:'act',f:s=>`<button class="b sm g" data-act="sview" data-id="${s.id}">View</button><a class="b sm" href="/invoice/${s.id}" target="_blank">Print</a>${can('owner')&&s.status==='PAID'?`<button class="b sm d" data-act="svoid" data-id="${s.id}">Void</button>`:''}`});
  $('#sl').innerHTML=`<div class="sub" style="margin-bottom:8px">${SALES.length} invoice(s) · paid total <b>${peso(paid.reduce((a,s)=>a+s.total,0))}</b></div>`+dtable(cols,SALES,{sort:1,dir:-1,empty:'No sales match these filters.'});
}
ACT.sview=async id=>{const s=await api('/sales/'+id);modal(esc(s.invoice_no)+' '+badge(s.status),`<p class="sub">${dtm(s.ts)} · ${esc(s.customer)} ${esc(s.phone||'')} · ${esc(s.payment)} · cashier ${esc(s.user)}</p>
  ${dtable([{h:'Item',cls:'wrap',f:i=>esc(i.label)},{h:'Qty',cls:'r',f:i=>i.qty},{h:'Unit price',cls:'r',f:i=>peso(i.unit_price)},{h:'List',cls:'r',f:i=>peso(i.list_price)},{h:'Amount',cls:'r',f:i=>peso(i.qty*i.unit_price)}],s.items)}
  <div class="tot"><div><span>Total</span><b>${peso(s.total)}</b></div>${s.profit!==undefined?`<div><span>Profit</span><span>${peso(s.profit)}</span></div>`:''}</div>
  ${s.status==='VOID'?`<div class="note bad"><b>Voided</b> by ${esc(s.void_by)} on ${dtm(s.void_ts)}: ${esc(s.void_reason)}</div>`:''}<p><a class="b" href="/invoice/${s.id}" target="_blank">Print invoice</a></p>`,null,'',true)};
ACT.svoid=id=>{const s=SALES.find(x=>x.id==id);modal('Void '+esc(s.invoice_no),`<div class="note bad">Voiding returns the units to stock and cannot be undone. It is recorded against your name.</div><label>Reason</label><input name="reason" required autofocus placeholder="e.g. customer cancelled, wrong model">`,
  async o=>{await api('/sales/'+id+'/void','POST',o);toast('Sale voided, stock restored');loadSales()},'Void sale')};

/* ---------- restock radar ---------- */
V.low=async()=>{
  const ps=await api('/lowstock');cacheP(ps);
  $('#view').innerHTML=head('Restock Radar','Products below minimum stock, or likely to run out before a new order arrives.',can('owner','purchasing')?`<button class="b" data-act="go" data-id="reorder">Plan purchase</button>`:'')+
   `<div class="note"><b>How it works:</b> <i>Days of cover</i> = available ÷ average daily sales (last 90 days). <i>Reorder point</i> = sales during the delivery lead time + minimum quantity.</div>
   <div class="panel">${dtable([{h:'Product',f:pname,s:p=>p.brand+p.model},{h:'Avail.',cls:'r',f:p=>`<b>${p.available}</b>`,s:p=>p.available},{h:'Min',cls:'r',f:p=>p.min_qty},
    {h:'Sales/day',cls:'r',f:p=>p.per_day},{h:'Cover',f:coverCell,s:p=>p.days_cover==null?9999:p.days_cover},{h:'Reorder pt',cls:'r',f:p=>p.rop},{h:'Suggested qty',cls:'r',f:p=>`<b>${p.suggest_qty}</b>`,s:p=>p.suggest_qty},{h:'Lead time',f:p=>p.lead_days+' days'},
    {h:'Status',f:p=>p.status!=='OK'?pbadge(p):badge('ORDERED','Reorder soon')}],ps,{empty:'Nothing needs restocking.'})}</div>`;
};

/* ---------- reorder simulator ---------- */
let LASTPLAN=[],RB={budget:150000,strategy:'urgent'};
V.reorder=async()=>{
  $('#view').innerHTML=head('Budget-Aware Reorder Simulator','Enter a budget to get a suggested purchase list based on stock cover, delivery lead time.')+
   `<div class="panel"><div class="bar" style="margin:0"><label style="margin:0">Budget (₱)</label><input id="bg" type="number" min="0" step="1000" value="${RB.budget}" style="width:150px">
   <label style="margin:0">Priority</label><select id="st"><option value="urgent" ${RB.strategy==='urgent'?'selected':''}>Most urgent first (avoid stock-outs)</option><option value="profit" ${RB.strategy==='profit'?'selected':''}>Highest profit potential</option><option value="balanced" ${RB.strategy==='balanced'?'selected':''}>Balanced</option></select>
   <button class="b" data-act="sim">Simulate</button></div></div><div id="simout"></div>`;
  await ACT.sim();
};
ACT.sim=async()=>{
  RB={budget:$('#bg').value,strategy:$('#st').value};const d=await api('/reorder','POST',RB);LASTPLAN=d.plan;
  $('#simout').innerHTML=`<div class="kpis">${kpi('Budget',peso(d.budget))}${kpi('Planned spend',peso(d.spent),d.plan.length+' product(s)')}${kpi('Left over',peso(d.left))}${kpi('Expected revenue',peso(d.exp_revenue),'if all units sell')}${kpi('Expected profit',peso(d.exp_profit),'','pos')}</div>
   <div class="panel"><h3>Purchase plan</h3>${dtable([{h:'Product',f:pname},{h:'Why',cls:'wrap',f:p=>esc(p.why)},{h:'Avail.',cls:'r',f:p=>p.available},{h:'Target',cls:'r',f:p=>p.target},{h:'Buy',cls:'r',f:p=>`<b>${p.buy}</b>`},{h:'Unit cost',cls:'r',f:p=>peso(p.cost)},{h:'Line total',cls:'r',f:p=>peso(p.spend)},{h:'Coverage',f:p=>p.full?badge('OK','Fully covered'):badge('LOW','Partial (budget)')}],d.plan,{empty:'The budget is too small to buy any needed unit, or nothing needs restocking.'})}
   </div>
   ${d.skipped.length?`<div class="panel"><h3>Still needs restocking (not affordable)</h3>${dtable([{h:'Product',f:pname},{h:'Why',cls:'wrap',f:p=>esc(p.why)},{h:'Needed',cls:'r',f:p=>p.need},{h:'Unit cost',cls:'r',f:p=>peso(p.cost)}],d.skipped)}</div>`:''}`;
};

/* ---------- dead stock ---------- */
let DDAYS=60,DEAD=[];
V.dead=async()=>{
  $('#view').innerHTML=head('Dead Stock Recovery Planner','Slow-moving products, the money tied up in them, and suggested promo prices.')+
   `<div class="bar"><label style="margin:0">Show products unsold for at least</label><select id="dd">${[30,60,90,120,180].map(d=>`<option ${d==DDAYS?'selected':''}>${d}</option>`).join('')}</select> days</div><div id="dout"></div>`;
  $('#dd').onchange=e=>{DDAYS=+e.target.value;run(loadDead)};await loadDead();
};
async function loadDead(){
  const d=await api('/deadstock?days='+DDAYS);DEAD=d.items;
  $('#dout').innerHTML=`<div class="kpis">${kpi('Slow-moving models',d.items.length)}${kpi('Capital tied up (cost)',peso(d.tied_capital),'',d.tied_capital?'warn':'')}</div>
   <div class="panel">${dtable([{h:'Product',f:pname},{h:'Units',cls:'r',f:p=>p.qty},{h:'Idle',cls:'r',f:p=>`<b class="neg">${p.idle_days}d</b>`,s:p=>p.idle_days},{h:'Capital tied',cls:'r',f:p=>peso(p.tied_capital),s:p=>p.tied_capital},{h:'Price now',cls:'r',f:priceCell},
    {h:'Suggested',cls:'r',f:p=>`<b>${peso(p.suggested_price)}</b> <span class="sub">(-${p.suggested_discount}%)</span>`},{h:'Margin/unit',cls:'r',f:p=>peso(p.margin_after)},{h:'Action',cls:'wrap',f:p=>esc(p.action)},
    {h:'',f:p=>p.promo_price?`<button class="b sm g" data-act="promoclear2" data-id="${p.id}">Clear promo</button>`:`<button class="b sm" data-act="promoapply" data-id="${p.id}">Apply promo</button>`}],d.items,{empty:'No slow-moving stock for this period.'})}
   ${d.items.length?`<div style="padding-top:14px;text-align:right"><button class="b" data-act="promoall">Apply all suggested promos</button></div>`:''}<p class="sub" style="margin-top:10px">Suggested prices never go below cost + 2%. Applied promos show on the New Sale screen automatically.</p></div>`;
}
ACT.promoapply=async id=>{const p=DEAD.find(x=>x.id==id);await api('/promo','POST',{items:[{product_id:p.id,price:p.suggested_price}]});toast('Promo applied: '+peso(p.suggested_price));loadDead()};
ACT.promoclear2=async id=>{await api('/promo','POST',{items:[{product_id:+id,price:null}]});toast('Promo cleared');loadDead()};
ACT.promoall=async()=>{if(!confirm(`Apply promo prices to ${DEAD.filter(p=>!p.promo_price).length} product(s)?`))return;await api('/promo','POST',{items:DEAD.filter(p=>!p.promo_price).map(p=>({product_id:p.id,price:p.suggested_price}))});toast('Promos applied');loadDead()};

/* ---------- substitutes ---------- */
let SUBID=null;
V.sub=async()=>{
  const ps=await api('/products');cacheP(ps);
  if(!ps.length){$('#view').innerHTML=head('Smart Substitute Finder','Find in-stock units with similar HP, type and price.')+'<div class="panel empty">There are no products yet.</div>';return}
  if(!SUBID||!PC[SUBID])SUBID=(ps.find(p=>p.status==='OUT')||ps[0]).id;
  $('#view').innerHTML=head('Smart Substitute Finder',"Find in-stock units with similar HP, type and price.")+
   `<div class="bar"><select id="sp" style="min-width:340px">${ps.map(p=>`<option value="${p.id}" ${p.id==SUBID?'selected':''}>${esc(p.brand+' '+p.model)} - ${p.status==='OUT'?'OUT OF STOCK':p.available+' available'}</option>`).join('')}</select></div><div id="sout"></div>`;
  $('#sp').onchange=e=>{SUBID=+e.target.value;run(loadSub)};await loadSub();
};
async function loadSub(){
  const d=await api('/substitutes?product_id='+SUBID),t=d.target;
  $('#sout').innerHTML=`<p>Alternatives to <b>${esc(t.brand+' '+t.model)}</b> (${t.hp}HP, ${esc(t.type)}, ${peso(t.eff_price)}) ${pbadge(t)}</p>`+(d.substitutes.length?`<div class="sg">${d.substitutes.map((s,i)=>`<div class="card"><span class="sub">${i?'Option '+(i+1):'Best match'}</span><b>${esc(s.brand+' '+s.model)}</b><div style="font-size:18px;margin:4px 0">${priceCell(s)} <span class="sub ${s.price_diff>0?'neg':'pos'}">(${s.price_diff>=0?'+':''}${peso(s.price_diff)})</span></div><div class="sub">${s.available} available · ${esc(s.sku)} · shelf ${esc(s.location||'-')}</div><div class="sub">${s.reasons.join(' · ')}</div>${can('owner','employee')?`<button class="b sm" style="margin-top:8px" data-act="padd2" data-id="${s.id}">Sell this instead</button>`:''}</div>`).join('')}</div>`:'<p class="mut">No in-stock alternatives within 0.5HP.</p>');
}
ACT.padd2=id=>{cacheP([]);go('pos');setTimeout(()=>ACT.padd(id),400)};

/* ---------- reports ---------- */
let RDAYS=30;
V.rep=async()=>{
  const d=await api('/reports?days='+RDAYS);
  const pays=d.payments.map((p,i)=>({label:p.payment,value:p.n,extra:trow('Revenue',peso(p.revenue)),color:['var(--c1)','var(--c2)','var(--c3)','var(--c4)','var(--ok)','var(--bad)'][i%6]}));
  $('#view').innerHTML=head('Reports & Analytics',`Last ${d.days} days.`,`<select id="rd">${[7,30,90,180,365].map(x=>`<option value="${x}" ${x==RDAYS?'selected':''}>Last ${x} days</option>`).join('')}</select>`)+
   `<div class="kpis">${kpi('Revenue',peso(d.revenue),d.invoices+' invoices · avg '+peso(d.avg_ticket))}${kpi('Gross profit',peso(d.profit),d.margin_pct+'% margin','pos')}${kpi('Units sold',num(d.units),'Discounts given '+peso(d.discounts))}
   ${kpi('Inventory value',peso(d.inventory_value),'at cost')}${kpi('Inventory turns',d.turns+'×',d.days_inventory?d.days_inventory+' days of inventory':'')}</div>
   <div class="panel"><h3>Revenue & profit per day</h3>${lineChart(d.series.labels,[{name:'Revenue',vals:d.series.revenue},{name:'Gross profit',vals:d.series.profit}],d.series.count)}</div>
   <div class="g2"><div class="panel"><h3>Stock value by brand (cost)</h3>${hbars(d.brands.filter(b=>b.stock_value>0).map(b=>({label:b.brand,value:b.stock_value,text:peso(b.stock_value),extra:trow('Units on hand',num(b.units))})),'c3','Stock value')}</div>
   <div class="panel"><h3>Revenue by brand</h3>${hbars(d.brands.filter(b=>b.revenue>0).sort((a,b)=>b.revenue-a.revenue).map(b=>({label:b.brand,value:b.revenue,text:peso(b.revenue)})),'','Revenue')}</div></div>
   <div class="g2"><div class="panel"><h3>Payment methods (invoices)</h3>${donut(pays,d.invoices,'Invoices')}</div>
   <div class="panel"><h3>Cashier accountability</h3>${dtable([{h:'User',f:c=>esc(c.user)},{h:'Invoices',cls:'r',f:c=>c.invoices},{h:'Revenue',cls:'r',f:c=>peso(c.revenue)},{h:'Discounts',cls:'r',f:c=>peso(c.discounts)},{h:'Voids',cls:'r',f:c=>c.voids?`<b class="neg">${c.voids}</b>`:0}],d.cashiers)}</div></div>
   <div class="panel"><h3>Product performance & ABC class</h3><p class="sub">A = products making the first 80% of revenue, B = next 15%, C = the long tail. Keep A items always in stock; shrink C.</p>${dtable([{h:'Product',cls:'wrap',f:p=>esc(p.label),s:p=>p.label},{h:'ABC',f:p=>badge(p.abc),s:p=>p.abc},{h:'Units',cls:'r',f:p=>p.units,s:p=>p.units},{h:'Revenue',cls:'r',f:p=>peso(p.revenue),s:p=>p.revenue},{h:'Profit',cls:'r',f:p=>peso(p.profit),s:p=>p.profit}],d.products,{sort:3,dir:-1,empty:'No sales in this period.'})}</div>`;
  $('#rd').onchange=e=>{RDAYS=+e.target.value;run(V.rep)};
};

/* ---------- risk center ---------- */
V.alerts=async()=>{
  const a=await api('/alerts'),ic={};$('#belln').textContent=a.length;
  $('#view').innerHTML=head('Risk Center','Problems found automatically in stock and sales records.')+
   `<div class="kpis">${kpi('High priority',a.filter(x=>x.severity==='high').length,'','neg')}${kpi('Medium',a.filter(x=>x.severity==='med').length,'','warn')}${kpi('Low',a.filter(x=>x.severity==='low').length)}</div>`+
   (a.length?a.map(x=>`<div class="al ${x.severity}" data-act="go" data-id="${x.tab}"><div><b>${esc(x.title)} ${badge(x.severity==='high'?'high':x.severity==='med'?'med':'low-sev',x.type)}</b><span class="mut">${esc(x.detail)}</span>${x.ts?`<div class="sub">${dtm(x.ts)}</div>`:''}</div></div>`).join(''):'<div class="panel empty">All clear. Nothing needs your attention.</div>');
};

/* ---------- audit ---------- */
V.audit=async()=>{
  $('#view').innerHTML=head('Audit Trail','Record of changes to prices, stock, voids and users.')+`<div class="bar"><input type="search" id="aq" placeholder="Filter by action, user or detail"></div><div class="panel" id="al"></div>`;
  const load=async()=>{const l=await api('/audit?q='+encodeURIComponent($('#aq').value));$('#al').innerHTML=dtable([{h:'Date / time',f:x=>dtm(x.ts),s:x=>x.ts},{h:'User',f:x=>esc(x.user),s:x=>x.user},{h:'Action',f:x=>`<code>${esc(x.action)}</code>`,s:x=>x.action},{h:'Detail',cls:'wrap',f:x=>esc(x.detail)}],l,{sort:0,dir:-1})};
  $('#aq').oninput=()=>{clearTimeout(window._aq);window._aq=setTimeout(()=>run(load),250)};await load();
};

/* ---------- users & settings ---------- */
V.users=async()=>{
  const all=await api('/users'),us=all.filter(u=>!u.pending),pend=all.filter(u=>u.pending),s=ME.settings;window._users=us;
  const pendHtml=pend.length?`<div class="note bad"><b>${pend.length} request(s) waiting for your approval.</b> Approve only people you know. Once approved they can see this shop's stock.</div><div class="panel"><h3>Staff requests</h3>${dtable([{h:'Username',f:u=>`<b>${esc(u.username)}</b>`},{h:'Name',f:u=>esc(u.name)},{h:'Wants to be',f:u=>({owner:'Shop Owner',employee:'Sales staff',purchasing:'Purchasing'})[u.role]},{h:'Requested',f:u=>dtm(u.created_at)},{h:'',f:u=>`<button class="b sm" data-act="uok" data-id="${u.id}">Approve</button><button class="b sm d" data-act="uno" data-id="${u.id}">Reject</button>`}],pend)}</div>`:'';
  $('#view').innerHTML=head('Users & Settings','Accounts, roles and shop details.',`<button class="b" data-act="uform">+ Add user</button>`)+
   `${pendHtml}<div class="panel"><h3>Accounts</h3>${dtable([{h:'Username',f:u=>`<b>${esc(u.username)}</b>`},{h:'Name',f:u=>esc(u.name)},{h:'Role',f:u=>({owner:'Shop Owner',employee:'Sales staff',purchasing:'Purchasing'})[u.role]},{h:'Active',f:u=>u.active?badge('OK','active'):badge('CANCELLED','disabled')},{h:'Created',f:u=>d10(u.created_at)},{h:'',f:u=>`<button class="b sm g" data-act="uform" data-id="${u.id}">Edit / reset password</button>`}],us)}</div>
   <div class="g2"><div class="panel"><h3>Shop details (printed on invoices)</h3><form id="setf"><label>Shop name</label><input name="shop_name" value="${esc(s.shop_name)}" style="width:100%"><label>Address</label><input name="address" value="${esc(s.address)}" style="width:100%">
   <div class="r2"><div><label>Phone</label><input name="phone" value="${esc(s.phone)}" style="width:100%"></div><div><label>TIN</label><input name="tin" value="${esc(s.tin)}" style="width:100%"></div></div><label>Invoice footer</label><textarea name="footer" rows="2" style="width:100%">${esc(s.footer)}</textarea>
   <label><input type="checkbox" name="allow_signup" value="1" ${s.allow_signup!=='0'?'checked':''} style="width:auto"> Let staff ask to join my shop from the login page (I approve each request)</label>
   <p><button class="b" data-act="savesettings">Save shop details</button></p></form></div>
   <div class="panel"><h3>My account</h3>
   <p><button class="b g" data-act="pw">Change my password</button></p></div></div>`;
};
ACT.uok=async id=>{await api('/users/'+id+'/approve','POST');toast('Approved');V.users()};
ACT.uno=async id=>{if(!confirm('Reject and delete this request?'))return;await api('/users/'+id+'/reject','POST');toast('Request rejected');V.users()};
ACT.savesettings=async(id,b,e)=>{e.preventDefault();const o=Object.fromEntries(new FormData($('#setf')));o.allow_signup=$('#setf [name=allow_signup]').checked?'1':'0';await api('/settings','PUT',o);Object.assign(ME.settings,o);$('#shop').textContent=o.shop_name;toast('Saved')};
ACT.uform=id=>{const u=id?window._users.find(x=>x.id==id):null,v=k=>esc(u?u[k]:'');
  modal(u?'Edit user':'Add user',`${u?`<p class="sub">Username: <b>${esc(u.username)}</b></p>`:`<label>Username</label><input name="username" required pattern="[a-zA-Z0-9_.\\-]{3,30}">`}<label>Full name</label><input name="name" required value="${v('name')}">
   <label>Role</label>${sel('role',[['owner','Shop Owner (everything)'],['employee','Sales staff (sell, search stock)'],['purchasing','Purchasing (restock planning)']],u?u.role:'employee')}
   <label>${u?'New password (leave blank to keep)':'Password (min 6 characters)'}</label><input name="password" type="password" ${u?'':'required'} minlength="6" autocomplete="new-password">
   ${u?`<label><input type="checkbox" name="active" value="1" ${u.active?'checked':''} style="width:auto"> Account is active</label>`:''}`,
   async o=>{await api(u?'/users/'+u.id:'/users',u?'PUT':'POST',o);toast('Saved');V.users()})};

/* ---------- number steppers ---------- */
function stepper(){
  $$('input[type=number]').forEach(i=>{
    if(i.dataset.stp||i.closest('.cl,.ln'))return;i.dataset.stp='1';
    const w=document.createElement('span');w.className='numw';i.parentNode.insertBefore(w,i);w.appendChild(i);
    const up='<svg viewBox="0 0 10 10"><path d="M2 6.5 5 3.5l3 3"/></svg>',dn='<svg viewBox="0 0 10 10"><path d="M2 3.5 5 6.5l3-3"/></svg>';
    const p=document.createElement('span');p.className='stp';p.innerHTML=`<button type="button" tabindex="-1" aria-label="Increase">${up}</button><button type="button" tabindex="-1" aria-label="Decrease">${dn}</button>`;
    const go=d=>{if(i.disabled||i.readOnly)return;d>0?i.stepUp():i.stepDown();i.dispatchEvent(new Event('input',{bubbles:true}));i.dispatchEvent(new Event('change',{bubbles:true}))};
    p.children[0].onclick=()=>go(1);p.children[1].onclick=()=>go(-1);w.appendChild(p);
  });
}
new MutationObserver(stepper).observe(document.body,{childList:true,subtree:true});stepper();
/* ---------- boot ---------- */
(async()=>{
  try{const t=localStorage.getItem('cs-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}
  ME=await api('/me');$('#shop').textContent=ME.settings.shop_name;
  $('#nav').innerHTML=NAV.filter(n=>n[0]==='#'||n[3].includes(ME.role)).filter((n,i,a)=>n[0]!=='#'||(a[i+1]&&a[i+1][0]!=='#')).map(n=>n[0]==='#'?`<h6>${n[1]}</h6>`:`<a data-act="go" data-id="${n[0]}" data-id2="${n[0]}" data-nav="1">${n[1]}</a>`).join('');
  $$('#nav a').forEach(a=>a.dataset.id=a.dataset.id);
  $('#me').innerHTML=`<div>${esc(ME.name)}<small>${({owner:'Shop Owner',employee:'Sales staff',purchasing:'Purchasing'})[ME.role]}</small></div><button class="ib" data-act="pw" >Password</button><button class="ib" data-act="logout">Sign out</button>`;
  if(can('owner')){$('#bell').style.display='';run(async()=>{const a=await api('/alerts');$('#belln').textContent=a.length})}
  if(!location.hash)location.hash='#dash';else render();
})();
</script></body></html>
"""


def main():
    args = sys.argv[1:]
    port = int(os.environ.get("PORT", "8000"))
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    host = "0.0.0.0" if "--lan" in args else "127.0.0.1"
    init_db()
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://localhost:{port}"
    print(f"\n  {APP_NAME} is running at {url}   (Ctrl+C to stop)")
    if host == "0.0.0.0":
        print("  LAN mode: other devices can connect using this computer's IP address and the same port.")
    print("  First time? Open the page and create your account. Shop owners start with an empty shop.\n")
    if "--no-browser" not in args:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
