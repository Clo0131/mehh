#!/usr/bin/env python3
"""
CoolStock - logic layer (database, business rules, data structures and algorithms)
=================================================================================
This file has NO screens. It holds:
  - the SQLite database and its tables
  - the business rules (products, sales, forecast, reports, risk alerts, users)
  - the course data structures and algorithms: Linear Search, Merge Sort (Divide and Conquer),
    Heap / Priority Queue and the Greedy algorithm (look for the lines marked "DSA:")
The screens and the web server are in app.py, which imports this file.
"""
import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta

APP_NAME = "CoolStock"
TAGLINE = "Aircon Inventory, Sales & Purchasing"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "coolstock.db")
FMT = "%Y-%m-%d %H:%M:%S"
PW_ITER = 150_000
SESSION_HOURS = 12
MAX_EMP_DISCOUNT = 0.10
PAYMENTS = ["Cash", "GCash", "Maya", "Credit Card", "Bank Transfer", "Installment"]
OUT_REASONS = ["Damaged", "Demo / display unit", "Transfer to another branch", "Returned to supplier", "Lost / missing", "Other"]
COST_KEYS = {"cost", "unit_cost", "value", "tied_capital", "margin_after", "cost_total", "profit", "spend"}


# ================================================================ helpers
def now():
    return datetime.now().strftime(FMT)


def today():
    return datetime.now().strftime("%Y-%m-%d")


def days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime(FMT)


def parse_ts(s):
    return datetime.strptime(s, FMT)


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


class Resp:
    """Raw response (cookies, downloads)."""
    def __init__(self, data, ctype="application/json", code=200, headers=None):
        self.data, self.ctype, self.code, self.headers = data, ctype, code, headers or {}


_t = threading.local()


def shop():
    """The shop (owner id) of the signed-in user for the current request."""
    s = getattr(_t, "shop", None)
    if not s:
        raise ApiError("No shop selected.", 403)
    return s


def db():
    c = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), PW_ITER).hex(), salt


def check_pw(pw, h, salt):
    return secrets.compare_digest(hash_pw(pw, salt)[0], h)


def redact(o):
    """Sales staff never receive cost / profit figures."""
    if isinstance(o, dict):
        return {k: redact(v) for k, v in o.items() if k not in COST_KEYS}
    if isinstance(o, list):
        return [redact(x) for x in o]
    return o


def num(body, key, kind=float, minimum=0, required=True):
    v = body.get(key)
    if v in (None, ""):
        if required:
            raise ApiError(f"'{key}' is required")
        return None
    try:
        v = kind(v)
    except (TypeError, ValueError):
        raise ApiError(f"'{key}' must be a number")
    if v < minimum:
        raise ApiError(f"'{key}' must be at least {minimum}")
    return v


def text(body, key, required=True, maxlen=200):
    v = str(body.get(key) or "").strip()
    if required and not v:
        raise ApiError(f"'{key}' is required")
    return v[:maxlen]


def date_ok(s):
    if not s:
        return ""
    try:
        datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        raise ApiError("Dates must look like YYYY-MM-DD")
    return s


def audit(c, ctx, action, entity="", eid="", detail=""):
    c.execute("INSERT INTO audit(shop_id,ts,user,action,entity,entity_id,detail) VALUES(?,?,?,?,?,?,?)",
              (ctx.get("shop") or getattr(_t, "shop", None) or 0, now(), ctx.get("username", "system"), action, entity, str(eid), detail))


# ================================================================ schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(shop_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY(shop_id, key));
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  role TEXT NOT NULL, pw_hash TEXT NOT NULL, salt TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  owner_id INTEGER NOT NULL DEFAULT 0,      -- the shop owner this user belongs to (an owner points to themselves)
  pending INTEGER NOT NULL DEFAULT 0,       -- 1 = waiting for the owner to approve
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT, shop_id INTEGER NOT NULL, sku TEXT NOT NULL, brand TEXT NOT NULL, model TEXT NOT NULL,
  hp REAL NOT NULL, type TEXT NOT NULL, cost REAL NOT NULL, price REAL NOT NULL, promo_price REAL,
  qty INTEGER NOT NULL DEFAULT 0, min_qty INTEGER NOT NULL DEFAULT 0, location TEXT,
  warranty_months INTEGER NOT NULL DEFAULT 12, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, UNIQUE(shop_id, sku));
CREATE TABLE IF NOT EXISTS movements(
  id INTEGER PRIMARY KEY AUTOINCREMENT, shop_id INTEGER NOT NULL, product_id INTEGER NOT NULL, label TEXT NOT NULL,
  kind TEXT NOT NULL,            -- IN, OUT, SALE, VOID, ADJUST
  delta INTEGER NOT NULL, unit_cost REAL NOT NULL DEFAULT 0, note TEXT, user TEXT, ref TEXT, ts TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_mov_prod ON movements(product_id, ts);
CREATE INDEX IF NOT EXISTS ix_mov_shop ON movements(shop_id, ts);
CREATE TABLE IF NOT EXISTS sales(
  id INTEGER PRIMARY KEY AUTOINCREMENT, shop_id INTEGER NOT NULL, invoice_no TEXT NOT NULL, customer TEXT, phone TEXT, payment TEXT,
  total REAL NOT NULL, cost_total REAL NOT NULL, discount_total REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'PAID', user TEXT, ts TEXT NOT NULL, note TEXT,
  void_by TEXT, void_reason TEXT, void_ts TEXT, UNIQUE(shop_id, invoice_no));
CREATE INDEX IF NOT EXISTS ix_sales_ts ON sales(shop_id, ts);
CREATE TABLE IF NOT EXISTS sale_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT, sale_id INTEGER NOT NULL, product_id INTEGER NOT NULL, label TEXT NOT NULL,
  qty INTEGER NOT NULL, unit_price REAL NOT NULL, list_price REAL NOT NULL, unit_cost REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, shop_id INTEGER NOT NULL DEFAULT 0, ts TEXT NOT NULL, user TEXT, action TEXT NOT NULL,
  entity TEXT, entity_id TEXT, detail TEXT);
"""

def init_db():
    # A database from an older CoolStock (before separate shops) has a different layout:
    # keep it as a backup and start fresh.
    if os.path.exists(DB_PATH):
        t = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in t.execute("PRAGMA table_info(products)")]
        t.close()
        if cols and "shop_id" not in cols:
            bak = DB_PATH.replace(".db", f"-old-{datetime.now():%Y%m%d%H%M%S}.db")
            for ext in ("", "-wal", "-shm"):
                if os.path.exists(DB_PATH + ext):
                    os.replace(DB_PATH + ext, bak + ext)
            print(f"  Found a database from an older version; saved it as {os.path.basename(bak)} and created a fresh one.")
    c = db()
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    c.close()


def create_shop(c, owner_id, shop_name):
    """A new shop starts empty: no products, no sales, no suppliers."""
    for k, v in {"shop_name": shop_name, "address": "", "phone": "", "tin": "",
                 "footer": "Thank you for your purchase. Please keep this invoice for warranty claims.", "allow_signup": "1"}.items():
        c.execute("INSERT INTO settings(shop_id,key,value) VALUES(?,?,?)", (owner_id, k, v))


# ================================================================ data structures and algorithms (ILO3)
# The five pieces below are written by hand (no heapq / sorted) so the course concepts are visible:
#   Priority queue (binary min-heap) .... used by the Budget-Aware Reorder Simulator
#   Greedy algorithm .................... the purchase loop in h_reorder
#   Divide and conquer (merge sort) ..... ranks substitutes, slow-moving stock and the restock list
#   Searching (linear search) ........... the Smart Search on products
class PriorityQueue:
    """Array-based binary min-heap: pop() always returns the item with the smallest key.
    push and pop are O(log n); the smallest item is at index 0."""

    def __init__(self):
        self.a = []          # entries are (key, arrival number, item)
        self.count = 0       # arrival number breaks ties, so two items are never compared directly

    def __len__(self):
        return len(self.a)

    def _less(self, i, j):
        return self.a[i][:2] < self.a[j][:2]

    def push(self, key, item):
        self.a.append((key, self.count, item))
        self.count += 1
        i = len(self.a) - 1
        while i > 0:                                  # sift up
            parent = (i - 1) // 2
            if not self._less(i, parent):
                break
            self.a[i], self.a[parent] = self.a[parent], self.a[i]
            i = parent

    def pop(self):
        top = self.a[0]
        last = self.a.pop()
        if self.a:
            self.a[0] = last
            i, n = 0, len(self.a)
            while True:                               # sift down
                small = i
                for child in (2 * i + 1, 2 * i + 2):
                    if child < n and self._less(child, small):
                        small = child
                if small == i:
                    break
                self.a[i], self.a[small] = self.a[small], self.a[i]
                i = small
        return top[0], top[2]


def merge_sort(items, key=lambda x: x):
    """Divide and conquer: split the list in half, sort each half, then merge the two sorted halves.
    Stable, O(n log n) in every case."""
    if len(items) <= 1:
        return list(items)
    mid = len(items) // 2
    left, right = merge_sort(items[:mid], key), merge_sort(items[mid:], key)
    out, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        if key(right[j]) < key(left[i]):
            out.append(right[j]); j += 1
        else:
            out.append(left[i]); i += 1
    out.extend(left[i:])
    out.extend(right[j:])
    return out


def linear_search(items, words, text_of):
    """Look at every item once and keep the ones whose text contains all of the search words. O(n * w)."""
    found = []
    for item in items:
        text = text_of(item)
        match = True
        for w in words:
            if w not in text:
                match = False
                break
        if match:
            found.append(item)
    return found


# ================================================================ domain: products
PRODUCT_SQL = "SELECT p.* FROM products p"
LEAD_DAYS = 7          # days a supplier needs to deliver; used by the forecast


def prow(r):
    d = dict(r)
    d["lead_days"] = LEAD_DAYS
    d["available"] = d["qty"]
    d["status"] = "OUT" if d["available"] <= 0 else ("LOW" if d["available"] <= d["min_qty"] else "OK")
    d["value"] = round(d["qty"] * d["cost"], 2)
    d["eff_price"] = d["promo_price"] or d["price"]
    return d


def velocity(c, days):
    """Net units sold per product (sales minus voids) in the last `days` days."""
    return {r["product_id"]: r["s"] for r in c.execute(
        "SELECT product_id, -SUM(delta) s FROM movements WHERE shop_id=? AND kind IN ('SALE','VOID') AND ts>=? GROUP BY product_id",
        (shop(), days_ago(days)))}


def forecast(c, rows):
    v = velocity(c, 90)
    for p in rows:
        age = max((datetime.now() - parse_ts(p["created_at"])).days, 1)
        window = min(90, max(age, 14))
        sold = max(v.get(p["id"], 0), 0)
        per_day = sold / window
        lead = p["lead_days"]
        p["sold_90"] = sold
        p["per_day"] = round(per_day, 3)
        p["days_cover"] = round(max(p["available"], 0) / per_day, 1) if per_day > 0 else None
        p["rop"] = math.ceil(per_day * lead) + p["min_qty"]
        p["target"] = math.ceil(per_day * (lead + 30)) + p["min_qty"]
        p["suggest_qty"] = max(p["target"] - p["available"], 0)
        p["reorder_soon"] = p["status"] == "OK" and p["available"] <= p["rop"]
    return rows


def all_products(c, with_forecast=True, include_archived=False):
    sql = PRODUCT_SQL + " WHERE p.shop_id=?" + ("" if include_archived else " AND p.active=1") + " ORDER BY p.brand, p.model"
    rows = [prow(r) for r in c.execute(sql, (shop(),))]
    return forecast(c, rows) if with_forecast else rows


def get_product(c, pid):
    r = c.execute(PRODUCT_SQL + " WHERE p.shop_id=? AND p.id=?", (shop(), pid)).fetchone()
    if not r:
        raise ApiError("Product not found", 404)
    return prow(r)


def label_of(p):
    return f"{p['sku']} - {p['brand']} {p['model']}"


def log_move(c, p, kind, delta, note, user, ref=None, unit_cost=None):
    c.execute("INSERT INTO movements(shop_id,product_id,label,kind,delta,unit_cost,note,user,ref,ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (shop(), p["id"], label_of(p), kind, delta, p["cost"] if unit_cost is None else unit_cost, note, user, ref, now()))
    c.execute("UPDATE products SET qty=qty+? WHERE id=?", (delta, p["id"]))


def parse_product(c, body):
    f = {
        "sku": text(body, "sku").upper(), "brand": text(body, "brand"), "model": text(body, "model"),
        "hp": num(body, "hp", float, 0.1), "type": text(body, "type"),
        "cost": num(body, "cost"), "price": num(body, "price"),
        "promo_price": num(body, "promo_price", float, 0.01, required=False),
        "min_qty": num(body, "min_qty", int), "location": text(body, "location", False, 40),
        "warranty_months": num(body, "warranty_months", int, 0, required=False) or 0,
    }
    if f["promo_price"] is not None and f["promo_price"] >= f["price"]:
        raise ApiError("Promo price must be lower than the regular price.")
    return f


COLS = ("sku", "brand", "model", "hp", "type", "cost", "price", "promo_price", "min_qty", "location", "warranty_months")


def h_products(c, ctx, q, body):
    rows = all_products(c)
    term = (q.get("q", [""])[0]).lower().replace("hp", " ").strip()
    if term:
        words = term.split()
        # DSA: SEARCHING ALGORITHM (linear search) - checks every product once for all the typed words
        rows = linear_search(rows, words, lambda p: f"{p['brand']} {p['model']} {p['sku']} {p['type']} {p['hp']:g} {p['location'] or ''}".lower())
    lim = int(q.get("limit", ["0"])[0] or 0)
    return rows[:lim] if lim else rows


def h_product_create(c, ctx, q, body):
    f = parse_product(c, body)
    qty = num(body, "qty", int, 0, required=False) or 0
    try:
        pid = c.execute("INSERT INTO products(shop_id,%s,qty,created_at) VALUES(%s)" % (",".join(COLS), ",".join("?" * (len(COLS) + 3))),
                        [shop()] + [f[k] for k in COLS] + [0, now()]).lastrowid
    except sqlite3.IntegrityError:
        raise ApiError("That SKU already exists.")
    p = get_product(c, pid)
    if qty:
        log_move(c, p, "IN", qty, "Opening stock", ctx["username"])
    audit(c, ctx, "product.create", "product", pid, f"{label_of(p)} qty {qty} price {f['price']}")
    return get_product(c, pid)


def h_product_update(c, ctx, q, body, pid):
    old = get_product(c, int(pid))
    f = parse_product(c, body)
    ch = [f"{k}: {old[k]} -> {f[k]}" for k in COLS if f[k] != old[k]]
    try:
        c.execute("UPDATE products SET %s WHERE id=?" % ",".join(f"{k}=?" for k in COLS), [f[k] for k in COLS] + [old["id"]])
    except sqlite3.IntegrityError:
        raise ApiError("That SKU already exists.")
    if ch:
        audit(c, ctx, "product.update", "product", old["id"], f"{label_of(old)}: " + "; ".join(ch))
    return get_product(c, old["id"])


def h_product_archive(c, ctx, q, body, pid):
    p = get_product(c, int(pid))
    if p["qty"] != 0:
        raise ApiError("Cannot archive while units are on hand. Sell, transfer or count the stock to zero first.")
    c.execute("UPDATE products SET active=0 WHERE id=?", (p["id"],))
    audit(c, ctx, "product.archive", "product", p["id"], label_of(p))
    return {"ok": True}


def h_promo(c, ctx, q, body):
    n = 0
    for it in body.get("items") or []:
        p = get_product(c, int(num(it, "product_id", int, 1)))
        price = num(it, "price", float, 0.01, required=False)
        if price is not None and price >= p["price"]:
            raise ApiError(f"Promo for {label_of(p)} must be lower than the regular price.")
        c.execute("UPDATE products SET promo_price=? WHERE id=?", (price, p["id"]))
        audit(c, ctx, "promo.set" if price else "promo.clear", "product", p["id"], f"{label_of(p)} promo {price}")
        n += 1
    return {"updated": n}


def h_product_detail(c, ctx, q, body, pid):
    p = forecast(c, [get_product(c, int(pid))])[0]
    mv = [dict(r) for r in c.execute("SELECT * FROM movements WHERE product_id=? ORDER BY id DESC LIMIT 25", (p["id"],))]
    sold30 = velocity(c, 30).get(p["id"], 0)
    last = c.execute("SELECT MAX(ts) m FROM movements WHERE product_id=? AND kind='SALE'", (p["id"],)).fetchone()["m"]
    rev = c.execute("SELECT COALESCE(SUM(si.qty*si.unit_price),0) r FROM sale_items si JOIN sales s ON s.id=si.sale_id "
                    "WHERE si.product_id=? AND s.status='PAID' AND s.ts>=?", (p["id"], days_ago(90))).fetchone()["r"]
    return {"product": p, "movements": mv, "sold_30": max(sold30, 0), "last_sale": last, "revenue_90": rev}


# ================================================================ movements & counts
def h_move(c, ctx, q, body):
    p = get_product(c, int(num(body, "product_id", int, 1)))
    kind = str(body.get("kind", "")).upper()
    qty = num(body, "qty", int, 1)
    note = text(body, "note", maxlen=300)
    if kind == "IN":
        if ctx["role"] not in ("owner", "purchasing"):
            raise ApiError("Only the owner or purchasing can receive stock.", 403)
        log_move(c, p, "IN", qty, note, ctx["username"])
        audit(c, ctx, "stock.in", "product", p["id"], f"+{qty} {label_of(p)} ({note})")
    elif kind == "OUT":
        if ctx["role"] not in ("owner", "employee"):
            raise ApiError("Only the owner or sales staff can write stock out.", 403)
        reason = text(body, "reason")
        if reason not in OUT_REASONS:
            raise ApiError("Pick a reason for the stock-out.")
        if qty > p["available"]:
            raise ApiError(f"Only {p['available']} unit(s) available ({p['qty']} on hand).")
        log_move(c, p, "OUT", -qty, f"[{reason}] {note}", ctx["username"])
        audit(c, ctx, "stock.out", "product", p["id"], f"-{qty} {label_of(p)} [{reason}] {note}")
    else:
        raise ApiError("kind must be IN or OUT (sales go through New Sale)")
    return get_product(c, p["id"])


# ================================================================ sales / POS
def next_number(c, table, col, prefix):
    n = c.execute(f"SELECT COUNT(*) FROM {table} WHERE shop_id=? AND {col} LIKE ?", (shop(), prefix + "%")).fetchone()[0] + 1
    return f"{prefix}{n:04d}"


def h_sale_create(c, ctx, q, body):
    raw = body.get("items") or []
    if not raw:
        raise ApiError("Add at least one item to the sale.")
    customer = text(body, "customer", False, 80) or "Walk-in"
    payment = body.get("payment") or "Cash"
    if payment not in PAYMENTS:
        raise ApiError("Unknown payment method")
    merged = {}
    for it in raw:
        pid, qty = int(num(it, "product_id", int, 1)), num(it, "qty", int, 1)
        price = num(it, "price", float, 0)
        if pid in merged:
            merged[pid]["qty"] += qty
        else:
            merged[pid] = {"qty": qty, "price": price}
    lines, total, cost_total, disc_total = [], 0.0, 0.0, 0.0
    for pid, it in merged.items():
        p = get_product(c, pid)
        if not p["active"]:
            raise ApiError(f"{label_of(p)} is archived.")
        if it["qty"] > p["available"]:
            raise ApiError(f"Only {p['available']} unit(s) of {label_of(p)} are available.")
        lst, price = p["eff_price"], it["price"]
        if ctx["role"] != "owner":
            if price < p["cost"]:
                raise ApiError(f"{label_of(p)}: price is below cost. The owner must approve this sale.", 403)
            if lst and price < lst * (1 - MAX_EMP_DISCOUNT) - 0.5:
                raise ApiError(f"{label_of(p)}: discounts above {int(MAX_EMP_DISCOUNT * 100)}% need the owner.", 403)
        lines.append((p, it["qty"], price, lst))
        total += it["qty"] * price
        cost_total += it["qty"] * p["cost"]
        disc_total += it["qty"] * (lst - price)
    inv = next_number(c, "sales", "invoice_no", f"INV-{datetime.now():%Y%m%d}-")
    sid = c.execute(
        "INSERT INTO sales(shop_id,invoice_no,customer,phone,payment,total,cost_total,discount_total,status,user,ts,note) "
        "VALUES(?,?,?,?,?,?,?,?,'PAID',?,?,?)",
        (shop(), inv, customer, text(body, "phone", False, 40), payment, round(total, 2), round(cost_total, 2), round(disc_total, 2),
         ctx["username"], now(), text(body, "note", False, 200))).lastrowid
    for p, qty, price, lst in lines:
        c.execute("INSERT INTO sale_items(sale_id,product_id,label,qty,unit_price,list_price,unit_cost) VALUES(?,?,?,?,?,?,?)",
                  (sid, p["id"], label_of(p), qty, price, lst, p["cost"]))
        log_move(c, p, "SALE", -qty, f"Sold on {inv}", ctx["username"], ref=inv)
    audit(c, ctx, "sale.create", "sale", sid, f"{inv} {payment} {total:,.2f} for {customer}")
    return {"id": sid, "invoice_no": inv, "total": round(total, 2)}


def sale_with_items(c, sid):
    s = c.execute("SELECT * FROM sales WHERE id=? AND shop_id=?", (sid, shop())).fetchone()
    if not s:
        raise ApiError("Sale not found", 404)
    d = dict(s)
    d["items"] = [dict(r) for r in c.execute("SELECT * FROM sale_items WHERE sale_id=?", (sid,))]
    d["profit"] = round(d["total"] - d["cost_total"], 2)
    return d


def h_sale_get(c, ctx, q, body, sid):
    d = sale_with_items(c, int(sid))
    if ctx["role"] == "employee" and d["user"] != ctx["username"]:
        raise ApiError("You can only open your own sales.", 403)
    return d


def h_sales(c, ctx, q, body):
    where, args = ["s.shop_id=?"], [shop()]
    if ctx["role"] == "employee":
        where.append("s.user=?"); args.append(ctx["username"])
    elif q.get("user", [""])[0]:
        where.append("s.user=?"); args.append(q["user"][0])
    if q.get("status", [""])[0]:
        where.append("s.status=?"); args.append(q["status"][0].upper())
    if q.get("from", [""])[0]:
        where.append("s.ts>=?"); args.append(date_ok(q["from"][0]))
    if q.get("to", [""])[0]:
        where.append("s.ts<=?"); args.append(date_ok(q["to"][0]) + " 23:59:59")
    if q.get("q", [""])[0]:
        where.append("(s.invoice_no LIKE ? OR s.customer LIKE ?)"); args += [f"%{q['q'][0]}%"] * 2
    sql = ("SELECT s.*, (SELECT group_concat(label || ' x' || qty, '; ') FROM sale_items WHERE sale_id=s.id) AS items FROM sales s"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY s.id DESC LIMIT 400")
    out = []
    for r in c.execute(sql, args):
        d = dict(r)
        d["profit"] = round(d["total"] - d["cost_total"], 2)
        out.append(d)
    return out


def h_sale_void(c, ctx, q, body, sid):
    s = sale_with_items(c, int(sid))
    if s["status"] != "PAID":
        raise ApiError("This sale is already voided.")
    reason = text(body, "reason", maxlen=200)
    for it in s["items"]:
        p = get_product(c, it["product_id"])
        log_move(c, p, "VOID", it["qty"], f"Void {s['invoice_no']}: {reason}", ctx["username"], ref=s["invoice_no"], unit_cost=it["unit_cost"])
    c.execute("UPDATE sales SET status='VOID', void_by=?, void_reason=?, void_ts=? WHERE id=?", (ctx["username"], reason, now(), s["id"]))
    audit(c, ctx, "sale.void", "sale", s["id"], f"{s['invoice_no']} {s['total']:,.2f} by {s['user']}: {reason}")
    return {"ok": True}


def invoice_html(c, sid):
    s = sale_with_items(c, sid)
    st = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM settings WHERE shop_id=?", (shop(),))}
    e = lambda x: (str(x if x is not None else "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    rows = "".join(f"<tr><td>{e(i['label'])}</td><td class=r>{i['qty']}</td><td class=r>{i['unit_price']:,.2f}</td><td class=r>{i['qty'] * i['unit_price']:,.2f}</td></tr>" for i in s["items"])
    vatable = s["total"] / 1.12
    stamp = '<div class="void">VOID</div>' if s["status"] == "VOID" else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{e(s['invoice_no'])}</title><style>
body{{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;color:#111;max-width:760px;margin:20px auto;padding:0 18px;position:relative}}
h1{{margin:0;font-size:22px}}.m{{color:#555}}table{{width:100%;border-collapse:collapse;margin:16px 0}}th,td{{padding:7px 8px;border-bottom:1px solid #ddd;text-align:left}}
.r{{text-align:right}}th{{background:#f3f6f9;font-size:12px;text-transform:uppercase}}.tot td{{border:0;padding:3px 8px}}.tot .b td{{font-weight:700;font-size:16px;border-top:2px solid #111}}
.top{{display:flex;justify-content:space-between;gap:20px}}button{{padding:8px 16px;font-size:14px;cursor:pointer}}
.void{{position:absolute;top:240px;left:25%;font-size:110px;font-weight:800;color:#d03b2f33;transform:rotate(-18deg);pointer-events:none}}
.sig{{display:flex;gap:40px;margin-top:50px}}.sig div{{flex:1;border-top:1px solid #111;text-align:center;padding-top:4px;font-size:12px}}
@media print{{button{{display:none}}}}</style></head><body>{stamp}
<div class="top"><div><h1>{e(st.get('shop_name'))}</h1><div class="m">{e(st.get('address'))}<br>Tel {e(st.get('phone'))} &middot; TIN {e(st.get('tin'))}</div></div>
<div style="text-align:right"><b style="font-size:18px">SALES INVOICE</b><br>{e(s['invoice_no'])}<br><span class="m">{e(s['ts'][:16])}</span></div></div>
<p><b>Customer:</b> {e(s['customer'])} {e(s['phone'] or '')}<br><b>Payment:</b> {e(s['payment'])} &nbsp; <b>Cashier:</b> {e(s['user'])}</p>
<table><tr><th>Item</th><th class=r>Qty</th><th class=r>Unit price</th><th class=r>Amount</th></tr>{rows}</table>
<table class="tot" style="width:320px;margin-left:auto"><tr><td>VATable sales</td><td class=r>{vatable:,.2f}</td></tr><tr><td>VAT (12%)</td><td class=r>{s['total'] - vatable:,.2f}</td></tr>
<tr><td>Total</td><td class=r>{s['total']:,.2f}</td></tr><tr class="b"><td>Amount paid</td><td class=r>{s['total']:,.2f}</td></tr></table>
<p class="m">{e(st.get('footer'))}</p><div class="sig"><div>Customer signature</div><div>Authorized signature</div></div>
<p style="margin-top:24px"><button onclick="window.print()">Print invoice</button></p></body></html>"""


# ================================================================ smart tools
def h_lowstock(c, ctx, q, body):
    rows = [p for p in all_products(c) if p["status"] != "OK" or p["reorder_soon"]]
    # DSA: SORTING ALGORITHM (merge sort, divide and conquer) - out/low items first, then fewest days of cover
    return merge_sort(rows, key=lambda p: (p["status"] == "OK", p["days_cover"] if p["days_cover"] is not None else 9999, p["available"]))


def last_sale_map(c):
    return {r["product_id"]: r["m"] for r in c.execute("SELECT product_id, MAX(ts) m FROM movements WHERE shop_id=? AND kind='SALE' GROUP BY product_id", (shop(),))}


def dead_stock(c, days):
    last = last_sale_map(c)
    out = []
    for p in all_products(c):
        if p["qty"] <= 0:
            continue
        ref = parse_ts(last.get(p["id"]) or p["created_at"])
        idle = (datetime.now() - ref).days
        if idle < days:
            continue
        if idle >= 180:
            pct, action = 0.20, "Clearance sale: deep discount, bundle with free installation"
        elif idle >= 120:
            pct, action = 0.15, "Run a promo or bundle (free installation / freebies)"
        elif idle >= 90:
            pct, action = 0.10, "Limited-time promo; move to a high-traffic display spot"
        elif idle >= 60:
            pct, action = 0.07, "Light discount and offer to repeat customers"
        else:
            pct, action = 0.05, "Watch closely; small promo or add-on offer"
        floor = round(p["cost"] * 1.02)
        sug = max(round(p["price"] * (1 - pct)), floor)
        d = dict(p)
        d.update(idle_days=idle, tied_capital=round(p["qty"] * p["cost"], 2),
                 suggested_discount=round((1 - sug / p["price"]) * 100, 1) if p["price"] else 0,
                 suggested_price=sug, margin_after=round(sug - p["cost"], 2), action=action)
        out.append(d)
    # DSA: SORTING ALGORITHM (merge sort) - longest idle days first
    return merge_sort(out, key=lambda d: -d["idle_days"])


def h_deadstock(c, ctx, q, body):
    days = int(q.get("days", ["60"])[0])
    items = dead_stock(c, days)
    return {"days": days, "items": items, "tied_capital": round(sum(i["tied_capital"] for i in items), 2)}


def h_substitutes(c, ctx, q, body):
    t = get_product(c, int(q.get("product_id", ["0"])[0] or 0))
    cands = []
    for p in all_products(c):
        if p["id"] == t["id"] or p["available"] <= 0:
            continue
        gap = abs(p["hp"] - t["hp"])
        if gap > 0.5:
            continue
        pg = abs(p["eff_price"] - t["eff_price"]) / t["eff_price"] if t["eff_price"] else 0
        score = 100 - gap * 60 - pg * 100
        reasons = ["same HP" if gap == 0 else f"{p['hp']:g}HP (close to {t['hp']:g}HP)"]
        if p["type"] == t["type"]:
            score += 25; reasons.append("same type")
        elif ("Inverter" in p["type"]) == ("Inverter" in t["type"]):
            score += 10; reasons.append("same inverter class")
        if p["brand"] != t["brand"]:
            reasons.append("different brand")
        else:
            score += 5
        if p["promo_price"]:
            score += 4; reasons.append("on promo")
        score += min(p["available"], 5)
        d = dict(p)
        d.update(score=round(score, 1), reasons=reasons, price_diff=p["eff_price"] - t["eff_price"])
        cands.append(d)
    # DSA: SORTING ALGORITHM (merge sort) - highest substitute score first, then the top 6 are returned
    cands = merge_sort(cands, key=lambda d: -d["score"])
    return {"target": t, "substitutes": cands[:6]}


def h_reorder(c, ctx, q, body):
    budget = num(body, "budget", float, 1)
    strategy = body.get("strategy") or "urgent"
    # DSA: DATA STRUCTURE (heap / priority queue) - the most urgent product has the smallest key and pops first
    pq = PriorityQueue()
    for p in all_products(c):
        if p["suggest_qty"] <= 0 or p["cost"] <= 0:
            continue
        if p["available"] > p["rop"] and p["status"] == "OK":
            continue
        margin = (p["price"] - p["cost"]) / p["price"] if p["price"] else 0
        cover = p["days_cover"] if p["days_cover"] is not None else 999
        if strategy == "profit":
            key = (-(p["price"] - p["cost"]) * max(p["per_day"], 0.01), cover)
        elif strategy == "balanced":
            key = (cover / (0.5 + margin), -p["per_day"])
        else:
            key = (p["status"] == "OK", cover, -p["per_day"])
        pq.push(key, p)                        # DSA: heap push, O(log n)
    left, plan, skipped = budget, [], []
    # DSA: GREEDY ALGORITHM - always buy for the most urgent product next, until the budget runs out
    while len(pq):
        _, p = pq.pop()                        # DSA: heap pop, O(log n)
        need = p["suggest_qty"]
        buy = min(need, int(left // p["cost"]))
        if p["status"] == "OUT":
            why = "Out of stock"
        elif p["days_cover"] is not None and p["days_cover"] < p["lead_days"]:
            why = f"~{p['days_cover']:g} days of stock left, supplier needs {p['lead_days']} days"
        elif p["status"] == "LOW":
            why = "Below minimum quantity"
        else:
            why = "Reached reorder point"
        if buy <= 0:
            skipped.append({**p, "need": need, "why": why})
            continue
        spend = buy * p["cost"]
        left -= spend
        plan.append({**p, "need": need, "buy": buy, "spend": round(spend, 2), "full": buy == need, "why": why,
                     "exp_revenue": round(buy * p["price"], 2), "exp_profit": round(buy * (p["price"] - p["cost"]), 2)})
    return {"budget": budget, "strategy": strategy, "spent": round(budget - left, 2), "left": round(left, 2), "plan": plan,
            "skipped": skipped, "exp_revenue": round(sum(x["exp_revenue"] for x in plan), 2),
            "exp_profit": round(sum(x["exp_profit"] for x in plan), 2)}


# ================================================================ dashboard / reports / alerts
def sales_series(c, days, user=None):
    start = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    sql = "SELECT substr(ts,1,10) d, COALESCE(SUM(total),0) rev, COALESCE(SUM(total-cost_total),0) prof, COUNT(*) n FROM sales WHERE shop_id=? AND status='PAID' AND ts>=?"
    args = [shop(), start]
    if user:
        sql += " AND user=?"; args.append(user)
    got = {r["d"]: r for r in c.execute(sql + " GROUP BY d", args)}
    labels, rev, prof, n = [], [], [], []
    for i in range(days):
        d = (datetime.now() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        r = got.get(d)
        labels.append(d); rev.append(round(r["rev"]) if r else 0); prof.append(round(r["prof"]) if r else 0); n.append(r["n"] if r else 0)
    return {"labels": labels, "revenue": rev, "profit": prof, "count": n}


def top_sellers(c, days, limit=5):
    return [dict(r) for r in c.execute(
        "SELECT si.product_id, si.label, SUM(si.qty) units, SUM(si.qty*si.unit_price) revenue FROM sale_items si JOIN sales s ON s.id=si.sale_id "
        "WHERE s.shop_id=? AND s.status='PAID' AND s.ts>=? GROUP BY si.product_id ORDER BY revenue DESC LIMIT ?", (shop(), days_ago(days), limit))]


def h_dashboard(c, ctx, q, body):
    rows = all_products(c)
    role, me = ctx["role"], ctx["username"]
    low = [p for p in rows if p["status"] != "OK" or p["reorder_soon"]]
    low.sort(key=lambda p: (p["status"] == "OK", p["days_cover"] if p["days_cover"] is not None else 9999))
    mine = c.execute("SELECT COALESCE(SUM(total),0) s, COUNT(*) n FROM sales WHERE shop_id=? AND status='PAID' AND user=? AND ts>=?", (shop(), me, today())).fetchone()
    d = {
        "models": len(rows), "units": sum(p["qty"] for p in rows),
        "low_count": sum(1 for p in rows if p["status"] != "OK"), "out_count": sum(1 for p in rows if p["status"] == "OUT"),
        "ok_count": sum(1 for p in rows if p["status"] == "OK"), "soon_count": sum(1 for p in rows if p["reorder_soon"]),
        "value": round(sum(p["value"] for p in rows), 2), "low": low[:6],
        "recent": [dict(r) for r in c.execute("SELECT * FROM movements WHERE shop_id=? ORDER BY id DESC LIMIT 8", (shop(),))],
        "my_today": mine["s"], "my_today_count": mine["n"],
        "series": sales_series(c, 14, me if role == "employee" else None), "top": top_sellers(c, 30),
    }
    if role == "owner":
        m = c.execute("SELECT COALESCE(SUM(total),0) r, COALESCE(SUM(total-cost_total),0) p, COUNT(*) n FROM sales WHERE shop_id=? AND status='PAID' AND ts>=?",
                      (shop(), datetime.now().strftime("%Y-%m-01"))).fetchone()
        t = c.execute("SELECT COALESCE(SUM(total),0) r, COUNT(*) n FROM sales WHERE shop_id=? AND status='PAID' AND ts>=?", (shop(), today())).fetchone()
        dead = dead_stock(c, 90)
        d.update(month_revenue=m["r"], month_profit=m["p"], month_count=m["n"], today_revenue=t["r"], today_count=t["n"],
                 dead_capital=round(sum(x["tied_capital"] for x in dead), 2), dead_count=len(dead), alerts=len(build_alerts(c)),
                 pending_users=c.execute("SELECT COUNT(*) FROM users WHERE owner_id=? AND pending=1", (shop(),)).fetchone()[0])
    return d


def h_reports(c, ctx, q, body):
    days = max(1, min(int(q.get("days", ["30"])[0]), 365))
    start = days_ago(days)
    ser = sales_series(c, min(days, 90))
    tot = c.execute("SELECT COALESCE(SUM(total),0) rev, COALESCE(SUM(total-cost_total),0) prof, COALESCE(SUM(cost_total),0) cogs, COUNT(*) n, "
                    "COALESCE(SUM(discount_total),0) disc FROM sales WHERE shop_id=? AND status='PAID' AND ts>=?", (shop(), start)).fetchone()
    units = c.execute("SELECT COALESCE(SUM(si.qty),0) u FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE s.shop_id=? AND s.status='PAID' AND s.ts>=?", (shop(), start)).fetchone()["u"]
    prods = [dict(r) for r in c.execute(
        "SELECT si.product_id, si.label, SUM(si.qty) units, SUM(si.qty*si.unit_price) revenue, SUM(si.qty*(si.unit_price-si.unit_cost)) profit "
        "FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE s.shop_id=? AND s.status='PAID' AND s.ts>=? GROUP BY si.product_id ORDER BY revenue DESC", (shop(), start))]
    run, total_rev = 0, sum(p["revenue"] for p in prods) or 1
    for p in prods:                       # ABC analysis on revenue
        before = run / total_rev
        run += p["revenue"]
        p["abc"] = "A" if before < 0.8 else ("B" if before < 0.95 else "C")
    brand = {}
    for p in all_products(c, with_forecast=False):
        brand.setdefault(p["brand"], {"brand": p["brand"], "stock_value": 0, "units": 0, "revenue": 0})
        brand[p["brand"]]["stock_value"] += p["value"]; brand[p["brand"]]["units"] += p["qty"]
    for r in c.execute("SELECT p.brand b, SUM(si.qty*si.unit_price) rev FROM sale_items si JOIN sales s ON s.id=si.sale_id JOIN products p ON p.id=si.product_id "
                       "WHERE s.shop_id=? AND s.status='PAID' AND s.ts>=? GROUP BY p.brand", (shop(), start)):
        brand.setdefault(r["b"], {"brand": r["b"], "stock_value": 0, "units": 0, "revenue": 0})["revenue"] = r["rev"]
    inv_value = sum(b["stock_value"] for b in brand.values())
    status = {"OK": 0, "LOW": 0, "OUT": 0}
    for p in all_products(c, with_forecast=False):
        status[p["status"]] += 1
    return {
        "days": days, "series": ser, "revenue": tot["rev"], "profit": tot["prof"], "cogs": tot["cogs"], "invoices": tot["n"], "units": units,
        "discounts": tot["disc"], "avg_ticket": round(tot["rev"] / tot["n"], 2) if tot["n"] else 0,
        "margin_pct": round(tot["prof"] / tot["rev"] * 100, 1) if tot["rev"] else 0,
        "turns": round(tot["cogs"] / inv_value, 2) if inv_value else 0,
        "days_inventory": round(inv_value / (tot["cogs"] / days)) if tot["cogs"] else None,
        "products": prods, "brands": sorted(brand.values(), key=lambda b: -b["stock_value"]),
        "payments": [dict(r) for r in c.execute("SELECT payment, COUNT(*) n, SUM(total) revenue FROM sales WHERE shop_id=? AND status='PAID' AND ts>=? GROUP BY payment ORDER BY revenue DESC", (shop(), start))],
        "cashiers": [dict(r) for r in c.execute(
            "SELECT user, SUM(status='PAID') invoices, COALESCE(SUM(CASE WHEN status='PAID' THEN total END),0) revenue, SUM(status='VOID') voids, "
            "COALESCE(SUM(CASE WHEN status='PAID' THEN discount_total END),0) discounts FROM sales WHERE shop_id=? AND ts>=? GROUP BY user ORDER BY revenue DESC", (shop(), start))],
        "status": status, "inventory_value": inv_value,
    }


def build_alerts(c):
    A = []

    def add(sev, typ, title, detail, tab, ts=None):
        A.append({"severity": sev, "type": typ, "title": title, "detail": detail, "tab": tab, "ts": ts})
    prods = all_products(c)
    names = lambda L: ", ".join(f"{p['brand']} {p['model']}" for p in L[:5]) + (f" +{len(L) - 5} more" if len(L) > 5 else "")
    out = [p for p in prods if p["status"] == "OUT"]
    if out:
        add("high", "Stock", f"{len(out)} product(s) out of stock", names(out), "low")
    low = [p for p in prods if p["status"] == "LOW"]
    if low:
        add("med", "Stock", f"{len(low)} product(s) below minimum", names(low), "low")
    soon = [p for p in prods if p["reorder_soon"] and p["days_cover"] is not None and p["days_cover"] < p["lead_days"]]
    if soon:
        add("med", "Forecast", f"{len(soon)} product(s) will run out before a new order can arrive", names(soon), "reorder")
    t = today()
    for r in c.execute("SELECT * FROM sales WHERE shop_id=? AND status='VOID' AND ts>=? ORDER BY id DESC", (shop(), days_ago(30))):
        add("med", "Void", f"Voided sale {r['invoice_no']}", f"{r['total']:,.0f} by cashier {r['user']}, voided by {r['void_by']}: {r['void_reason']}", "sales", r["ts"])
    for r in c.execute("SELECT s.invoice_no, s.user, s.ts, si.label, si.unit_price, si.unit_cost FROM sale_items si JOIN sales s ON s.id=si.sale_id "
                       "WHERE s.shop_id=? AND s.status='PAID' AND s.ts>=? AND si.unit_price<si.unit_cost ORDER BY s.id DESC", (shop(), days_ago(30))):
        add("high", "Below cost", f"Sold below cost: {r['label']}", f"{r['invoice_no']} by {r['user']} at {r['unit_price']:,.0f} (cost {r['unit_cost']:,.0f})", "sales", r["ts"])
    for r in c.execute("SELECT s.invoice_no, s.user, s.ts, si.label, si.unit_price, si.list_price FROM sale_items si JOIN sales s ON s.id=si.sale_id "
                       "WHERE s.shop_id=? AND s.status='PAID' AND s.ts>=? AND si.list_price>0 AND si.unit_price<si.list_price*0.9 AND si.unit_price>=si.unit_cost ORDER BY s.id DESC", (shop(), days_ago(30))):
        add("med", "Discount", f"Deep discount: {r['label']}", f"{r['invoice_no']} by {r['user']}: {r['unit_price']:,.0f} vs {r['list_price']:,.0f} list ({(1 - r['unit_price'] / r['list_price']) * 100:.0f}% off)", "sales", r["ts"])
    for r in c.execute("SELECT * FROM movements WHERE shop_id=? AND kind='OUT' AND ts>=? ORDER BY id DESC", (shop(), days_ago(30))):
        add("med", "Write-off", f"Manual stock-out: {r['label']}", f"{r['delta']} unit(s) by {r['user']}. {r['note']}", "mov", r["ts"])
    for r in c.execute("SELECT * FROM audit WHERE shop_id=? AND action='product.update' AND ts>=? AND (detail LIKE '%price%' OR detail LIKE '%cost%') ORDER BY id DESC", (shop(), days_ago(7))):
        add("low", "Price change", "Price/cost edited", f"{r['detail']} (by {r['user']})", "audit", r["ts"])
    dead = dead_stock(c, 90)
    if dead:
        add("low", "Dead stock", f"{len(dead)} model(s) have not sold in 90+ days", f"{sum(d['tied_capital'] for d in dead):,.0f} of capital is tied up", "dead")
    order = {"high": 0, "med": 1, "low": 2}
    A.sort(key=lambda a: (order[a["severity"]], a["ts"] or ""), reverse=False)
    return A[:150]


def h_alerts(c, ctx, q, body):
    return build_alerts(c)


def h_audit(c, ctx, q, body):
    term = q.get("q", [""])[0]
    sql, args = "SELECT * FROM audit WHERE shop_id=?", [shop()]
    if term:
        sql += " AND (action LIKE ? OR detail LIKE ? OR user LIKE ?)"; args += [f"%{term}%"] * 3
    return [dict(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT 400", args)]


# ================================================================ users, settings, export
def h_me(c, ctx, q, body):
    return {"username": ctx["username"], "name": ctx["name"], "role": ctx["role"],
            "settings": {x["key"]: x["value"] for x in c.execute("SELECT key, value FROM settings WHERE shop_id=?", (shop(),))}, "payments": PAYMENTS, "out_reasons": OUT_REASONS,
            "max_emp_discount": MAX_EMP_DISCOUNT}


def h_password(c, ctx, q, body):
    r = c.execute("SELECT * FROM users WHERE id=?", (ctx["user_id"],)).fetchone()
    if not check_pw(str(body.get("old") or ""), r["pw_hash"], r["salt"]):
        raise ApiError("Current password is incorrect.", 403)
    new = str(body.get("new") or "")
    if len(new) < 6:
        raise ApiError("New password must be at least 6 characters.")
    h, s = hash_pw(new)
    c.execute("UPDATE users SET pw_hash=?, salt=? WHERE id=?", (h, s, r["id"]))
    audit(c, ctx, "user.password", "user", r["id"], "changed own password")
    return {"ok": True}


def h_users(c, ctx, q, body):
    return [dict(r) for r in c.execute("SELECT id,username,name,role,active,pending,created_at FROM users WHERE owner_id=? ORDER BY pending DESC, id", (shop(),))]


def h_user_approve(c, ctx, q, body, uid, action):
    u = c.execute("SELECT * FROM users WHERE id=? AND owner_id=? AND pending=1", (int(uid), shop())).fetchone()
    if not u:
        raise ApiError("No pending request found.", 404)
    if action == "approve":
        c.execute("UPDATE users SET pending=0, active=1 WHERE id=?", (u["id"],))
    else:
        c.execute("DELETE FROM users WHERE id=?", (u["id"],))
    audit(c, ctx, "user." + action, "user", u["id"], f"{u['username']} ({u['role']})")
    return {"ok": True}


def h_user_save(c, ctx, q, body, uid=None):
    role = body.get("role")
    if role not in ("owner", "employee", "purchasing"):
        raise ApiError("Pick a role.")
    name = text(body, "name", maxlen=60)
    pw = str(body.get("password") or "")
    if uid:
        u = c.execute("SELECT * FROM users WHERE id=? AND owner_id=?", (int(uid), shop())).fetchone()
        if not u:
            raise ApiError("User not found", 404)
        active = 1 if body.get("active") in (1, True, "1", "true", "on") else 0
        if u["id"] == ctx["user_id"] and (not active or role != "owner"):
            raise ApiError("You cannot deactivate or demote your own account.")
        c.execute("UPDATE users SET name=?, role=?, active=? WHERE id=?", (name, role, active, u["id"]))
        if pw:
            if len(pw) < 6:
                raise ApiError("Password must be at least 6 characters.")
            h, s = hash_pw(pw)
            c.execute("UPDATE users SET pw_hash=?, salt=? WHERE id=?", (h, s, u["id"]))
        if not active:
            c.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],))
        audit(c, ctx, "user.update", "user", u["id"], f"{u['username']} role={role} active={active}" + (" password reset" if pw else ""))
        return {"id": u["id"]}
    uname = text(body, "username", maxlen=30).lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", uname):
        raise ApiError("Username: 3-30 letters, numbers, dot, dash or underscore.")
    if len(pw) < 6:
        raise ApiError("Password must be at least 6 characters.")
    h, s = hash_pw(pw)
    try:
        uid = c.execute("INSERT INTO users(username,name,role,pw_hash,salt,owner_id,created_at) VALUES(?,?,?,?,?,?,?)", (uname, name, role, h, s, shop(), now())).lastrowid
    except sqlite3.IntegrityError:
        raise ApiError("That username is taken.")
    audit(c, ctx, "user.create", "user", uid, f"{uname} ({role})")
    return {"id": uid}


def h_settings_put(c, ctx, q, body):
    for k in ("shop_name", "address", "phone", "tin", "footer"):
        if k in body:
            c.execute("INSERT INTO settings(shop_id,key,value) VALUES(?,?,?) ON CONFLICT(shop_id,key) DO UPDATE SET value=excluded.value", (shop(), k, text(body, k, False, 300)))
    if "allow_signup" in body:
        c.execute("INSERT INTO settings(shop_id,key,value) VALUES(?,'allow_signup',?) ON CONFLICT(shop_id,key) DO UPDATE SET value=excluded.value",
                  (shop(), "1" if body.get("allow_signup") in (1, True, "1", "on", "true") else "0"))
    audit(c, ctx, "settings.update", "settings", "", "shop details changed")
    return {"ok": True}


# ================================================================ auth
FAILS = {}


def h_login_info(c, ctx, q, body):
    return {"shop": APP_NAME, "users": c.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]}


def h_shops(c, ctx, q, body):
    """Shops whose owners accept staff requests (shown to staff when they sign up)."""
    return [dict(r) for r in c.execute(
        "SELECT u.id, u.name owner, COALESCE(st.value,'') shop FROM users u "
        "LEFT JOIN settings st ON st.shop_id=u.id AND st.key='shop_name' "
        "LEFT JOIN settings sg ON sg.shop_id=u.id AND sg.key='allow_signup' "
        "WHERE u.role='owner' AND u.active=1 AND u.pending=0 AND u.owner_id=u.id AND COALESCE(sg.value,'1')='1' ORDER BY st.value, u.name")]


def h_login(c, ctx, q, body):
    uname = str(body.get("username") or "").strip().lower()
    key = (uname, ctx.get("ip"))
    cnt, first = FAILS.get(key, (0, 0))
    if cnt >= 5 and time.time() - first < 300:
        raise ApiError("Too many failed attempts. Try again in a few minutes.", 429)
    u = c.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
    if not u or not check_pw(str(body.get("password") or ""), u["pw_hash"], u["salt"]):
        FAILS[key] = (cnt + 1 if time.time() - first < 300 else 1, first if cnt and time.time() - first < 300 else time.time())
        raise ApiError("Wrong username or password.", 401)
    FAILS.pop(key, None)
    if u["pending"]:
        o = c.execute("SELECT name FROM users WHERE id=?", (u["owner_id"],)).fetchone()
        raise ApiError(f"Your account is waiting for approval by {o['name'] if o else 'the shop owner'}. Try again after they approve it.", 403)
    if not u["active"]:
        raise ApiError("This account has been disabled. Ask the shop owner.", 403)
    c.execute("DELETE FROM sessions WHERE expires_at<?", (now(),))
    tok = secrets.token_urlsafe(32)
    c.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
              (tok, u["id"], now(), (datetime.now() + timedelta(hours=SESSION_HOURS)).strftime(FMT)))
    audit(c, {"username": u["username"], "shop": u["owner_id"]}, "login", "user", u["id"], "signed in")
    ck = f"sid={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_HOURS * 3600}"
    return Resp(json.dumps({"ok": True, "role": u["role"]}).encode(), headers={"Set-Cookie": ck})


REG_FAILS = {}


def h_register(c, ctx, q, body):
    ip = ctx.get("ip")
    cnt, first = REG_FAILS.get(ip, (0, 0))
    if cnt >= 10 and time.time() - first < 3600:
        raise ApiError("Too many sign-ups from this device. Try again later.", 429)
    uname = text(body, "username", maxlen=30).lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", uname):
        raise ApiError("Username: 3-30 letters, numbers, dot, dash or underscore.")
    name = text(body, "name", maxlen=60)
    pw = str(body.get("password") or "")
    if len(pw) < 6:
        raise ApiError("Password must be at least 6 characters.")
    if pw != str(body.get("confirm") or ""):
        raise ApiError("The two passwords do not match.")
    role = body.get("role")
    if role not in ("owner", "employee", "purchasing"):
        raise ApiError("Please choose your role.")
    owner = None
    if role == "owner":
        shop_name = text(body, "shop_name", maxlen=80)
    else:
        owner = c.execute("SELECT * FROM users WHERE id=? AND role='owner' AND active=1 AND pending=0 AND owner_id=id",
                          (int(num(body, "owner_id", int, 1)),)).fetchone() if body.get("owner_id") else None
        if not owner:
            raise ApiError("Please choose which shop owner you work for.")
        ok = c.execute("SELECT value FROM settings WHERE shop_id=? AND key='allow_signup'", (owner["id"],)).fetchone()
        if ok and ok["value"] != "1":
            raise ApiError("That owner is not accepting new staff requests. Ask them to create your account.", 403)
    h, s_ = hash_pw(pw)
    try:
        uid = c.execute("INSERT INTO users(username,name,role,pw_hash,salt,active,owner_id,pending,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (uname, name, role, h, s_, 1 if role == "owner" else 0, owner["id"] if owner else 0, 0 if role == "owner" else 1, now())).lastrowid
    except sqlite3.IntegrityError:
        raise ApiError("That username is already taken.")
    REG_FAILS[ip] = (cnt + 1 if time.time() - first < 3600 else 1, first if cnt and time.time() - first < 3600 else time.time())
    if role != "owner":
        audit(c, {"username": uname, "shop": owner["id"]}, "user.request", "user", uid, f"{name} asked to join as {role}")
        return {"ok": True, "pending": True, "owner": owner["name"]}
    c.execute("UPDATE users SET owner_id=? WHERE id=?", (uid, uid))     # the owner's own shop
    create_shop(c, uid, shop_name)
    audit(c, {"username": uname, "shop": uid}, "user.signup", "user", uid, f"new shop '{shop_name}' created by {name}")
    tok = secrets.token_urlsafe(32)
    c.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
              (tok, uid, now(), (datetime.now() + timedelta(hours=SESSION_HOURS)).strftime(FMT)))
    ck = f"sid={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_HOURS * 3600}"
    return Resp(json.dumps({"ok": True, "role": role}).encode(), headers={"Set-Cookie": ck})


def h_logout(c, ctx, q, body):
    c.execute("DELETE FROM sessions WHERE token=?", (ctx["token"],))
    return Resp(b'{"ok":true}', headers={"Set-Cookie": "sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})


def session_user(c, sid):
    if not sid:
        return None
    r = c.execute("SELECT u.id user_id, u.username, u.name, u.role, u.owner_id shop FROM sessions s JOIN users u ON u.id=s.user_id "
                  "WHERE s.token=? AND s.expires_at>? AND u.active=1 AND u.pending=0", (sid, now())).fetchone()
    return dict(r, token=sid) if r else None


