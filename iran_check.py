#!/usr/bin/env python3
"""
Iran reachability checker via the free check-host.net API.

چرا این ماژول وجود داره؟
گیت‌هاب اکشن از خارج از ایران تست می‌کنه؛ پس کانفیگ‌هایی که IPشون برای
کاربر داخل ایران فیلتر شده ولی از بقیه دنیا سالمه، از تست عادی رد میشن
و غلط به ساب خروجی راه پیدا می‌کنن.

این ماژول در لحظه‌ی اجرا:
  1) لیست نودهای مانیتورینگ داخل ایران رو مستقیم از API سایت
     check-host.net می‌گیره (/nodes/hosts -> کشور "ir").
     ==> هیچ آیپی یا نام نودی توی کد هاردکد نیست؛ اگر سایت نود اضافه/کم
         کنه، اسکریپت خودکار همراهش آپدیت میشه.
  2) برای هر IP/دامنه‌ی یکتا یک پینگ واقعی (۴ بار روی هر نود) از داخل
     ایران می‌گیره.
  3) تصمیم‌گیری:
       - اکثریت لازم از نودهای ایران جواب دادن           -> "pass"    (نگه داشته میشه)
       - دنیا در دسترس ولی ایران عملاً قطع               -> "blocked" (از خروجی حذف میشه)
       - داده‌ی ناکافی / خطای API / سرور اصلاً ICMP جواب نمیده -> "unknown" (نگه داشته میشه؛
         تست اصلی سمت گیت‌هاب مرجع میمونه — fail-open تا هیچ‌وقت کل ساب
         به‌خاطر خطای یک سایت بیرونی خالی نشه)
  4) نتیجه‌ی هر IP تا iran_cache_hours ساعت (پیش‌فرض ۲۴) تو فایل
     iran_cache.json کش میشه تا اجراهای مکرر API رو اذیت نکنه و عملاً
     «روزی یک بار تست» برقرار باشه.

استفاده‌ی مستقل (تست دستی):
    python iran_check.py 172.67.70.142 104.16.157.77
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

API_BASE = "https://check-host.net"
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iran_cache.json")
HTTP_UA = "Mozilla/5.0 (X11; Linux x86_64) subscription-health-checker"

REQUEST_TIMEOUT = 25   # ثانیه، برای هر درخواست HTTP به check-host
START_GAP = 0.05       # فاصله بین شروع چک‌ها (مودبانه با سرور، دور از rate-limit)
POLL_INTERVAL = 4      # فاصله‌ی هر دور چک کردن نتیجه‌ها
MIN_WAIT = 30          # حداقل زمان صبر برای کامل شدن نتایج (نودهای ایران دیر می‌نویسن)
MAX_WAIT = 240         # حداکثر انتظار برای کامل شدن نتایج (ثانیه)
STALL_LIMIT = 13       # اگر این‌قدر هیچ داده‌ی تازه‌ای نرسید، با داده‌ی موجود قضاوت کن
SUBMIT_WORKERS = 6     # درخواست‌های همزمان برای شروع چک‌ها
POLL_WORKERS = 8       # درخواست‌های همزمان برای گرفتن نتیجه‌ها


# ─────────────────────────── HTTP helpers ───────────────────────────

def _get(path, params=None, tries=3):
    """GET به API با Accept: application/json + چند بار تلاش در خطا."""
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(
                API_BASE + path + qs,
                headers={"Accept": "application/json", "User-Agent": HTTP_UA},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            last = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"check-host API {path} failed after {tries} tries: {last}")


def get_iran_nodes():
    """لیست نودهای مانیتورینگ داخل ایران — هر بار زنده از خود سایت."""
    data = _get("/nodes/hosts")
    nodes = []
    for name, info in (data.get("nodes") or {}).items():
        loc = info.get("location") or []
        if loc and str(loc[0]).lower() == "ir":
            nodes.append(name)
    if not nodes:
        raise RuntimeError("check-host.net currently lists no Iranian nodes")
    return sorted(nodes)


def _start_ping(host):
    """شروع یک چک پینگ غیرهمزمان؛ request_id برمی‌گردونه."""
    data = _get("/check-ping", {"host": host})
    rid = data.get("request_id")
    if not rid:
        raise RuntimeError(f"no request_id for {host!r}: {data}")
    return rid


# ─────────────────────────── result parsing ───────────────────────────

def _attempts(value):
    """خروجی check-host تو در توئه ([[["OK",0.08,"ip"],...]])؛ یکدستش می‌کنیم."""
    if not isinstance(value, list) or not value:
        return []
    inner = value
    while (
        len(inner) == 1
        and isinstance(inner[0], list)
        and inner[0]
        and isinstance(inner[0][0], list)
    ):
        inner = inner[0]
    return [a for a in inner if isinstance(a, list) and a]


def _node_summary(attempts):
    """(تعداد موفق، کل، میانگین تأخیر موفق‌ها به میلی‌ثانیه)"""
    ok = 0
    ms = []
    for a in attempts:
        if a and a[0] == "OK":
            ok += 1
            try:
                ms.append(float(a[1]) * 1000.0)
            except Exception:
                pass
    avg = (sum(ms) / len(ms)) if ms else None
    return ok, len(attempts), avg


def _evaluate(per_node, iran_nodes, min_ok_nodes, min_ok_pings):
    """
    per_node: {node_name: raw_result_or_None} برای همه‌ی نودها (ایران + دنیا)
    برمی‌گردونه: dict با verdict/pass-stats.
    """
    iran_set = set(iran_nodes)
    ir_good, ir_ms, ir_responded = 0, [], 0
    world_seen, world_ok = 0, 0

    for node, val in per_node.items():
        att = _attempts(val)
        if not att:
            continue  # این نود هنوز داده نداره / جواب نداده
        ok, _tot, avg = _node_summary(att)
        if node in iran_set:
            ir_responded += 1
            if ok >= min_ok_pings:
                ir_good += 1
                if avg is not None:
                    ir_ms.append(avg)
        else:
            world_seen += 1
            if ok > 0:
                world_ok += 1

    if ir_responded == 0:
        return {
            "verdict": "unknown", "iran_avg_ms": None,
            "ir_good": 0, "ir_responded": 0, "world_ok": world_ok, "needed": 0,
        }

    # حداقل نودهای ایرانِ موردنیاز: عدد تنظیم‌شده، یا ۷۵٪ نودهای آنلاینِ الان
    # (هرکدوم کمتر بود) — تا اگر موقتاً مثلاً فقط ۴ نود ایران فعال بود،
    # شرط غیرواقعیِ «۵ نود» کل خروجی رو نبُره.
    needed = max(2, min(min_ok_nodes, -(-3 * ir_responded // 4)))

    if ir_good >= needed:
        verdict = "pass"
    elif world_ok >= 2:
        # از بقیه‌ی دنیا در دسترسه ولی از ایران نه ⇒ فیلتر مخصوص ایران
        verdict = "blocked"
    else:
        # نه داده‌ی ایران کافی نه نشونه‌ی دسترسی جهانی ⇒ تکلیف روشنه نیست؛
        # fail-open: حذف نمی‌کنیم، تست اصلی گیت‌هاب مرجه.
        verdict = "unknown"

    avg_all = (sum(ir_ms) / len(ir_ms)) if ir_ms else None
    return {
        "verdict": verdict, "iran_avg_ms": avg_all,
        "ir_good": ir_good, "ir_responded": ir_responded,
        "world_ok": world_ok, "needed": needed,
    }


# ─────────────────────────── cache ───────────────────────────

def _load_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_cache(cache):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"WARNING: could not write {CACHE_FILE}: {e}")


# ─────────────────────────── live runner ───────────────────────────

def _run_live(targets, min_ok_nodes, min_ok_pings, log):
    iran_nodes = get_iran_nodes()
    log(
        f"  Iran nodes discovered live: {len(iran_nodes)} "
        f"({', '.join(n.split('.')[0] for n in iran_nodes)})"
    )

    pending = {}                       # target -> request_id
    errors = {}

    def _submit(t):
        try:
            return t, _start_ping(t)
        except Exception as e:
            return t, e

    with ThreadPoolExecutor(max_workers=SUBMIT_WORKERS) as pool:
        for t, res in pool.map(_submit, targets):
            if isinstance(res, Exception):
                errors[t] = res
                log(f"  WARNING: could not start Iran ping for {t}: {res}")
            else:
                pending[t] = res

    # بعضی نودها ممکنه اصلاً تو خروجی API ظاهر نشن (نود آفلاین). برای هر هدف
    # بهترین داده‌ی دیده‌شده از نودهای ایران رو نگه می‌داریم؛ تا وقتی هنوز
    # داده‌ی تازه‌ای (از هر نودی) میاد، صبر می‌کنیم — نودهای ایران معمولاً
    # دیرتر از بقیه دنیا تو API ثبت میشن، پس زود قضاوت نکن.
    iran_set = set(iran_nodes)
    best_iran = {t: {} for t in pending}
    best_full = {t: {} for t in pending}   # همه‌ی نودها (دنیا + ایران) برای قضاوت نهایی
    counts = {t: 0 for t in pending}
    started = time.time()
    last_growth = time.time()

    def _poll_one(item):
        t, rid = item
        try:
            return t, _get(f"/check-result/{rid}", tries=1)
        except Exception:
            return t, None  # خطای گذرا؛ دور بعد دوباره امتحان میشه

    while pending and time.time() - started < MAX_WAIT:
        time.sleep(POLL_INTERVAL)
        grew = False
        done_now = []
        with ThreadPoolExecutor(max_workers=POLL_WORKERS) as pool:
            for t, data in pool.map(_poll_one, list(pending.items())):
                if not isinstance(data, dict):
                    continue
                for n, v in data.items():
                    if not v:
                        continue
                    if n in iran_set and n not in best_iran[t]:
                        best_iran[t][n] = v
                    best_full[t][n] = v
                if len(best_iran[t]) >= len(iran_nodes):
                    counts[t] = len(iran_nodes)   # کامل شد
                    done_now.append(t)
                elif len(best_iran[t]) > counts.get(t, 0):
                    counts[t] = len(best_iran[t])
                if data:
                    grew = True  # هر داده‌ای یعنی هنوز نتایج داره میرسد
        for t in done_now:
            del pending[t]
        if not pending or all(counts.get(t, 0) >= len(iran_nodes) for t in pending):
            break
        if grew or time.time() - started < MIN_WAIT:
            last_growth = time.time()
        if time.time() - last_growth > STALL_LIMIT:
            log("  NOTE: results stopped arriving; continuing with partial data")
            break

    out = {}
    for t in targets:
        per_node = best_full.get(t) or {}
        if not per_node:
            log(f"  WARNING: no Iran result for {t} -> kept (unknown)")
            out[t] = {"verdict": "unknown", "iran_avg_ms": None,
                      "ir_good": 0, "ir_responded": 0, "world_ok": 0, "needed": 0}
            continue
        r = _evaluate(per_node, iran_nodes, min_ok_nodes, min_ok_pings)
        ms = r.get("iran_avg_ms")
        log(
            f"  {t}: {r['verdict'].upper()} "
            f"(iran {r['ir_good']}/{r['ir_responded']} nodes OK, needed {r['needed']}, "
            f"world_ok {r['world_ok']}"
            + (f", avg {ms:.0f}ms" if ms else "") + ")"
        )
        out[t] = r
    return out


# ─────────────────────────── public entry ───────────────────────────

def check_addresses(addresses, min_ok_nodes=5, min_ok_pings=3,
                    cache_hours=24.0, log=None):
    """
    addresses: لیست hostname/IP (بدون پورت).
    خروجی: {addr: {"verdict": "pass|blocked|unknown", "iran_avg_ms": float|None, ...}}
    """
    log = log or (lambda s: None)
    now = time.time()
    cache = _load_cache()

    results, todo, cached = {}, [], 0
    for a in addresses:
        ent = cache.get(a)
        if ent and (now - ent.get("ts", 0)) <= float(cache_hours) * 3600.0:
            results[a] = {
                "verdict": ent.get("verdict", "unknown"),
                "iran_avg_ms": ent.get("iran_avg_ms"),
                "cached": True,
            }
            cached += 1
        else:
            todo.append(a)
    log(f"  Iran check: {len(addresses)} unique host(s) | {cached} cached, {len(todo)} fresh")
    if cached:
        log("  (delete iran_cache.json to force a full fresh re-test)")

    if todo:
        try:
            live = _run_live(todo, min_ok_nodes, min_ok_pings, log)
        except Exception as e:
            log(f"  WARNING: live Iran check failed ({e}) -> {len(todo)} host(s) kept as unknown")
            live = {a: {"verdict": "unknown", "iran_avg_ms": None,
                        "ir_good": 0, "ir_responded": 0, "world_ok": 0, "needed": 0}
                    for a in todo}
        results.update(live)
        for a, r in live.items():
            cache[a] = {"ts": now, "verdict": r["verdict"], "iran_avg_ms": r.get("iran_avg_ms")}
        _save_cache(cache)

    return results


if __name__ == "__main__":
    hosts = sys.argv[1:] or ["172.67.70.142", "104.16.157.77"]
    res = check_addresses(hosts, log=print)
    print("\nSummary:")
    for h in hosts:
        r = res.get(h, {})
        print(f"  {h} -> {r.get('verdict')} (iran_avg_ms={r.get('iran_avg_ms')})")
