#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用多站点签到面板（不写死任何网站）
====================================
零第三方依赖，纯 Python stdlib。浏览器打开 http://127.0.0.1:8799

能力:
  - 任意站点签到接口可配: URL / 方法 / 请求头 / 请求体 / 判定规则
  - 凭据占位符: {{user}} {{pass}} {{token}} {{cookie}} (自动代入账号资料与最新 token)
  - 三种登录态: none(固定头/Cookie) / cookie(手动贴 Cookie) / login(自动登录换 token, 401 自动重登)
  - 每个账号单独设置每日签到时间 HH:MM，可开关
  - 成功/已签/失败 三态判定: 状态码集合 + already 特征串 + fail 特征串
  - 结果历史留存, JSON 文件持久化, 重启不重复签

启动:  python checkin_panel.py
环境变量: HD_PORT=8799  HD_BIND=127.0.0.1  (放服务器改 0.0.0.0 并自配防火墙)
"""
import json, os, re, ssl, sys, threading, time, uuid, hashlib, hmac, secrets
import urllib.request, urllib.error
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, "checkin_tasks.json")
AUTH_FILE = os.path.join(BASE, "checkin_auth.json")
LOG_FILE = os.path.join(BASE, "checkin_panel.log")
PORT = int(os.environ.get("HD_PORT", "8799"))
BIND = os.environ.get("HD_BIND", "127.0.0.1")

_CTX = ssl._create_unverified_context()  # 签到面板常碰自签/旧站, 放宽证书校验
_LOCK = threading.Lock()

# ================= 登录系统（面板自身鉴权） =================
_AUTH = {"user": "", "salt": "", "hash": "", "iter": 200000}
_SESSIONS = {}          # token -> {"user":..., "exp":...}
SESSION_TTL = 30 * 86400  # 30 天
_FAIL = {}              # ip -> (count, last_ts) 简易防爆破

def _hash_pw(pw, salt, iters=_AUTH["iter"]):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), iters).hex()

def load_auth():
    global _AUTH
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        if d.get("user") and d.get("hash"):
            _AUTH.update(d)
            return True
    except Exception:
        pass
    return False

def auth_initialized():
    return bool(_AUTH.get("hash"))

def setup_admin(user, pw):
    if auth_initialized():
        return False, "管理员已存在"
    user = (user or "").strip()
    if len(user) < 2:
        return False, "用户名至少 2 个字符"
    if len(pw or "") < 6:
        return False, "密码至少 6 位"
    salt = secrets.token_hex(16)
    _AUTH["user"] = user
    _AUTH["salt"] = salt
    _AUTH["hash"] = _hash_pw(pw, salt)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_AUTH, f)
    os.replace(tmp, AUTH_FILE)
    try:
        os.chmod(AUTH_FILE, 0o600)
    except OSError:
        pass
    return True, "创建成功"

def verify_login(user, pw):
    if not auth_initialized():
        return False
    return hmac.compare_digest(_hash_pw(pw or "", _AUTH["salt"]), _AUTH["hash"]) and user == _AUTH["user"]

def change_credentials(old_pw, new_user="", new_pw=""):
    """改用户名/密码；至少改一项，密码需验证旧密。"""
    if not verify_login(_AUTH["user"], old_pw):
        return False, "当前密码不正确"
    nu = (new_user or "").strip()
    if nu and len(nu) < 2:
        return False, "用户名至少 2 个字符"
    if new_pw and len(new_pw) < 6:
        return False, "新密码至少 6 位"
    if not nu and not new_pw:
        return False, "用户名与新密码至少填一项"
    if nu:
        _AUTH["user"] = nu
    if new_pw:
        _AUTH["salt"] = secrets.token_hex(16)
        _AUTH["hash"] = _hash_pw(new_pw, _AUTH["salt"])
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_AUTH, f)
    os.replace(tmp, AUTH_FILE)
    _SESSIONS.clear()  # 改密后全部会话失效
    return True, "已更新，需重新登录"

def new_session(user):
    tok = secrets.token_urlsafe(32)
    _SESSIONS[tok] = {"user": user, "exp": time.time() + SESSION_TTL}
    return tok

def session_valid(tok):
    s = _SESSIONS.get(tok or "")
    if not s:
        return False
    if s["exp"] < time.time():
        _SESSIONS.pop(tok, None)
        return False
    return True

def _cookie_val(header, name):
    for part in (header or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return ""

def login_throttle(ip):
    c, ts = _FAIL.get(ip, (0, 0))
    if c >= 8 and time.time() - ts < 300:
        return True
    if time.time() - ts > 300:
        c = 0
    _FAIL[ip] = (c + 1, time.time())
    return False

def login_unthrottle(ip):
    _FAIL.pop(ip, None)

def now_cn():
    return datetime.now(timezone(timedelta(hours=8)))

# ---------------- 邮件告警 (参考 AutoBackup notifier: 465=SSL 其余 STARTTLS, host 归一化, 失败静默降级) ----------------
def normalize_smtp_host(raw):
    import re as _re
    h = (raw or "").strip()
    h = _re.sub(r"^[a-z][a-z0-9+.-]*://", "", h, flags=_re.I)
    h = _re.sub(r"/.*$", "", h)
    h = _re.sub(r":\d+$", "", h)
    return h

def smtp_cfg(db):
    n = (db or {}).get("notify") or {}
    host = normalize_smtp_host(n.get("smtp_host", ""))
    user, pw, to = n.get("smtp_user", ""), n.get("smtp_pass", ""), n.get("mail_to", "")
    if not (host and user and pw and to):
        return None
    port = int(n.get("smtp_port") or 465)
    return {"host": host, "port": port, "secure": port == 465, "user": user, "pass": pw, "to": to}

def send_mail(cfg, subject, text):
    """独立建连、用完即关；绝不抛出（通道故障只记日志）。"""
    import smtplib
    from email.mime.text import MIMEText
    from email.header import Header
    try:
        msg = MIMEText(text, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = "签到面板 <%s>" % cfg["user"]
        msg["To"] = cfg["to"]
        if cfg["secure"]:
            srv = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=20, context=_CTX)
        else:
            srv = smtplib.SMTP(cfg["host"], cfg["port"], timeout=20)
            srv.starttls(context=_CTX)
        try:
            srv.login(cfg["user"], cfg["pass"])
            srv.sendmail(cfg["user"], [cfg["to"]], msg.as_string())
        finally:
            srv.quit()
        return True, ""
    except Exception as e:
        return False, str(e)

def notify_fail_once(db, t, msg):
    """每天每任务首次失败只提醒一次；之后当天重试再失败不再发（防轰炸）。任务开关关闭则不提醒。"""
    if not t.get("notify_mail", True):
        return
    cfg = smtp_cfg(db)
    if not cfg:
        return
    st = t["state"]
    today = now_cn().strftime("%Y-%m-%d")
    if st.get("notified_day") == today:
        return  # 今天已提醒过
    subject = "⚠️ 签到失败：%s" % (t.get("name") or t["id"])
    text = "\n".join([
        "任务：%s（组：%s）" % (t.get("name") or "-", t.get("group") or "未分组"),
        "账号：%s" % (t.get("cred", {}).get("user") or "-"),
        "时间：%s（北京时间）" % st.get("last_at", now_cn().isoformat(timespec="seconds")),
        "原因：%s" % (msg or "")[:300],
        "",
        "面板将按设定间隔自动重试；若后续重试仍失败，今日不再重复提醒。",
        "—— checkin_panel 自动告警，请勿回复",
    ])
    ok, err = send_mail(cfg, subject, text)
    st["notified_day"] = today  # 失败也记，避免每轮都狂发
    log("邮件提醒 %s: %s%s" % ("已发" if ok else "失败", t.get("name"), "" if ok else " - " + err[:120]))

def log(msg):
    line = "[%s] %s" % (now_cn().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass

# ---------- HTTP 底层 ----------
def http_call(method, url, headers=None, body=None, timeout=30):
    data = None
    if body is not None and body != "":
        data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            raw = r.read().decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status, raw, hdrs
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, raw, hdrs
    except Exception as e:
        return 0, str(e), {}

def try_json(s):
    try:
        return json.loads(s)
    except Exception:
        return None

# ---------- 模板代入 ----------
def render(tpl, ctx):
    if isinstance(tpl, str):
        def rep(m):
            return str(ctx.get(m.group(1), ""))
        return re.sub(r"\{\{\s*(\w+)\s*\}\}", rep, tpl)
    if isinstance(tpl, dict):
        return {render(k, ctx): render(v, ctx) for k, v in tpl.items()}
    if isinstance(tpl, list):
        return [render(x, ctx) for x in tpl]
    return tpl

def extract_path(obj, path):
    """'data.access_token' / 'headers.x-token' —— 点路径提取"""
    if not path:
        return None
    cur = obj
    for key in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and key.isdigit():
            cur = cur[int(key)] if int(key) < len(cur) else None
        else:
            return None
    return cur

# ---------- DB ----------
def load_db():
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"tasks": []}

def save_db(db):
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_FILE)

def blank_task():
    return {
        "id": uuid.uuid4().hex[:10], "name": "", "group": "", "enabled": True, "time": "09:00",
        "cred": {"user": "", "pass": "", "cookie": ""},
        "auth_mode": "login",
        "login": {"url": "", "method": "POST", "headers": {}, "body": "", "token_path": "token", "token_header": ""},
        "checkin": {"url": "", "method": "POST", "headers": {}, "body": ""},
        "judge": {"ok_status": "200,201,204", "already": "", "fail": "", "ok_msg": ""},
        "balance": {"url": "", "method": "GET", "path": "data.traffic_bytes"},
        "retry_on_fail": True, "retry_hours": 6, "retry_max": 0, "notify_mail": True,
        "state": {"token": "", "token_exp": 0, "last_date": "", "last_status": "", "last_msg": "", "last_at": "", "history": []},
    }

# ---------- 登录换 token ----------
def do_login(t):
    lg = t["login"]
    ctx = ctx_of(t)
    url = render(lg["url"], ctx)
    if not url:
        t["state"]["auth_ok"] = False
        t["state"]["auth_msg"] = "登录接口 URL 未配置"
        t["state"]["auth_at"] = now_cn().isoformat(timespec="seconds")
        return False, "未配置登录接口 URL（登录方式选错了？请改为固定Token/Cookie 或补全登录接口）"
    headers = render(lg.get("headers") or {}, ctx)
    body = render(lg.get("body") or "", ctx)
    if body and "content-type" not in {k.lower() for k in headers}:
        headers["content-type"] = "application/json"
    s, raw, hdrs = http_call(lg.get("method", "POST"), url, headers, body)
    st = t["state"]
    if s not in (200, 201):
        st["auth_ok"] = False
        st["auth_msg"] = "登录接口返回 HTTP %s" % s
        st["auth_at"] = now_cn().isoformat(timespec="seconds")
        return False, "登录 HTTP %s: %s" % (s, raw[:120])
    tj = try_json(raw)
    tokpath = lg.get("token_path", "token")
    tok = None
    if tokpath == "set-cookie":
        sc = hdrs.get("set-cookie", "")
        tok = sc.split(";")[0] if sc else None
    elif tj is not None:
        tok = extract_path(tj, tokpath)
    if tok is None and lg.get("token_header"):
        tok = hdrs.get(lg["token_header"].lower())
    if not tok:
        st["auth_ok"] = False
        st["auth_msg"] = "登录成功但提取不到 token（路径不对）"
        st["auth_at"] = now_cn().isoformat(timespec="seconds")
        return False, "登录成功但提取不到 token (路径: %s)" % tokpath
    t["state"]["token"] = str(tok)
    t["state"]["token_exp"] = time.time() + 6 * 86400  # 保守 6 天, 失效靠 401 重登兜底
    st["auth_ok"] = True
    st["auth_msg"] = "登录成功，已取到 token"
    st["auth_at"] = now_cn().isoformat(timespec="seconds")
    return True, "登录成功"

def ctx_of(t):
    c = t.get("cred", {})
    return {"user": c.get("user", ""), "pass": c.get("pass", ""),
            "cookie": c.get("cookie", ""), "token": t["state"].get("token", ""),
            "date": now_cn().strftime("%Y-%m-%d"), "ts": str(int(time.time()))}

def token_fresh(t):
    return t["state"].get("token") and t["state"].get("token_exp", 0) > time.time()

# ---------- 执行签到 ----------
def run_checkin(t):
    st = t["state"]
    ctx = ctx_of(t)
    ck_url = (t.get("checkin") or {}).get("url") or ""
    if not ck_url:
        return "fail", "未配置签到接口 URL"
    # 需要登录态且 token 不新鲜 -> 先登
    if t["auth_mode"] == "login" and not token_fresh(t):
        ok, msg = do_login(t)
        if not ok:
            return "fail", msg
        ctx = ctx_of(t)
    ck = t["checkin"]
    if (t.get("balance") or {}).get("url"):
        ctx["_bal_before"] = _balance(t, ctx)
    def attempt():
        headers = render(ck.get("headers") or {}, ctx)
        body = render(ck.get("body") or "", ctx)
        if body and "content-type" not in {k.lower() for k in headers}:
            headers["content-type"] = "application/json"
        return http_call(ck.get("method", "POST"), render(ck["url"], ctx), headers, body)
    s, raw, _ = attempt()
    # 401 自动重登再试一次
    if s == 401 and t["auth_mode"] == "login":
        ok, msg = do_login(t)
        if not ok:
            return "fail", "token失效且重登失败: " + msg
        ctx = token_ctx = ctx_of(t)
        s, raw, _ = attempt()

    j = t["judge"]
    ok_codes = {int(x) for x in re.findall(r"\d+", j.get("ok_status", "200"))}
    already = j.get("already", "")
    failpat = j.get("fail", "")
    if already and re.search(already, raw, re.I):
        return "dup", "今天已经签到过了"
    if failpat and re.search(failpat, raw, re.I):
        return "fail", "接口返回失败：" + _brief(raw)
    if s in ok_codes:
        gain = _traffic_delta(t, ctx)
        return "ok", ("签到成功" + ("，获得 %s" % _fmt_bytes(gain) if gain > 0 else ""))
    return "fail", "请求未成功（HTTP %s）：%s" % (s, _brief(raw))

def _brief(raw):
    """从响应里提炼一句人话：优先 JSON 的 message/error.msg，否则截断原文"""
    j = try_json(raw)
    if isinstance(j, dict):
        e = j.get("error")
        if isinstance(e, dict) and e.get("message"):
            return str(e["message"])[:80]
        if j.get("message"):
            return str(j["message"])[:80]
    txt = re.sub(r"\s+", " ", raw or "").strip()
    return (txt[:80] + "…") if len(txt) > 80 else (txt or "无响应内容")

def _fmt_bytes(n):
    if n >= 1024 ** 3:
        return "%.2f GB" % (n / 1024 ** 3)
    if n >= 1024 ** 2:
        return "%.0f MB" % (n / 1024 ** 2)
    return "%d B" % n

def _balance(t, ctx):
    """可选：任务配了 balance 接口就取余额数值"""
    b = t.get("balance") or {}
    url = render(b.get("url", ""), ctx)
    if not url:
        return None
    headers = render(b.get("headers") or (t.get("checkin") or {}).get("headers") or {}, ctx)
    s, raw, _ = http_call(b.get("method", "GET"), url, headers, None)
    if s != 200:
        return None
    v = extract_path(try_json(raw), b.get("path", "data.traffic_bytes"))
    try:
        return int(v)
    except Exception:
        return None

def _traffic_delta(t, ctx):
    b = t.get("balance") or {}
    if not b.get("url"):
        return 0
    after = _balance(t, ctx)
    before = ctx.get("_bal_before")
    if after is None or before is None:
        return 0
    return max(0, after - before)

def execute_task(t, manual=False):
    today = now_cn().strftime("%Y-%m-%d")
    st = t["state"]
    if not manual and st.get("last_date") == today and st.get("last_status") in ("ok", "dup"):
        return st["last_status"]
    status, msg = run_checkin(t)
    # 手动重跑遇到「今天已签过」且上次就是成功签到 -> 保留原战果消息，不覆盖成空话
    if status == "dup" and st.get("last_date") == today and "签到成功" in (st.get("last_msg") or ""):
        return "ok"
    st = t["state"]
    # 跨天重置失败重试计数
    if st.get("retry_day") != today:
        st["retry_day"] = today
        st["retry_count"] = 0
    st["last_at"] = now_cn().isoformat(timespec="seconds")
    st["last_status"] = status
    st["last_msg"] = msg
    if status in ("ok", "dup"):
        st["last_date"] = today  # 今天不再重复
        st["retry_count"] = 0
        if not st.get("auth_ok"):
            st["auth_ok"] = True
            st["auth_msg"] = "接口连通正常" if t.get("auth_mode") != "login" else "签到通过，登录态有效"
            st["auth_at"] = now_cn().isoformat(timespec="seconds")
    else:
        st["retry_count"] = st.get("retry_count", 0) + 1
    st["history"] = ([{"at": st["last_at"], "s": status, "m": msg[:200]}] + st.get("history", []))[:20]
    log("%s [%s] %s - %s" % (t["name"] or t["id"], t["cred"].get("user") or "-", status, msg[:80]))
    return status

def retry_due(t, hm_now):
    """今天签过但失败了 -> 按 retry_hours 间隔判断是否到重试时间。"""
    if not t.get("retry_on_fail", True):
        return False
    st = t["state"]
    today = now_cn().strftime("%Y-%m-%d")
    if st.get("last_status") != "fail" or st.get("last_date") == today:
        return False  # 只重试当天失败且未成功的
    maxn = int(t.get("retry_max", 0) or 0)
    if maxn > 0 and st.get("retry_count", 0) >= maxn:
        return False
    try:
        last = datetime.fromisoformat(st["last_at"])
    except Exception:
        return False
    hours = float(t.get("retry_hours", 6) or 6)
    return (now_cn() - last).total_seconds() >= hours * 3600

def scheduler_loop():
    while True:
        try:
            hm = now_cn().strftime("%H:%M")
            today = now_cn().strftime("%Y-%m-%d")
            with _LOCK:
                db = load_db()
                due = []
                for t in db["tasks"]:
                    if not t.get("enabled"):
                        continue
                    if t.get("time", "09:00") <= hm and t["state"].get("last_date") != today:
                        # 今天还没成功：若是失败状态, 要等够 retry_hours 间隔才再跑
                        if t["state"].get("last_status") == "fail":
                            last = t["state"].get("last_at", "")
                            if last.startswith(today) and not retry_due(t, hm):
                                continue
                        due.append(t)
                ran = []
                for t in due:
                    try:
                        execute_task(t)
                    except Exception as e:
                        log("执行异常 %s: %s" % (t["id"], e))
                    if t["state"].get("last_status") == "fail":
                        notify_fail_once(db, t, t["state"].get("last_msg", ""))
                    ran.append(t)
                if ran:
                    db2 = load_db()
                    byid = {x["id"]: x for x in db2["tasks"]}
                    for t in ran:
                        if t["id"] in byid:
                            byid[t["id"]]["state"] = t["state"]
                    save_db(db2)
        except Exception as e:
            log("调度异常: %s" % e)
        time.sleep(30)

# ---------- 登录/首次设置门页 ----------
GATE = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>签到面板 · 登录</title>
<style>
:root{--bg:#0f1117;--card:#181c26;--inset:#0d1017;--fg:#e6e9ef;--mut:#8b93a7;--ac:#4f8cff;--err:#ff5c5c;--bd:#262c3a}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(1000px 500px at 50% -10%,#1b2333 0%,var(--bg) 60%);color:var(--fg);font:14px/1.6 system-ui,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;padding:20px}
.box{width:100%;max-width:360px;background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:28px 26px}
.logo{text-align:center;font-size:34px;margin-bottom:6px}
h1{font-size:17px;text-align:center;margin:0 0 4px}
.tip{color:var(--mut);font-size:12px;text-align:center;margin-bottom:20px}
.fld{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--mut);margin-bottom:12px}
input{background:var(--inset);border:1px solid var(--bd);color:var(--fg);padding:10px 12px;border-radius:9px;font-size:14px;outline:none;width:100%}
input:focus{border-color:var(--ac)}
button{width:100%;cursor:pointer;border:0;border-radius:9px;padding:11px;font-size:14px;font-weight:600;color:#fff;background:var(--ac);margin-top:6px}
button:disabled{opacity:.55;cursor:default}
.err{color:var(--err);font-size:12px;min-height:18px;margin-top:10px;text-align:center}
.warn{background:rgba(245,166,35,.12);border:1px solid rgba(245,166,35,.35);color:#f5c76a;font-size:12px;border-radius:9px;padding:9px 11px;margin-bottom:16px;line-height:1.5}
</style></head><body>
<div class="box">
<div class="logo">🔧</div>
<h1 id="title">自动签到面板</h1>
<div class="tip" id="subtitle">登录以管理你的签到任务</div>
<div class="warn" id="warn" style="display:none"></div>
<div class="fld">用户名<input id="u" autocomplete="username" maxlength="40"></div>
<div class="fld">密码<input id="p" type="password" autocomplete="current-password" maxlength="64"></div>
<div class="fld" id="p2row" style="display:none">确认密码<input id="p2" type="password" autocomplete="new-password" maxlength="64"></div>
<button id="btn" onclick="go()">登 录</button>
<div class="err" id="err"></div>
</div>
<script>
var MODE="__MODE__";
var u=document.getElementById('u'),pw=document.getElementById('p'),p2=document.getElementById('p2'),btn=document.getElementById('btn'),err=document.getElementById('err');
if(MODE==='setup'){
  document.getElementById('title').textContent='首次使用 · 创建管理员';
  document.getElementById('subtitle').textContent='为自己的签到面板设置账号密码';
  var w=document.getElementById('warn');w.style.display='';
  w.textContent='⚠️ 这个账号密码只用于打开本面板，且无法找回——请妥善记录。';
  p2row.style.display='';btn.textContent='创建并进入';u.focus();
}else{u.focus();}
function sub(d){btn.disabled=true;err.textContent='';
  fetch('/api/auth/'+(MODE==='setup'?'setup':'login'),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(d)})
  .then(function(r){return r.json()})
  .then(function(r){btn.disabled=false;
    if(r.ok){location.href='/'}else{err.textContent=r.msg||'失败'}})
  .catch(function(e){btn.disabled=false;err.textContent='网络错误: '+e})}
function go(){
  err.textContent='';
  if(!u.value.trim()){err.textContent='请输入用户名';return}
  if(!pw.value){err.textContent='请输入密码';return}
  if(MODE==='setup'){
    if(pw.value.length<6){err.textContent='密码至少 6 位';return}
    if(pw.value!==p2.value){err.textContent='两次密码不一致';return}
    return sub({user:u.value.trim(),pass:pw.value})
  }
  sub({user:u.value.trim(),pass:pw.value})}
[pw,p2,u].forEach(function(el){el.addEventListener('keydown',function(e){if(e.key==='Enter')go()})});
</script></body></html>
"""

# ---------- Web ----------
PAGE = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>自动签到面板</title>
<style>
:root{--bg:#0f1117;--card:#181c26;--inset:#0d1017;--fg:#e6e9ef;--mut:#8b93a7;--ac:#4f8cff;--ok:#3ecf8e;--warn:#f5a623;--err:#ff5c5c;--bd:#262c3a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,"Segoe UI",sans-serif}
.app{max-width:1180px;margin:0 auto;padding:28px 20px 48px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:20px;flex-wrap:wrap}
h1{font-size:21px;margin:0}
.sub{color:var(--mut);font-size:12px}
.clock{color:var(--mut);font-size:12px;font-variant-numeric:tabular-nums}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px;margin-bottom:14px;width:100%}
.card.flush{padding:0;overflow-x:auto}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{cursor:pointer;border:0;border-radius:8px;padding:9px 16px;font-size:13px;font-weight:600;color:#fff;background:var(--ac);white-space:nowrap}
button.gho{background:transparent;border:1px solid var(--bd);color:var(--fg);font-weight:400}
button.dgr{background:transparent;border:1px solid var(--bd);color:var(--err);font-weight:400}
button.sm{padding:4px 10px;font-size:12px;border-radius:6px}
input,select,textarea{background:var(--inset);border:1px solid var(--bd);color:var(--fg);padding:8px 10px;border-radius:8px;font-size:13px;outline:none;font-family:inherit}
input:focus,textarea:focus{border-color:var(--ac)}
textarea{width:100%;min-height:56px;font-family:ui-monospace,Consolas,monospace;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
th{text-align:left;color:var(--mut);font-weight:500;padding:10px 12px;border-bottom:1px solid var(--bd);white-space:nowrap;overflow:hidden}
td{padding:11px 12px;border-bottom:1px solid var(--bd);vertical-align:middle;overflow:hidden}
th.c-grp{width:76px}th.c-task{width:20%}th.c-acc{width:14%}th.c-time{width:120px}th.c-st{width:110px}th.c-sw{width:52px}th.c-act{width:240px}
td.trunc b,td.trunc div{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
tr:last-child td{border-bottom:0}
.empty{text-align:center;color:var(--mut);padding:34px 0}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;white-space:nowrap}
.b-ok{background:rgba(62,207,142,.15);color:var(--ok)}
.b-wait{background:rgba(139,147,167,.15);color:var(--mut)}
.b-err{background:rgba(255,92,92,.15);color:var(--err)}
.b-dup{background:rgba(245,166,35,.15);color:var(--warn)}
.b-grp{background:rgba(79,140,255,.15);color:var(--ac)}
.mut{color:var(--mut);font-size:12px}
.gb{font-weight:600;font-variant-numeric:tabular-nums}
.fld{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--mut)}
.fld input,.fld select{width:100%}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:8px 12px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px 12px}
.sect{border-top:1px solid var(--bd);margin:14px 0 10px}
details>summary{cursor:pointer;font-weight:600;font-size:13px;list-style:none;display:flex;align-items:center;gap:8px}
details>summary::before{content:"▸";color:var(--mut);transition:.15s}
details[open]>summary::before{content:"▾"}
.sw{position:relative;width:34px;height:19px;background:#333c50;border-radius:20px;cursor:pointer;transition:.2s;display:inline-block;flex:none}
.sw.on{background:var(--ok)}
.sw i{position:absolute;top:2px;left:2px;width:15px;height:15px;background:#fff;border-radius:50%;transition:.2s}
.sw.on i{left:17px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.65);display:none;justify-content:center;align-items:flex-start;z-index:20;overflow:auto;padding:32px 16px}
.modal.show{display:flex}
.mbox{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:22px;width:100%;max-width:780px}
.mbox h3{margin:0 0 14px;font-size:16px}
.toast{position:fixed;top:16px;right:16px;background:#232a38;border:1px solid var(--bd);padding:10px 16px;border-radius:10px;font-size:13px;opacity:0;transition:.25s;z-index:99;max-width:340px;pointer-events:none}
.toast.show{opacity:1}
.eye{position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:0;cursor:pointer;font-size:15px;padding:4px 6px;opacity:.55;line-height:1}
.eye:hover{opacity:1}
footer{color:var(--mut);font-size:12px;text-align:center;margin-top:8px}
.acts{display:flex;gap:6px}
</style></head><body>
<div class="app">

<header>
  <div><h1>🔧 自动签到面板</h1><div class="sub">通用多站点 · 多账号 · 每账号独立定时 · 失败自动重试与邮件提醒</div></div>
  <div style="text-align:right">
    <div class="clock" id="clock"></div>
    <div class="mut" style="margin-top:2px">👤 <b id="who">…</b>
      <a href="#" onclick="openAcct();return false" style="color:var(--ac);text-decoration:none;margin:0 6px">账号设置</a>
      <a href="#" onclick="logout();return false" style="color:var(--mut);text-decoration:none">退出</a></div>
  </div>
</header>

<div class="card row">
  <button onclick="openEdit()">＋ 添加任务</button>
  <button class="gho" onclick="presetHD()">示例 · Hyperdown</button>
  <button class="gho" onclick="runBatch('all')">▶ 一键全部签到</button>
  <button class="gho" onclick="load()">↻ 刷新</button>
  <span style="margin-left:auto"></span>
  <label class="fld" style="width:170px">按组筛选
    <select id="gfilter" onchange="render()"><option value="">全部</option></select>
  </label>
</div>

<div class="card">
<details id="mailcard">
<summary>📧 签到失败邮件提醒 <span class="mut">每天每任务首次失败一封，重试再失败不重复；可在任务里单独关闭</span></summary>
<div class="g3" style="margin-top:12px">
  <div class="fld">SMTP 服务器<input id="m_host" placeholder="smtp.qq.com"></div>
  <div class="fld">端口（465=SSL）<input id="m_port" type="number" value="465"></div>
  <div class="fld">发件邮箱<input id="m_user" placeholder="you@qq.com"></div>
</div>
<div class="g3" style="margin-top:8px">
  <div class="fld">SMTP 密码/授权码（*** 表示不改动）<input id="m_pass" type="password"></div>
  <div class="fld">收件邮箱（告警发到）<input id="m_to" placeholder="you@qq.com"></div>
  <div class="fld">　<div class="row"><button class="gho" onclick="saveMail()">保存</button><button onclick="testMail()">测发</button></div></div>
</div>
<div class="mut" style="margin-top:8px">QQ 邮箱：官网设置→账号→开启 SMTP→生成授权码；仅定时/自动重试失败会发信，手动「跑一次」不发。</div>
</details>
</div>

<div class="card flush">
<table>
<thead><tr><th class="c-grp">组</th><th class="c-task">任务</th><th class="c-acc">账号</th><th class="c-time">定时</th><th class="c-st">今日状态</th><th>最近结果</th><th class="c-sw">开关</th><th class="c-act">操作</th></tr></thead>
<tbody id="tb"></tbody>
</table>
</div>

<footer>数据存于同目录 checkin_tasks.json · 服务保持运行才会自动触发</footer>
</div>

<div class="modal" id="m"><div class="mbox">
<h3 id="mt">添加任务</h3>
<div class="g3">
  <div class="fld">任务名称<input id="f_name" placeholder="例：Hyperdown 主号"></div>
  <div class="fld">分组（同站点归组，可空）<input id="f_group" list="glist" placeholder="例：Hyperdown"><datalist id="glist"></datalist></div>
  <div class="fld">每日签到时间（北京时间）<input id="f_time" type="time" value="09:00"></div>
</div>
<div class="sect"></div><b style="font-size:13px">凭据</b>
<div class="g3" style="margin-top:8px">
  <div class="fld">账号/邮箱<input id="f_user"></div>
  <div class="fld">密码<div style="position:relative"><input id="f_pass" type="password" style="width:100%;padding-right:34px"><button type="button" class="eye" onclick="pwSee('f_pass',this)">👁</button></div></div>
  <div class="fld">登录方式<select id="f_auth" onchange="authVis()">
    <option value="login">账号密码登录</option><option value="none">无/固定Token</option><option value="cookie">Cookie 登录</option></select></div>
</div>
<div class="fld" style="margin-top:8px">Cookie 字符串（Cookie 登录时贴这里，请求头用 {{cookie}} 引用）<textarea id="f_cookie" style="min-height:40px"></textarea></div>
<div class="sect"></div><b style="font-size:13px">签到接口</b>
<div class="row" style="margin-top:8px">
  <input id="f_ck_url" style="flex:2;min-width:240px" placeholder="https://site.com/api/checkin">
  <select id="f_ck_method"><option>POST</option><option>GET</option><option>PUT</option></select>
</div>
<div class="fld" style="margin-top:8px">请求头 JSON（占位符 {{token}} {{cookie}} {{user}} {{pass}} {{date}}）<textarea id="f_ck_h">{"accept":"application/json","authorization":"Bearer {{token}}"}</textarea></div>
<div class="fld">请求体 JSON / 表单串（留空=无）<textarea id="f_ck_b" style="min-height:38px" placeholder='{"date":"{{date}}"}'></textarea></div>
<div class="sect"></div><b style="font-size:13px">判定规则</b>
<div class="g3" style="margin-top:8px">
  <div class="fld">成功状态码（逗号分隔）<input id="f_ok" value="200,201,204"></div>
  <div class="fld">已签特征（正则）<input id="f_already" placeholder="already_checked_in|今日已"></div>
  <div class="fld">失败特征（正则）<input id="f_fail" placeholder="unauthorized|token"></div>
</div>
<div class="sect"></div><b style="font-size:13px">失败重试与提醒</b>
<div class="g3" style="margin-top:8px">
  <div class="fld">失败自动重试<select id="f_reton"><option value="1">开启</option><option value="0">关闭</option></select></div>
  <div class="fld">重试间隔（小时）<input id="f_rethr" type="number" min="0.5" step="0.5" value="6"></div>
  <div class="fld">每日重试上限（0=不限）<input id="f_retmx" type="number" min="0" value="0"></div>
</div>
<label style="display:flex;gap:8px;align-items:center;margin-top:10px;font-size:13px;cursor:pointer"><input type="checkbox" id="f_mail" checked>本任务失败时发邮件提醒（每天首封）</label>
<div class="sect"></div><b style="font-size:13px">获得流量统计 <span class="mut" style="font-weight:400">（可选：签到后余额涨了会在结果里显示「获得 xx GB」）</span></b>
<div class="g2" style="margin-top:8px">
  <div class="fld">余额接口 URL（GET，留空=不统计）<input id="f_bal_url" placeholder="https://site.com/api/me"></div>
  <div class="fld">余额数值路径（点路径）<input id="f_bal_path" value="data.traffic_bytes"></div>
</div>
<div id="lgbox">
<div class="sect"></div><b style="font-size:13px">登录接口（自动换 token）</b>
<div class="row" style="margin-top:8px">
  <input id="f_lg_url" style="flex:2;min-width:240px" placeholder="https://site.com/api/login">
  <select id="f_lg_method"><option>POST</option><option>GET</option></select>
</div>
<div class="fld" style="margin-top:8px">登录头 JSON<textarea id="f_lg_h" style="min-height:38px">{"accept":"application/json"}</textarea></div>
<div class="fld">登录体 JSON<textarea id="f_lg_b" style="min-height:38px">{"email":"{{user}}","password":"{{pass}}"}</textarea></div>
<div class="g2" style="margin-top:8px">
  <div class="fld">token 提取路径（点路径；set-cookie=取响应头）<input id="f_tp" value="data.access_token"></div>
  <div class="fld">或从响应头取（头名，可空）<input id="f_th" placeholder="x-auth-token"></div>
</div>
</div>
<div class="row" style="margin-top:18px;justify-content:flex-end">
  <button class="gho" onclick="closeM()">取消</button><button onclick="save()">保存任务</button>
</div>
</div></div>
<div class="modal" id="am"><div class="mbox" style="max-width:430px">
<h3>👤 账号设置</h3>
<div class="mut" style="margin-bottom:14px">当前用户：<b id="a_now" style="color:var(--fg)">…</b>　·　修改后所有设备需重新登录</div>
<div class="fld" style="margin-bottom:10px">新用户名（不改就留空）<input id="a_user" maxlength="40"></div>
<div class="fld" style="margin-bottom:10px">新密码（不改就留空，至少 6 位）<input id="a_pass" type="password" maxlength="64"></div>
<div class="fld" style="margin-bottom:10px">当前密码（确认身份，必填）<input id="a_old" type="password" maxlength="64"></div>
<div class="row" style="justify-content:flex-end;margin-top:16px">
<button class="gho" onclick="am.classList.remove('show')">取消</button>
<button onclick="saveAcct()">保存</button></div>
</div></div>
<div class="toast" id="toast"></div>
<script>
let DB={tasks:[]},editing=null;
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('show'),3200)}
async function J(u,o){const r=await fetch(u,Object.assign({headers:{'content-type':'application/json'}},o));
 if(r.status===401){location.href='/login';throw new Error('请先登录')}
 return r.json()}
const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function gb(b){return ((b||0)/1e9).toFixed(2)}
function authName(m){return {none:'固定Token',cookie:'Cookie',login:'账号密码'}[m]||m}
function groups(){return [...new Set(DB.tasks.map(t=>t.group).filter(Boolean))].sort()}
function hhmm(iso){return iso?String(iso).slice(11,16):''}
function nextRetry(t){
  if(!t.state.last_at||t.state.last_status!=='fail'||t.retry_on_fail===false)return '';
  const mx=+t.retry_max||0;
  if(mx&&(t.state.retry_count||0)>=mx)return '今日重试已用完，明天再试';
  const d=new Date(t.state.last_at);if(isNaN(d))return '';
  d.setMinutes(d.getMinutes()+(+t.retry_hours||6)*60);
  const bj=new Date(d.getTime()+d.getTimezoneOffset()*60000+8*3600000);
  const now=new Date();
  const hm=bj.toTimeString().slice(0,5);
  return bj.toDateString()===now.toDateString()?'下次重试 '+hm:'下次重试 明天'+hm;
}
function authBadge(t){
  const st=t.state,mode=t.auth_mode;
  if(st.auth_ok===true)return '<span class="badge b-ok" title="'+esc(st.auth_msg||'')+'">已登录</span>';
  if(st.auth_ok===false)return '<span class="badge b-err" title="'+esc(st.auth_msg||'')+'">登录失败</span>';
  return '<span class="badge b-wait" title="还没实际连接过，跑一次或到点自动签到后显示">未验证</span>';
}
function statusCell(t){
  const st=t.state.last_status;let b='<span class="badge b-wait">待签</span>';
  if(st==='ok')b='<span class="badge b-ok">✓ 今日已签</span>';
  else if(st==='dup')b='<span class="badge b-dup">今日已签过</span>';
  else if(st==='fail')b='<span class="badge b-err">失败</span>';
  let extra='';
  if(st==='fail'){
    if(t.retry_on_fail===false)extra='不会自动重试';
    else{const mx=+t.retry_max||0;extra=nextRetry(t)||(mx?'0.5小时后再看':'');}
  }
  return b+(extra?'<div class="mut">'+extra+'</div>':'');
}
function render(){
  const sel=document.getElementById('gfilter'),cur=sel.value;
  sel.innerHTML='<option value="">全部</option>'+groups().map(g=>'<option>'+esc(g)+'</option>').join('');
  sel.value=cur;sel.selectedIndex=sel.selectedIndex;
  document.getElementById('glist').innerHTML=groups().map(g=>'<option value="'+esc(g)+'">').join('');
  const list=cur===''?DB.tasks:DB.tasks.filter(t=>t.group===cur);
  const tb=document.getElementById('tb');
  tb.innerHTML=list.length?list.map(t=>'<tr>'+
   '<td>'+(t.group?'<span class="badge b-grp">'+esc(t.group)+'</span>':'<span class="mut">—</span>')+'</td>'+
   '<td class="trunc"><b>'+esc(t.name||'未命名')+'</b><div class="mut">'+esc(t.checkin.url)+'</div></td>'+
   '<td>'+esc(t.cred.user)+'<div style="margin-top:3px">'+authBadge(t)+'<span class="mut" style="margin-left:6px">'+authName(t.auth_mode)+'</span></div></td>'+
   '<td><input type="time" value="'+t.time+'" style="width:96px" onchange="setTime(\''+t.id+'\',this.value)"></td>'+
   '<td>'+statusCell(t)+'</td>'+
   '<td class="mut">'+(t.state.last_at?hhmm(t.state.last_at)+'　':'')+esc(t.state.last_msg||'尚未执行过')+'</td>'+
   '<td><span class="sw'+(t.enabled?' on':'')+'" onclick="toggle(\''+t.id+'\')"><i></i></span></td>'+
   '<td><div class="acts">'+
     '<button class="gho sm" onclick="run(\''+t.id+'\')">跑一次</button>'+
     '<button class="gho sm" onclick="dup(\''+t.id+'\')">复制</button>'+
     '<button class="gho sm" onclick="openEdit(\''+t.id+'\')">编辑</button>'+
     '<button class="dgr sm" onclick="del(\''+t.id+'\')">删</button>'+
   '</div></td></tr>').join(''):'<tr><td colspan="8" class="empty">暂无任务 —— 点「＋ 添加任务」开始；配好一个后用「复制」快速加同站多账号</td></tr>';
}
async function load(){const r=await J('/api/state');if(r.ok){DB=r.data}render();fillMail()}
async function toggle(id){await J('/api/toggle',{method:'POST',body:JSON.stringify({id})});load()}
async function setTime(id,v){await J('/api/config',{method:'POST',body:JSON.stringify({id,time:v})});toast('定时已改为 '+v);load()}
async function run(id){toast('执行中…');const r=await J('/api/run',{method:'POST',body:JSON.stringify({id})});toast(r.msg||'完成');load()}
async function runBatch(mode){
  const cur=document.getElementById('gfilter').value;
  const ids=DB.tasks.filter(t=>t.enabled&&(mode==='all'&&cur===''||mode==='group'&&(!cur||t.group===cur))).map(t=>t.id);
  if(!ids.length)return toast('没有启用的任务');
  J('/api/runbatch',{method:'POST',body:JSON.stringify({ids})}).then(r=>toast(r.msg||'已触发'));
  setTimeout(load,3000);setTimeout(load,10000);
}
async function del(id){if(!confirm('删除该任务？'))return;await J('/api/del',{method:'POST',body:JSON.stringify({id})});load()}
function blank(){return {name:'',group:'',time:'09:00',cred:{user:'',pass:'',cookie:''},auth_mode:'login',
 login:{url:'',method:'POST',headers:{},body:'',token_path:'data.access_token',token_header:''},
 checkin:{url:'',method:'POST',headers:{},body:''},judge:{ok_status:'200,201,204',already:'',fail:''},
 balance:{url:'',method:'GET',path:'data.traffic_bytes'},
 retry_on_fail:true,retry_hours:6,retry_max:0,notify_mail:true,state:{}}}
function openEdit(id){
  editing=id||null;
  const t=id?DB.tasks.find(x=>x.id===id):blank();
  f_name.value=t.name;f_group.value=t.group||'';f_time.value=t.time||'09:00';
  f_user.value=t.cred.user;f_pass.value=t.cred.pass;f_cookie.value=t.cred.cookie;f_auth.value=t.auth_mode;
  f_ck_url.value=t.checkin.url;f_ck_method.value=t.checkin.method;
  f_ck_h.value=JSON.stringify(t.checkin.headers,null,1);f_ck_b.value=t.checkin.body||'';
  f_ok.value=t.judge.ok_status;f_already.value=t.judge.already||'';f_fail.value=t.judge.fail||'';
  f_reton.value=t.retry_on_fail===false?'0':'1';f_rethr.value=t.retry_hours||6;f_retmx.value=t.retry_max||0;
  f_mail.checked=t.notify_mail!==false;
  f_bal_url.value=(t.balance||{}).url||'';f_bal_path.value=(t.balance||{}).path||'data.traffic_bytes';
  f_lg_url.value=t.login.url;f_lg_method.value=t.login.method;f_lg_h.value=JSON.stringify(t.login.headers,null,1);
  f_lg_b.value=t.login.body;f_tp.value=t.login.token_path;f_th.value=t.login.token_header||'';
  authVis();mt.textContent=id?'编辑任务':'添加任务';m.classList.add('show');
}
function closeM(){m.classList.remove('show')}
function authVis(){lgbox.style.display=f_auth.value==='login'?'':'none'}
function PJ(id){try{return JSON.parse(document.getElementById(id).value||'{}')}catch(e){throw new Error('「'+id+'」不是合法 JSON')}}
function pwSee(id,btn){const el=document.getElementById(id);const show=el.type==='password';el.type=show?'text':'password';btn.textContent=show?'🙈':'👁';btn.style.opacity='1'}
async function save(){
  let ckH,lgH;
  try{ckH=PJ('f_ck_h');lgH=PJ('f_lg_h')}catch(e){return toast(e.message)}
  if(!f_ck_url.value.trim())return toast('签到 URL 必填');
  const body={id:editing||undefined,name:f_name.value.trim(),group:f_group.value.trim(),time:f_time.value,
   cred:{user:f_user.value.trim(),pass:f_pass.value,cookie:f_cookie.value},auth_mode:f_auth.value,
   checkin:{url:f_ck_url.value.trim(),method:f_ck_method.value,headers:ckH,body:f_ck_b.value},
   login:{url:f_lg_url.value.trim(),method:f_lg_method.value,headers:lgH,body:f_lg_b.value,token_path:f_tp.value.trim(),token_header:f_th.value.trim()},
   judge:{ok_status:f_ok.value,already:f_already.value,fail:f_fail.value},
   retry_on_fail:f_reton.value==='1',retry_hours:parseFloat(f_rethr.value)||6,retry_max:parseInt(f_retmx.value)||0,
   balance:{url:f_bal_url.value.trim(),method:'GET',path:f_bal_path.value.trim()||'data.traffic_bytes'},
   notify_mail:f_mail.checked};
  toast('保存中…');
  const r=await J('/api/save',{method:'POST',body:JSON.stringify(body)});
  if(r.ok){closeM();toast('已保存');load()}else toast(r.msg||'保存失败');
}
async function dup(id){
  const t=DB.tasks.find(x=>x.id===id);if(!t)return;
  const b=JSON.parse(JSON.stringify(t));delete b.id;
  b.name=(t.name||'未命名')+' 副本';b.state=blank().state;
  const r=await J('/api/save',{method:'POST',body:JSON.stringify(b)});
  if(r.ok){toast('已复制，改账号后保存');const st=await J('/api/state');DB=st.data;render();
    const nt=[...DB.tasks].reverse().find(x=>x.name===b.name);if(nt)openEdit(nt.id)}
  else toast(r.msg||'复制失败');
}
function presetHD(){
  openEdit();
  f_name.value='Hyperdown 签到';f_group.value='Hyperdown';f_time.value='00:05';
  f_ck_url.value='https://hyperdown.net/api/v1/Me/checkins';f_ck_method.value='POST';
  f_ck_h.value=JSON.stringify({accept:'application/json',authorization:'Bearer {{token}}'},null,1);
  f_ck_b.value='{}';f_ok.value='200';f_already.value='already_checked_in';
  f_lg_url.value='https://hyperdown.net/api/v1/auth/login';
  f_lg_h.value=JSON.stringify({accept:'application/json'},null,1);
  f_lg_b.value='{"email":"{{user}}","password":"{{pass}}"}';f_tp.value='data.tokens.access_token';
  f_bal_url.value='https://hyperdown.net/api/v1/me/snapshot';f_bal_path.value='data.user.traffic_bytes';
  toast('示例已填入，补上邮箱密码保存即可');
}
function fillMail(){const n=DB.notify||{};
  if(!m_host.value&&!n.smtp_host){/* 未配置且用户未输入: 不覆盖 */}
  m_host.value=n.smtp_host||'';m_port.value=n.smtp_port||465;m_user.value=n.smtp_user||'';
  m_to.value=n.mail_to||'';m_pass.value=n.smtp_pass?'***':'';
  mailcard.open=!(n.smtp_host||n.mail_to);
}
async function saveMail(){
  const r=await J('/api/mailcfg',{method:'POST',body:JSON.stringify({smtp_host:m_host.value,smtp_port:m_port.value,smtp_user:m_user.value,smtp_pass:m_pass.value,mail_to:m_to.value})});
  toast(r.ok?(r.configured?'邮件提醒已启用':'已保存（配置不全，暂不发信）'):(r.msg||'失败'));
  const st=await J('/api/state');DB=st.data;fillMail();
}
async function testMail(){toast('发送中…');const r=await J('/api/mailtest',{method:'POST'});toast(r.ok?'✅ '+(r.msg||'已发送'):'❌ '+(r.msg||'失败'))}
function bjClock(){const n=new Date(),bj=new Date(n.getTime()+n.getTimezoneOffset()*60000+8*3600000);
  clock.textContent='北京时间 '+bj.toLocaleString('zh-CN',{hour12:false})}
function openAcct(){a_user.value='';a_pass.value='';a_old.value='';a_now.textContent=MYUSER||'';am.classList.add('show')}
async function saveAcct(){
 if(!a_old.value)return toast('请填写当前密码确认身份');
 if(a_pass.value&&a_pass.value.length<6)return toast('新密码至少 6 位');
 if(!a_user.value.trim()&&!a_pass.value)return toast('新用户名/新密码至少填一项');
 const r=await J('/api/auth/change',{method:'POST',body:JSON.stringify({old_pass:a_old.value,new_user:a_user.value.trim(),new_pass:a_pass.value})});
 if(r.ok){toast(r.msg);setTimeout(()=>location.href='/login',1200)}else toast(r.msg||'失败')}
async function logout(){await fetch('/api/auth/logout',{method:'POST'});location.href='/login'}
var MYUSER='';
fetch('/api/auth/me').then(r=>r.json()).then(d=>{MYUSER=d.user||'';who.textContent=MYUSER}).catch(()=>{});
load();setInterval(load,30000);bjClock();setInterval(bjClock,1000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    OPEN_PATHS = ("/login", "/api/auth/login", "/api/auth/setup", "/favicon.ico")

    def _send(self, code, ctype, body_bytes, extra=None, html=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        if html:
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body_bytes)

    def _set_cookie(self, val, max_age=SESSION_TTL):
        self._pending_cookie = "hd_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d" % (val, max_age)

    def _drain_cookie(self):
        c = getattr(self, "_pending_cookie", None)
        self._pending_cookie = None
        return [("Set-Cookie", c)] if c else []

    def _json(self, obj, code=200):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, ensure_ascii=False).encode(), self._drain_cookie())

    def _authed(self):
        return session_valid(_cookie_val(self.headers.get("Cookie", ""), "hd_session"))

    def _need_auth(self):
        """未登录: 页面请求 302 到登录页, API 返回 401。返回 True 表示已拦截。"""
        p = self.path.split("?")[0]
        # 管理员未创建: 一切页面先去 /login 走创建向导（API 暂不拦截以便 setup 调用）
        if not auth_initialized():
            if p in ("/", "/index.html") or (p.startswith("/api/") and not p.startswith("/api/auth/")):
                if p.startswith("/api/"):
                    self._json({"ok": False, "msg": "请先创建管理员账号", "need_login": True}, 401)
                else:
                    self.send_response(302)
                    self.send_header("Location", "/login")
                    self.end_headers()
                return True
            return False
        if p not in self.OPEN_PATHS and not self._authed():
            if p in ("/", "/index.html") or not p.startswith("/api/"):
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            else:
                self._json({"ok": False, "msg": "unauthorized", "need_login": True}, 401)
            return True
        return False

    def _page(self, html):
        self._send(200, "text/html; charset=utf-8", html.encode(), self._drain_cookie(), html=True)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/login":
            if not auth_initialized():
                return self._page(GATE.replace("__MODE__", "setup"))
            if self._authed():
                self.send_response(302); self.send_header("Location", "/"); self.end_headers(); return
            return self._page(GATE.replace("__MODE__", "login"))
        if p == "/api/auth/me":
            ok = self._authed()
            return self._json({"ok": ok, "user": _AUTH["user"] if ok else "", "first": not auth_initialized()})
        if self._need_auth():
            return
        if p in ("/", "/index.html"):
            return self._page(PAGE)
        if self.path.startswith("/api/state"):
            with _LOCK:
                db = load_db()
            pub = json.loads(json.dumps(db))  # 脱敏副本
            if (pub.get("notify") or {}).get("smtp_pass"):
                pub["notify"]["smtp_pass"] = "***"
            self._json({"ok": True, "data": pub})
        else:
            self._json({"ok": False, "msg": "not found"}, 404)

    def _body(self):
        n = int(self.headers.get("content-length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def do_POST(self):
        body = self._body()
        p = self.path
        ip = (self.client_address[0] if self.client_address else "?")
        # ---- 面板自身鉴权接口（免登录） ----
        if p.startswith("/api/auth/setup"):
            if auth_initialized():
                return self._json({"ok": False, "msg": "管理员已存在，请改用登录或修改账号"})
            ok, msg = setup_admin(body.get("user", ""), body.get("pass", ""))
            if ok:
                tok = new_session(_AUTH["user"])
                self._set_cookie(tok)
            return self._json({"ok": ok, "msg": msg})
        if p.startswith("/api/auth/login"):
            if login_throttle(ip):
                return self._json({"ok": False, "msg": "失败次数过多，请 5 分钟后再试"})
            if verify_login(body.get("user", ""), body.get("pass", "")):
                login_unthrottle(ip)
                tok = new_session(_AUTH["user"])
                self._set_cookie(tok)
                return self._json({"ok": True, "user": _AUTH["user"]})
            return self._json({"ok": False, "msg": "用户名或密码错误"})
        if p.startswith("/api/auth/logout"):
            sid = _cookie_val(self.headers.get("Cookie", ""), "hd_session")
            _SESSIONS.pop(sid, None)
            self._set_cookie("", max_age=0)
            return self._json({"ok": True})
        if p.startswith("/api/auth/change"):
            if self._need_auth():
                return
            ok, msg = change_credentials(body.get("old_pass", ""), body.get("new_user", ""), body.get("new_pass", ""))
            if ok:
                self._set_cookie("", max_age=0)  # 改密后强制重登
            return self._json({"ok": ok, "msg": msg})
        if p.startswith("/api/auth/check"):
            if self._need_auth():
                return
            return self._json({"ok": verify_login(_AUTH["user"], body.get("pass", ""))})
        # ---- 拦截：其余接口必须登录 ----
        if self._need_auth():
            return
        if p.startswith("/api/save"):
            with _LOCK:
                db = load_db()
                old = next((x for x in db["tasks"] if x["id"] == body.get("id")), None)
                t = blank_task()
                for k in ("name", "group", "time", "enabled", "auth_mode", "checkin", "login", "judge", "cred",
                          "retry_on_fail", "retry_hours", "retry_max", "notify_mail", "balance"):
                    if k in body:
                        t[k] = body[k]
                t["cred"].setdefault("user", ""); t["cred"].setdefault("pass", ""); t["cred"].setdefault("cookie", "")
                if not t["checkin"].get("url"):
                    return self._json({"ok": False, "msg": "签到 URL 必填"})
                if t.get("auth_mode") == "login" and not (t.get("login") or {}).get("url"):
                    return self._json({"ok": False, "msg": "登录方式是「账号密码登录」但登录接口 URL 没填——要么补上登录接口，要么改用 Cookie/固定Token"})
                if t.get("auth_mode") == "cookie" and not (t.get("cred") or {}).get("cookie"):
                    return self._json({"ok": False, "msg": "登录方式是「Cookie 登录」但 Cookie 没贴"})
                if old:
                    t["id"] = old["id"]; t["state"] = old["state"]
                    # 凭据/登录配置有改动 -> 身份变了，旧 token 与今日已签记录全部作废
                    cred_changed = json.dumps(old.get("cred"), sort_keys=True) != json.dumps(t.get("cred"), sort_keys=True)
                    login_changed = json.dumps(old.get("login"), sort_keys=True) != json.dumps(t.get("login"), sort_keys=True)
                    mode_changed = old.get("auth_mode") != t.get("auth_mode")
                    if cred_changed or login_changed or mode_changed:
                        for k in ("auth_ok", "auth_msg", "auth_at", "token", "token_exp", "last_date", "last_status", "last_msg", "last_at", "retry_count", "retry_day", "notified_day"):
                            t["state"].pop(k, None)
                    db["tasks"] = [x for x in db["tasks"] if x["id"] != old["id"]] + [t]
                else:
                    # 新任务立即试签一把（若带凭据）；首次失败按开关发邮件
                    try:
                        execute_task(t, manual=True)
                    except Exception as e:
                        t["state"]["last_msg"] = str(e)
                    if t["state"].get("last_status") == "fail":
                        notify_fail_once(db, t, t["state"].get("last_msg", ""))
                    db["tasks"].append(t)
                save_db(db)
            return self._json({"ok": True})
        if p.startswith("/api/del"):
            with _LOCK:
                db = load_db()
                db["tasks"] = [x for x in db["tasks"] if x["id"] != body.get("id")]
                save_db(db)
            return self._json({"ok": True})
        if p.startswith("/api/toggle"):
            with _LOCK:
                db = load_db()
                for t in db["tasks"]:
                    if t["id"] == body.get("id"):
                        t["enabled"] = not t.get("enabled")
                save_db(db)
            return self._json({"ok": True})
        if p.startswith("/api/config"):
            with _LOCK:
                db = load_db()
                for t in db["tasks"]:
                    if t["id"] == body.get("id"):
                        if "time" in body:
                            t["time"] = body["time"]
                save_db(db)
            return self._json({"ok": True})
        if p.startswith("/api/mailcfg"):
            with _LOCK:
                db = load_db()
                n = db.get("notify") or {}
                for k in ("smtp_host", "smtp_port", "smtp_user", "mail_to"):
                    if k in body:
                        n[k] = str(body[k]).strip()
                if "smtp_host" in n:
                    n["smtp_host"] = normalize_smtp_host(n["smtp_host"])
                # 密码回显为 *** 时不覆盖；传空串=清除
                if "smtp_pass" in body and body["smtp_pass"] != "***":
                    n["smtp_pass"] = str(body["smtp_pass"]).strip()
                db["notify"] = n
                save_db(db)
            return self._json({"ok": True, "configured": smtp_cfg(db) is not None})
        if p.startswith("/api/mailtest"):
            with _LOCK:
                db = load_db()
            cfg = smtp_cfg(db)
            if not cfg:
                return self._json({"ok": False, "msg": "SMTP 配置不全（host/发件/授权码/收件）"})
            ok, err = send_mail(cfg, "✅ 签到面板测试邮件", "这是 checkin_panel 的测试邮件，收到即代表 SMTP 配置可用。")
            return self._json({"ok": ok, "msg": "已发送到 %s" % cfg["to"] if ok else "发送失败: " + err[:150]})
        if p.startswith("/api/runbatch"):
            ids = body.get("ids") or []
            def batch():
                with _LOCK:
                    db = load_db()
                    tasks = [x for x in db["tasks"] if x["id"] in ids]
                for t in tasks:
                    try:
                        execute_task(t, manual=True)
                    except Exception as e:
                        t["state"]["last_msg"] = str(e)
                with _LOCK:
                    db = load_db()
                    byid = {x["id"]: x for x in db["tasks"]}
                    for t in tasks:
                        if t["id"] in byid:
                            byid[t["id"]]["state"] = t["state"]
                    save_db(db)
                log("批量跑完 %d 个任务" % len(tasks))
            threading.Thread(target=batch, daemon=True).start()
            return self._json({"ok": True, "msg": "已排队 %d 个任务" % len(ids)})
        if p.startswith("/api/run"):
            with _LOCK:
                db = load_db()
                t = next((x for x in db["tasks"] if x["id"] == body.get("id")), None)
            if not t:
                return self._json({"ok": False, "msg": "任务不存在"})
            try:
                st = execute_task(t, manual=True)
            except Exception as e:
                t["state"]["last_status"] = "fail"
                t["state"]["last_msg"] = "执行异常: " + str(e)[:150]
                t["state"]["last_at"] = now_cn().isoformat(timespec="seconds")
                st = "fail"
            with _LOCK:
                db = load_db()
                for x in db["tasks"]:
                    if x["id"] == t["id"]:
                        x["state"] = t["state"]
                save_db(db)
            return self._json({"ok": st in ("ok", "dup"), "msg": "%s: %s" % (st, t["state"]["last_msg"][:120])})
        return self._json({"ok": False, "msg": "not found"}, 404)


def main():
    if not os.path.exists(DB_FILE):
        save_db(load_db())
    if not load_auth():
        log("首次启动：打开面板将进入「创建管理员」向导")
    threading.Thread(target=scheduler_loop, daemon=True).start()
    srv = ThreadingHTTPServer((BIND, PORT), H)
    log("通用签到面板: http://%s:%d" % (BIND, PORT))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
