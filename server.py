#!/usr/bin/env python3
"""Plesk Dashboard - Web UI wrapper for Plesk SSH commands.

Reuses logic from admin.py but exposes operations through a small FastAPI app.
Designed to coexist with Plesk panel (default ports 9080/9443).
"""
import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

import bcrypt
import pymysql
import pymysql.cursors
import uvicorn
from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File, Depends
from fastapi.responses import (
    HTMLResponse, RedirectResponse, FileResponse,
    PlainTextResponse, JSONResponse, StreamingResponse,
)
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("PLESK_DASHBOARD_CONFIG",
                                  "/etc/plesk-dashboard/config.json"))


def load_config() -> dict:
    candidates = [CONFIG_PATH, ROOT / "config.json", ROOT / "config.example.json"]
    for c in candidates:
        if c.exists():
            return json.loads(c.read_text())
    return {}


CONFIG = load_config()
HOST = CONFIG.get("host", "0.0.0.0")
HTTP_PORT = int(CONFIG.get("http_port", 9080))
HTTPS_PORT = int(CONFIG.get("https_port", 9443))
SSL_CERT = CONFIG.get("ssl_cert")
SSL_KEY = CONFIG.get("ssl_key")
SESSION_SECRET = CONFIG.get("session_secret", os.urandom(32).hex())
VHOSTS_ROOT = CONFIG.get("vhosts_root", "/var/www/vhosts")
BACKUP_DIR = CONFIG.get("backup_dir", "/root/backups")
PLESK_PANEL_URL = CONFIG.get("plesk_panel_url", "https://localhost:8443")
USERS = CONFIG.get("users", {})
MAX_UPLOAD_MB = int(CONFIG.get("max_upload_mb", 200))
AUDIT_LOG = CONFIG.get("audit_log", "/var/log/plesk-dashboard/audit.log")


# ---------- audit logging ----------
audit_logger = logging.getLogger("plesk_dashboard.audit")
audit_logger.setLevel(logging.INFO)
try:
    Path(AUDIT_LOG).parent.mkdir(parents=True, exist_ok=True)
    _handler = logging.FileHandler(AUDIT_LOG)
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    audit_logger.addHandler(_handler)
except OSError as e:
    print(f"WARNING: เปิด audit log ไม่ได้ ({e}) — log จะไปที่ stderr", file=sys.stderr)
    audit_logger.addHandler(logging.StreamHandler(sys.stderr))


def audit(request: Request, action: str, **details):
    user = request.session.get("user", "?") if hasattr(request, "session") else "?"
    ip = request.client.host if request.client else "?"
    extras = " ".join(f"{k}={v}" for k, v in details.items())
    audit_logger.info(f"user={user} ip={ip} action={action} {extras}".strip())


app = FastAPI(title="Plesk Dashboard", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, https_only=False)
templates = Jinja2Templates(directory=str(ROOT / "templates"))


def panel_url(request: Request) -> str:
    """Return Plesk panel base URL.

    Prefer explicit config value (if not the localhost default), otherwise
    derive from the request's host so links work when accessed remotely.
    """
    if PLESK_PANEL_URL and "localhost" not in PLESK_PANEL_URL \
            and "127.0.0.1" not in PLESK_PANEL_URL:
        return PLESK_PANEL_URL.rstrip("/")
    host = request.url.hostname or "localhost"
    return f"https://{host}:8443"


templates.env.globals["panel_url"] = panel_url


# ---------- CSRF ----------

def csrf_token(request: Request) -> str:
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_hex(32)
    return request.session["csrf"]


async def require_csrf(request: Request, csrf: str = Form(...)):
    expected = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected, csrf):
        raise HTTPException(403, "Invalid CSRF token — โปรด refresh หน้าและลองใหม่")


templates.env.globals["csrf_token"] = csrf_token


# ---------- helpers ----------

def now_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def run_cmd(cmd, timeout=600, input_data=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, input=input_data
    )


def safe_sql_value(val: str) -> str:
    if not val or any(c in val for c in ["'", '"', ";", "\\", "\x00", "\n", "\r", "`"]):
        raise HTTPException(400, f"invalid value: {val!r}")
    return val


_LOGIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


def safe_login(name: str) -> str:
    if not _LOGIN_RE.match(name):
        raise HTTPException(400, "ชื่อผู้ใช้ต้องเป็น a-z, 0-9, ., -, _ (ความยาว 1-32)")
    return name


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def safe_domain(name: str) -> str:
    name = (name or "").strip().lower()
    if not _DOMAIN_RE.match(name):
        raise HTTPException(400, f"ชื่อโดเมนไม่ถูกต้อง: {name!r}")
    return name


def safe_join(base: str, *parts: str) -> Path:
    """Resolve base/parts and ensure result stays inside base."""
    base_p = Path(base).resolve()
    p = base_p
    for part in parts:
        if part:
            p = p / part.lstrip("/")
    p = p.resolve()
    if not (p == base_p or base_p in p.parents):
        raise HTTPException(400, "path escapes allowed root")
    return p


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def human_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ---------- auth ----------

def is_authed(request: Request) -> bool:
    return bool(request.session.get("user"))


def require_auth(request: Request):
    if not is_authed(request):
        raise HTTPException(303, headers={"location": "/login"})


# ---------- plesk wrappers ----------

def plesk_db(sql: str) -> List[List[str]]:
    proc = run_cmd(["plesk", "db", "-N", "-B"], input_data=sql)
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "plesk db failed")
    rows = []
    for line in proc.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("---"):
            continue
        if s.upper().startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "USE ", "SHOW ")):
            continue
        rows.append(line.split("\t"))
    return rows


def list_domains() -> List[Dict]:
    proc = run_cmd(["plesk", "bin", "site", "--list"])
    return [{"name": l.strip()} for l in proc.stdout.splitlines() if l.strip()]


def get_domain_info(domain: str) -> Dict[str, str]:
    proc = run_cmd(["plesk", "bin", "site", "--info", domain])
    info = {}
    for line in proc.stdout.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k:
                info[k] = v
    return info


def list_domain_aliases(domain: str) -> List[Dict]:
    """Domain aliases (mirrors) of a given main domain, from the Plesk DB.

    The alias table/columns differ across Plesk versions, so we try a few known
    schemas and return [] if none work (never 500 the domain page over this —
    create/delete still work via `plesk bin domalias`).
    """
    safe_sql_value(domain)
    candidates = [
        # Plesk Obsidian: aliases live in `domains` as rows whose parent is the
        # target domain's webspace (webspace_id), flagged by type='alias'.
        "SELECT a.name, a.status FROM domains a "
        "JOIN domains d ON a.webspace_id = d.id "
        f"WHERE d.name = '{domain}' AND a.type = 'alias' ORDER BY a.name;",
        # Older schema: dedicated domainaliases table keyed by dom_id.
        "SELECT da.name, da.status FROM domainaliases da "
        "JOIN domains d ON d.id = da.dom_id "
        f"WHERE d.name = '{domain}' ORDER BY da.name;",
    ]
    for sql in candidates:
        try:
            rows = plesk_db(sql)
        except HTTPException:
            continue
        out = []
        for r in rows:
            while len(r) < 2:
                r.append("")
            out.append({"name": r[0], "status": r[1]})
        return out
    return []


def list_php_handlers() -> List[Dict]:
    """Parse `plesk bin php_handler --list` output.

    Format varies across versions — we accept tab- or whitespace-separated rows,
    skip header/separator lines, and extract id + any version-like token.
    """
    proc = run_cmd(["plesk", "bin", "php_handler", "--list"])
    if proc.returncode != 0:
        return []
    handlers = []
    seen = set()
    for line in proc.stdout.splitlines():
        line = line.rstrip()
        s = line.strip()
        if not s or s.startswith(("-", "=")):
            continue
        parts = line.split("\t") if "\t" in line else line.split()
        parts = [p.strip() for p in parts if p.strip()]
        if not parts:
            continue
        first = parts[0].lower()
        if first in ("id", "handler", "name", "type", "php_handler_id"):
            continue
        handler_id = parts[0]
        if handler_id in seen:
            continue
        seen.add(handler_id)
        version = ""
        for p in parts[1:]:
            if any(c.isdigit() for c in p) and "." in p and len(p) < 10:
                version = p
                break
        handlers.append({"id": handler_id, "version": version})
    return handlers


def try_decrypt_password(encrypted: str) -> str:
    if not encrypted or not encrypted.startswith("$AES"):
        return encrypted
    enc_tool = "/usr/local/psa/admin/sbin/encrypt3"
    key_file = "/etc/psa/private/secret_key"
    if not Path(enc_tool).exists() or not Path(key_file).exists():
        return encrypted
    try:
        proc = run_cmd(
            [enc_tool, "-d", "-data", encrypted, "-secret-key-file", key_file],
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return encrypted


def get_ftp_passwords(domain: Optional[str], user: Optional[str], all_users: bool):
    if all_users:
        sql = (
            "SELECT IFNULL(d.name, '-'), s.login, a.password, a.type "
            "FROM sys_users s "
            "JOIN accounts a ON a.id = s.account_id "
            "LEFT JOIN hosting h ON h.sys_user_id = s.id "
            "LEFT JOIN domains d ON d.id = h.dom_id "
            "ORDER BY d.name, s.login;"
        )
    elif user:
        u = safe_sql_value(user)
        sql = (
            "SELECT IFNULL(d.name, '-'), s.login, a.password, a.type "
            "FROM sys_users s "
            "JOIN accounts a ON a.id = s.account_id "
            "LEFT JOIN hosting h ON h.sys_user_id = s.id "
            "LEFT JOIN domains d ON d.id = h.dom_id "
            f"WHERE s.login = '{u}';"
        )
    elif domain:
        d = safe_sql_value(domain)
        sql = (
            "SELECT d.name, s.login, a.password, a.type "
            "FROM domains d "
            "JOIN hosting h ON h.dom_id = d.id "
            "JOIN sys_users s ON s.id = h.sys_user_id "
            "JOIN accounts a ON a.id = s.account_id "
            f"WHERE d.name = '{d}';"
        )
    else:
        return []

    out = []
    for r in plesk_db(sql):
        while len(r) < 4:
            r.append("")
        d, login, pwd, ptype = r[:4]
        out.append({
            "domain": d, "user": login,
            "password": try_decrypt_password(pwd), "type": ptype,
        })
    return out


def list_databases() -> List[Dict]:
    sql = (
        "SELECT db.name, db.type, IFNULL(d.name, '-') "
        "FROM data_bases db "
        "LEFT JOIN domains d ON db.dom_id = d.id "
        "ORDER BY db.name;"
    )
    rows = plesk_db(sql)
    return [
        {"name": r[0], "type": r[1] if len(r) > 1 else "", "domain": r[2] if len(r) > 2 else ""}
        for r in rows
    ]


def get_db_credentials(db_name: str) -> Dict[str, str]:
    """Look up DB user credentials from Plesk DB and decrypt password."""
    safe_sql_value(db_name)
    sql = (
        "SELECT u.login, a.password, a.type "
        "FROM db_users u "
        "JOIN accounts a ON a.id = u.account_id "
        "JOIN data_bases db ON db.id = u.db_id "
        f"WHERE db.name = '{db_name}' "
        "ORDER BY u.id LIMIT 1;"
    )
    rows = plesk_db(sql)
    if not rows:
        raise HTTPException(404, f"ไม่พบ user สำหรับ DB: {db_name}")
    r = rows[0]
    while len(r) < 3:
        r.append("")
    return {
        "login": r[0],
        "password": try_decrypt_password(r[1]),
        "type": r[2],
    }


def db_connect(db_name: str, host: str = "127.0.0.1", port: int = 3306):
    creds = get_db_credentials(db_name)
    return pymysql.connect(
        host=host, port=port,
        user=creds["login"],
        password=creds["password"],
        database=db_name,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
        autocommit=True,
    )


def list_dns_records(domain: str) -> List[Dict]:
    safe_sql_value(domain)
    sql = (
        "SELECT r.id, r.type, r.host, r.val, r.opt "
        "FROM dns_recs r "
        "JOIN domains d ON d.id = r.dom_id "
        f"WHERE d.name = '{domain}' "
        "ORDER BY r.type, r.host;"
    )
    out = []
    for r in plesk_db(sql):
        while len(r) < 5:
            r.append("")
        out.append({
            "id": r[0], "type": r[1], "host": r[2],
            "value": r[3], "opt": r[4],
        })
    return out


def get_ssl_info(domain: str) -> Dict:
    """Return SSL/cert info from Plesk DB."""
    safe_sql_value(domain)
    sql = (
        "SELECT d.name, IFNULL(h.ssl, 'false'), IFNULL(c.name, ''), IFNULL(c.cert_file, '') "
        "FROM domains d "
        "LEFT JOIN hosting h ON h.dom_id = d.id "
        "LEFT JOIN certificates c ON c.id = h.certificate_id "
        f"WHERE d.name = '{domain}' LIMIT 1;"
    )
    rows = plesk_db(sql)
    if not rows:
        return {"domain": domain, "ssl": "false", "cert_name": "", "cert_file": ""}
    r = rows[0]
    while len(r) < 4:
        r.append("")
    return {
        "domain": r[0], "ssl": r[1] or "false",
        "cert_name": r[2] or "", "cert_file": r[3] or "",
    }


def list_backup_files() -> List[Dict]:
    p = Path(BACKUP_DIR)
    if not p.is_dir():
        return []
    out = []
    for f in sorted(p.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if not f.is_file():
            continue
        st = f.stat()
        out.append({
            "name": f.name, "size": st.st_size,
            "size_human": human_size(st.st_size),
            "modified_human": human_time(st.st_mtime),
        })
    return out


# ---------- routes: auth ----------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authed(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    stored = USERS.get(username)
    ok = False
    if stored:
        try:
            ok = bcrypt.checkpw(password.encode(), stored.encode())
        except ValueError:
            ok = False
    if not ok:
        audit(request, "login_failed", username=username)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "ผู้ใช้หรือรหัสไม่ถูกต้อง"},
            status_code=401,
        )
    request.session["user"] = username
    request.session["csrf"] = secrets.token_hex(32)
    audit(request, "login_ok", username=username)
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    audit(request, "logout")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------- routes: dashboard ----------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": request.session["user"],
        "active": "dashboard",
        "domain_count": len(list_domains()),
    })


# ---------- routes: domains ----------

@app.get("/domains", response_class=HTMLResponse)
async def domains_page(request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "domains.html", {
        "user": request.session["user"],
        "active": "domains",
        "domains": list_domains(),
    })


@app.get("/domains/{name}", response_class=HTMLResponse)
async def domain_detail(name: str, request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "domain_detail.html", {
        "user": request.session["user"],
        "active": "domains", "domain": name,
        "info": get_domain_info(name),
        "php_handlers": list_php_handlers(),
        "aliases": list_domain_aliases(name),
    })


@app.post("/domains/{name}/rename", dependencies=[Depends(require_csrf)])
async def domain_rename(name: str, request: Request, new_name: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(new_name)
    # Try subscription rename first (works for subscription main domain)
    proc = run_cmd(["plesk", "bin", "subscription", "-u", name, "-new_name", new_name])
    if proc.returncode != 0:
        # Fallback for addon/non-subscription domains
        proc2 = run_cmd(["plesk", "bin", "site", "--update", name, "-name", new_name])
        if proc2.returncode != 0:
            audit(request, "domain_rename_failed", domain=name, new=new_name)
            err = (proc.stderr or proc.stdout) + "\n\nfallback site --update:\n" + (proc2.stderr or proc2.stdout)
            return PlainTextResponse(err, status_code=400)
    audit(request, "domain_rename", domain=name, new=new_name)
    return RedirectResponse(f"/domains/{new_name}", status_code=303)


@app.post("/domains/{name}/php", dependencies=[Depends(require_csrf)])
async def domain_set_php(name: str, request: Request, handler: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(handler)
    proc = run_cmd(["plesk", "bin", "site", "--update", name, "-php_handler_id", handler])
    if proc.returncode != 0:
        audit(request, "php_change_failed", domain=name, handler=handler)
        return PlainTextResponse(proc.stderr or proc.stdout, status_code=400)
    audit(request, "php_change", domain=name, handler=handler)
    return RedirectResponse(f"/domains/{name}", status_code=303)


@app.post("/domains/{name}/alias", dependencies=[Depends(require_csrf)])
async def domain_alias_create(name: str, request: Request,
                              alias: str = Form(...),
                              mail: Optional[str] = Form(None),
                              dns: Optional[str] = Form(None)):
    if not is_authed(request):
        raise HTTPException(401)
    main = safe_domain(name)
    alias = safe_domain(alias)
    if alias == main:
        return PlainTextResponse("alias ต้องไม่ซ้ำกับโดเมนหลัก", status_code=400)
    cmd = [
        "plesk", "bin", "domalias", "--create", alias,
        "-domain", main,
        "-web", "true",
        "-mail", "true" if mail else "false",
        "-dns", "true" if dns else "false",
    ]
    proc = run_cmd(cmd)
    if proc.returncode != 0:
        audit(request, "alias_create_failed", domain=main, alias=alias)
        return PlainTextResponse(proc.stderr or proc.stdout, status_code=400)
    audit(request, "alias_create", domain=main, alias=alias)
    return RedirectResponse(f"/domains/{main}", status_code=303)


@app.post("/domains/{name}/alias/delete", dependencies=[Depends(require_csrf)])
async def domain_alias_delete(name: str, request: Request, alias: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    main = safe_domain(name)
    alias = safe_domain(alias)
    proc = run_cmd(["plesk", "bin", "domalias", "--remove", alias])
    if proc.returncode != 0:
        audit(request, "alias_delete_failed", domain=main, alias=alias)
        return PlainTextResponse(proc.stderr or proc.stdout, status_code=400)
    audit(request, "alias_delete", domain=main, alias=alias)
    return RedirectResponse(f"/domains/{main}", status_code=303)


# ---------- routes: ftp ----------

@app.get("/ftp", response_class=HTMLResponse)
async def ftp_page(request: Request, domain: Optional[str] = None,
                   user: Optional[str] = None, all: int = 0):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    results, error = [], None
    if domain or user or all:
        try:
            results = get_ftp_passwords(domain, user, bool(all))
        except HTTPException as e:
            error = e.detail
    return templates.TemplateResponse(request, "ftp.html", {
        "user": request.session["user"],
        "active": "ftp",
        "results": results, "error": error,
        "q_domain": domain, "q_user": user, "q_all": all,
    })


@app.post("/ftp/create", dependencies=[Depends(require_csrf)])
async def ftp_create(request: Request,
                     login: str = Form(...),
                     password: str = Form(...),
                     domain: str = Form(...),
                     home: str = Form("")):
    if not is_authed(request):
        raise HTTPException(401)
    safe_login(login)
    safe_sql_value(domain)
    if len(password) < 5:
        raise HTTPException(400, "รหัสผ่านสั้นเกินไป (อย่างน้อย 5 ตัว)")
    cmd = ["plesk", "bin", "ftpuser", "--create", login,
           "-owner", domain, "-passwd", password]
    if home.strip():
        h = home.strip()
        if not h.startswith("/"):
            h = "/" + h
        cmd.extend(["-home", h])
    proc = run_cmd(cmd)
    if proc.returncode != 0:
        audit(request, "ftp_create_failed", login=login, domain=domain)
        return PlainTextResponse(
            (proc.stderr or proc.stdout or "ftpuser create failed").strip(),
            status_code=400,
        )
    audit(request, "ftp_create", login=login, domain=domain)
    return RedirectResponse(f"/ftp?domain={domain}", status_code=303)


@app.post("/ftp/password", dependencies=[Depends(require_csrf)])
async def ftp_password(request: Request,
                       login: str = Form(...),
                       new_password: str = Form(...),
                       domain: str = Form(""),
                       is_main: int = Form(0)):
    """Change FTP password. Tries ftpuser --update first, falls back to
    subscription -u for main subscription users."""
    if not is_authed(request):
        raise HTTPException(401)
    safe_login(login)
    if len(new_password) < 5:
        raise HTTPException(400, "รหัสผ่านสั้นเกินไป (อย่างน้อย 5 ตัว)")

    # Try ftpuser first (works for additional FTP users)
    cmd1 = ["plesk", "bin", "ftpuser", "--update", login, "-passwd", new_password]
    proc1 = run_cmd(cmd1)

    if proc1.returncode != 0 and domain:
        # Fallback: main subscription user — use subscription -u
        safe_sql_value(domain)
        cmd2 = ["plesk", "bin", "subscription", "-u", domain, "-passwd", new_password]
        proc2 = run_cmd(cmd2)
        if proc2.returncode == 0:
            audit(request, "ftp_password_main", domain=domain)
            return RedirectResponse(f"/ftp?domain={domain}", status_code=303)
        err = (proc1.stderr or proc1.stdout) + "\n---fallback---\n" + (proc2.stderr or proc2.stdout)
        audit(request, "ftp_password_failed", login=login, domain=domain)
        return PlainTextResponse(err.strip(), status_code=400)

    if proc1.returncode != 0:
        audit(request, "ftp_password_failed", login=login)
        return PlainTextResponse((proc1.stderr or proc1.stdout).strip(), status_code=400)

    audit(request, "ftp_password", login=login)
    redirect = f"/ftp?domain={domain}" if domain else f"/ftp?user={login}"
    return RedirectResponse(redirect, status_code=303)


@app.post("/ftp/delete", dependencies=[Depends(require_csrf)])
async def ftp_delete(request: Request,
                     login: str = Form(...),
                     domain: str = Form("")):
    if not is_authed(request):
        raise HTTPException(401)
    safe_login(login)
    proc = run_cmd(["plesk", "bin", "ftpuser", "--remove", login])
    if proc.returncode != 0:
        audit(request, "ftp_delete_failed", login=login)
        return PlainTextResponse(
            (proc.stderr or proc.stdout or "ลบไม่สำเร็จ (อาจเป็น main subscription user)").strip(),
            status_code=400,
        )
    audit(request, "ftp_delete", login=login)
    redirect = f"/ftp?domain={domain}" if domain else "/ftp"
    return RedirectResponse(redirect, status_code=303)


# ---------- routes: backup ----------

@app.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, domain: Optional[str] = None):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "backup.html", {
        "user": request.session["user"],
        "active": "backup",
        "domains": list_domains(), "backup_dir": BACKUP_DIR,
        "selected_domain": domain,
        "backup_files": list_backup_files(),
    })


async def stream_process(cmd: List[str], success_msg: str = "", env: Optional[Dict] = None):
    """Run a subprocess and stream combined stdout+stderr line-by-line.

    Yields bytes so caller can wrap in StreamingResponse.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
    except Exception as e:
        yield f"start failed: {e}\n".encode()
        return

    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield line
    finally:
        rc = await proc.wait()
        yield f"\n=== exit {rc} ===\n".encode()
        if rc == 0 and success_msg:
            yield f"OK: {success_msg}\n".encode()


@app.post("/backup/subscription", dependencies=[Depends(require_csrf)])
async def backup_subscription(request: Request,
                              domain: str = Form(...),
                              incremental: int = Form(0)):
    if not is_authed(request):
        raise HTTPException(401)
    Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    safe_sql_value(domain)
    out = f"{BACKUP_DIR}/{domain}_{now_ts()}.tar"
    cmd = ["plesk", "bin", "pleskbackup", "--domains-name", domain, "-output-file", out]
    if incremental:
        cmd.append("-incremental")
    audit(request, "backup_subscription", domain=domain, output=out)
    return StreamingResponse(stream_process(cmd, success_msg=out), media_type="text/plain")


@app.post("/backup/files", dependencies=[Depends(require_csrf)])
async def backup_files(request: Request,
                       domain: str = Form(...),
                       exclude: str = Form("")):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(domain)
    Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    src = Path(VHOSTS_ROOT) / domain / "httpdocs"
    if not src.is_dir():
        raise HTTPException(404, f"source not found: {src}")
    out = f"{BACKUP_DIR}/{domain}_files_{now_ts()}.tar.gz"
    cmd = ["tar", "-czvf", out]
    for ex in [x.strip() for x in exclude.split(",") if x.strip()]:
        cmd.extend(["--exclude", ex])
    cmd.extend(["-C", str(src), "."])
    audit(request, "backup_files", domain=domain, output=out)
    return StreamingResponse(stream_process(cmd, success_msg=out), media_type="text/plain")


@app.post("/backup/db", dependencies=[Depends(require_csrf)])
async def backup_db(request: Request,
                    db_name: str = Form(...),
                    db_user: str = Form(...),
                    db_pass: str = Form(...),
                    host: str = Form("127.0.0.1"),
                    gzip: int = Form(0)):
    if not is_authed(request):
        raise HTTPException(401)
    Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    out = f"{BACKUP_DIR}/{db_name}_db_{now_ts()}.sql"
    if gzip:
        out += ".gz"
    env = os.environ.copy()
    env["MYSQL_PWD"] = db_pass
    audit(request, "backup_db", db=db_name, host=host, output=out)

    async def stream_db():
        cmd = ["mysqldump", f"--host={host}", f"--user={db_user}",
               "--single-transaction", "--quick", "--routines", "--triggers",
               "--default-character-set=utf8mb4", db_name]
        try:
            if gzip:
                shell_cmd = f"{shlex.join(cmd)} | gzip > {shlex.quote(out)}"
                proc = await asyncio.create_subprocess_shell(
                    shell_cmd, env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            else:
                f = open(out, "wb")
                proc = await asyncio.create_subprocess_exec(
                    *cmd, env=env,
                    stdout=f,
                    stderr=asyncio.subprocess.PIPE,
                )
        except Exception as e:
            yield f"start failed: {e}\n".encode()
            return

        try:
            stream_source = proc.stdout if gzip else proc.stderr
            while stream_source:
                line = await stream_source.readline()
                if not line:
                    break
                yield line
        finally:
            rc = await proc.wait()
            if not gzip:
                f.close()
            yield f"\n=== exit {rc} ===\n".encode()
            if rc == 0:
                yield f"OK: {out}\n".encode()

    return StreamingResponse(stream_db(), media_type="text/plain")


# ---------- routes: files ----------

TEXT_EXTS = {".txt", ".html", ".htm", ".css", ".js", ".php", ".py",
             ".json", ".yml", ".yaml", ".xml", ".md", ".conf", ".ini",
             ".env", ".htaccess", ".log", ".sql", ".sh"}


@app.get("/files", response_class=HTMLResponse)
async def files_page(request: Request, path: str = ""):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)

    full = safe_join(VHOSTS_ROOT, path)
    if not full.exists():
        raise HTTPException(404, f"not found: {path}")

    rel = "" if full == Path(VHOSTS_ROOT) else str(full.relative_to(VHOSTS_ROOT))
    parent = "/".join(rel.split("/")[:-1]) if rel else ""

    is_file = full.is_file()
    items = []
    file_content = ""

    if is_file:
        if full.suffix.lower() in TEXT_EXTS or full.stat().st_size < 1024 * 1024:
            try:
                file_content = full.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                file_content = f"(อ่านไฟล์ไม่ได้: {e})"
        else:
            file_content = "(ไฟล์ใหญ่เกินไปหรือเป็น binary — ใช้ดาวน์โหลดแทน)"
    else:
        for child in sorted(full.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                st = child.stat()
                items.append({
                    "name": child.name,
                    "is_dir": child.is_dir(),
                    "size": st.st_size,
                    "size_human": human_size(st.st_size),
                    "modified_human": human_time(st.st_mtime),
                })
            except OSError:
                continue

    return templates.TemplateResponse(request, "files.html", {
        "user": request.session["user"],
        "active": "files",
        "current_path": rel, "parent_path": parent,
        "items": items, "is_file": is_file,
        "file_content": file_content,
    })


@app.post("/files/save", dependencies=[Depends(require_csrf)])
async def files_save(request: Request, path: str = Form(...), content: str = Form("")):
    if not is_authed(request):
        raise HTTPException(401)
    full = safe_join(VHOSTS_ROOT, path)
    if not full.is_file():
        raise HTTPException(404)
    full.write_text(content, encoding="utf-8")
    audit(request, "file_save", path=path, size=len(content))
    return RedirectResponse(f"/files?path={path}", status_code=303)


@app.post("/files/delete", dependencies=[Depends(require_csrf)])
async def files_delete(request: Request,
                       path: str = Form(...),
                       recursive: int = Form(0)):
    if not is_authed(request):
        raise HTTPException(401)
    full = safe_join(VHOSTS_ROOT, path)
    if not full.exists():
        raise HTTPException(404)
    if full == Path(VHOSTS_ROOT).resolve():
        raise HTTPException(400, "cannot delete root")
    if full.is_dir():
        if recursive:
            import shutil
            shutil.rmtree(full)
            audit(request, "dir_delete_recursive", path=path)
        else:
            try:
                full.rmdir()
                audit(request, "dir_delete", path=path)
            except OSError as e:
                return PlainTextResponse(
                    f"ลบโฟลเดอร์ไม่ได้: {e} (ติ๊ก recursive เพื่อลบทั้งหมด)",
                    status_code=400,
                )
    else:
        full.unlink()
        audit(request, "file_delete", path=path)
    parent = "/".join(path.strip("/").split("/")[:-1])
    return RedirectResponse(f"/files?path={parent}", status_code=303)


@app.post("/files/upload", dependencies=[Depends(require_csrf)])
async def files_upload(request: Request,
                       path: str = Form(""),
                       file: UploadFile = File(...)):
    if not is_authed(request):
        raise HTTPException(401)
    target_dir = safe_join(VHOSTS_ROOT, path)
    if not target_dir.is_dir():
        raise HTTPException(400, "target is not a directory")
    target = target_dir / Path(file.filename).name
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    size = 0
    try:
        with target.open("wb") as f:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    f.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"ไฟล์ใหญ่เกิน {MAX_UPLOAD_MB} MB",
                    )
                f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        target.unlink(missing_ok=True)
        raise HTTPException(500, f"upload failed: {e}")
    audit(request, "file_upload", path=path, name=file.filename, size=size)
    return RedirectResponse(f"/files?path={path}", status_code=303)


@app.post("/files/mkdir", dependencies=[Depends(require_csrf)])
async def files_mkdir(request: Request, path: str = Form(""), name: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    # Disallow path separators in name to keep mkdir local
    if "/" in name or "\\" in name or name in (".", ".."):
        raise HTTPException(400, "ชื่อโฟลเดอร์ไม่ถูกต้อง")
    parent = safe_join(VHOSTS_ROOT, path)
    if not parent.is_dir():
        raise HTTPException(400, "parent is not a directory")
    new_dir = parent / name
    if new_dir.exists():
        raise HTTPException(409, "มีอยู่แล้ว")
    new_dir.mkdir(parents=False)
    audit(request, "mkdir", path=path, name=name)
    return RedirectResponse(f"/files?path={path}", status_code=303)


@app.post("/files/rename", dependencies=[Depends(require_csrf)])
async def files_rename(request: Request, path: str = Form(...), new_name: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    if "/" in new_name or "\\" in new_name or new_name in (".", ".."):
        raise HTTPException(400, "ชื่อใหม่ไม่ถูกต้อง")
    full = safe_join(VHOSTS_ROOT, path)
    if not full.exists():
        raise HTTPException(404)
    target = full.parent / new_name
    if target.exists():
        raise HTTPException(409, "ปลายทางมีอยู่แล้ว")
    full.rename(target)
    audit(request, "rename", old=path, new=str(target.relative_to(VHOSTS_ROOT)))
    parent = "/".join(path.strip("/").split("/")[:-1])
    return RedirectResponse(f"/files?path={parent}", status_code=303)


@app.get("/files/download")
async def files_download(request: Request, path: str):
    if not is_authed(request):
        raise HTTPException(401)
    full = safe_join(VHOSTS_ROOT, path)
    if not full.is_file():
        raise HTTPException(404)
    return FileResponse(str(full), filename=full.name)


# ---------- routes: databases ----------

@app.get("/databases", response_class=HTMLResponse)
async def databases_page(request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    error = None
    dbs = []
    try:
        dbs = list_databases()
    except HTTPException as e:
        error = e.detail
    return templates.TemplateResponse(request, "databases.html", {
        "user": request.session["user"],
        "active": "databases",
        "databases": dbs, "error": error,
    })


@app.get("/databases/{name}", response_class=HTMLResponse)
async def db_detail(name: str, request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    safe_sql_value(name)
    error, tables, creds = None, [], None
    try:
        creds = get_db_credentials(name)
        conn = db_connect(name)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT TABLE_NAME AS name, "
                "IFNULL(TABLE_ROWS, 0) AS rows_est, "
                "ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024, 1) AS size_kb, "
                "ENGINE, TABLE_COLLATION AS collation "
                "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s",
                (name,),
            )
            tables = cur.fetchall()
        conn.close()
    except Exception as e:
        error = str(e)
    return templates.TemplateResponse(request, "db_detail.html", {
        "user": request.session["user"],
        "active": "databases",
        "db_name": name, "tables": tables,
        "creds": creds, "error": error,
    })


@app.get("/databases/{name}/table/{table}", response_class=HTMLResponse)
async def db_table(name: str, table: str, request: Request,
                   page: int = 1, size: int = 50):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    safe_sql_value(name); safe_sql_value(table)
    page = max(1, page); size = max(1, min(500, size))
    offset = (page - 1) * size
    error, columns, rows, total = None, [], [], 0
    try:
        conn = db_connect(name)
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS c FROM `{table}`")
            total = cur.fetchone()["c"]
            cur.execute(f"SELECT * FROM `{table}` LIMIT %s OFFSET %s", (size, offset))
            rows = cur.fetchall()
            if rows:
                columns = list(rows[0].keys())
            else:
                cur.execute(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
                    (name, table),
                )
                columns = [r["COLUMN_NAME"] for r in cur.fetchall()]
        conn.close()
    except Exception as e:
        error = str(e)
    total_pages = (total + size - 1) // size if total else 1
    return templates.TemplateResponse(request, "db_table.html", {
        "user": request.session["user"],
        "active": "databases",
        "db_name": name, "table_name": table,
        "columns": columns, "rows": rows,
        "page": page, "size": size, "total": total, "total_pages": total_pages,
        "error": error,
    })


@app.get("/databases/{name}/sql", response_class=HTMLResponse)
async def db_sql_page(request: Request, name: str):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "db_sql.html", {
        "user": request.session["user"],
        "active": "databases",
        "db_name": name,
        "result": None, "error": None, "sql": "",
        "affected": None, "columns": [], "rows": [],
    })


@app.post("/databases/{name}/sql", response_class=HTMLResponse,
          dependencies=[Depends(require_csrf)])
async def db_sql_run(request: Request, name: str, sql: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(name)
    error, columns, rows, affected = None, [], [], None
    audit(request, "db_sql", db=name, query=sql[:200])
    try:
        conn = db_connect(name)
        with conn.cursor() as cur:
            cur.execute(sql)
            if cur.description:
                columns = [c[0] for c in cur.description]
                rows = cur.fetchmany(500)
            else:
                affected = cur.rowcount
        conn.close()
    except Exception as e:
        error = str(e)
    return templates.TemplateResponse(request, "db_sql.html", {
        "user": request.session["user"],
        "active": "databases",
        "db_name": name, "sql": sql,
        "columns": columns, "rows": rows, "affected": affected,
        "error": error, "result": True,
    })


@app.post("/databases/{name}/import",
          dependencies=[Depends(require_csrf)])
async def db_import(request: Request, name: str, file: UploadFile = File(...)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(name)
    creds = get_db_credentials(name)
    audit(request, "db_import", db=name, filename=file.filename)
    # save uploaded file to temp
    tmp = Path("/tmp") / f"plesk-dash-import-{now_ts()}-{Path(file.filename).name}"
    size = 0
    max_b = 500 * 1024 * 1024
    with tmp.open("wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > max_b:
                f.close(); tmp.unlink(missing_ok=True)
                raise HTTPException(413, "ไฟล์ใหญ่เกิน 500 MB")
            f.write(chunk)

    env = os.environ.copy()
    env["MYSQL_PWD"] = creds["password"]

    is_gz = tmp.suffix.lower() == ".gz"

    async def stream():
        yield f"Importing {file.filename} ({human_size(size)}) -> {name}\n".encode()
        if is_gz:
            cmd = f"gunzip -c {shlex.quote(str(tmp))} | mysql --user={shlex.quote(creds['login'])} {shlex.quote(name)}"
            proc = await asyncio.create_subprocess_shell(
                cmd, env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        else:
            cmd = f"mysql --user={shlex.quote(creds['login'])} {shlex.quote(name)} < {shlex.quote(str(tmp))}"
            proc = await asyncio.create_subprocess_shell(
                cmd, env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                yield line
        finally:
            rc = await proc.wait()
            tmp.unlink(missing_ok=True)
            yield f"\n=== exit {rc} ===\n".encode()
            if rc == 0:
                yield "OK: import completed\n".encode()

    return StreamingResponse(stream(), media_type="text/plain")


# ---------- routes: DNS ----------

@app.get("/domains/{name}/dns", response_class=HTMLResponse)
async def dns_page(name: str, request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    error, records = None, []
    try:
        records = list_dns_records(name)
    except HTTPException as e:
        error = e.detail
    return templates.TemplateResponse(request, "dns.html", {
        "user": request.session["user"],
        "active": "domains", "domain": name,
        "records": records, "error": error,
    })


@app.post("/domains/{name}/dns/add", dependencies=[Depends(require_csrf)])
async def dns_add(name: str, request: Request,
                  type: str = Form(...),
                  host: str = Form(""),
                  value: str = Form(...),
                  opt: str = Form("")):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(name)
    if type not in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV"):
        raise HTTPException(400, "DNS type ไม่รองรับ")
    cmd = ["plesk", "bin", "dns", "--add", name, "-" + type.lower(),
           "-host", host, "-value", value]
    if type == "MX" and opt:
        cmd.extend(["-opt", opt])
    proc = run_cmd(cmd)
    if proc.returncode != 0:
        audit(request, "dns_add_failed", domain=name, type=type)
        return PlainTextResponse((proc.stderr or proc.stdout).strip(), status_code=400)
    audit(request, "dns_add", domain=name, type=type, host=host, value=value)
    return RedirectResponse(f"/domains/{name}/dns", status_code=303)


@app.post("/domains/{name}/dns/del", dependencies=[Depends(require_csrf)])
async def dns_del(name: str, request: Request, record_id: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(name); safe_sql_value(record_id)
    proc = run_cmd(["plesk", "bin", "dns", "--del", name, "-id", record_id])
    if proc.returncode != 0:
        audit(request, "dns_del_failed", domain=name, id=record_id)
        return PlainTextResponse((proc.stderr or proc.stdout).strip(), status_code=400)
    audit(request, "dns_del", domain=name, id=record_id)
    return RedirectResponse(f"/domains/{name}/dns", status_code=303)


# ---------- routes: SSL ----------

@app.get("/domains/{name}/ssl", response_class=HTMLResponse)
async def ssl_page(name: str, request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    info = get_ssl_info(name)
    return templates.TemplateResponse(request, "ssl.html", {
        "user": request.session["user"],
        "active": "domains", "domain": name, "info": info,
    })


@app.post("/domains/{name}/ssl/letsencrypt",
          dependencies=[Depends(require_csrf)])
async def ssl_letsencrypt(name: str, request: Request,
                          email: str = Form(...),
                          secure_www: int = Form(1)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_sql_value(name)
    if "@" not in email or len(email) > 200:
        raise HTTPException(400, "อีเมลไม่ถูกต้อง")
    cmd = ["plesk", "bin", "extension", "--exec", "letsencrypt", "cli.php",
           "-d", name, "-m", email]
    if secure_www:
        cmd.append("--secure-www")
    audit(request, "ssl_letsencrypt", domain=name, email=email)
    return StreamingResponse(stream_process(cmd, success_msg=f"LE installed for {name}"),
                             media_type="text/plain")


# ---------- routes: restore ----------

@app.post("/backup/restore", dependencies=[Depends(require_csrf)])
async def backup_restore(request: Request,
                         filename: str = Form(...),
                         only: str = Form("all"),
                         domain: str = Form("")):
    if not is_authed(request):
        raise HTTPException(401)
    # Restrict to files within BACKUP_DIR
    safe_name = Path(filename).name
    full = Path(BACKUP_DIR) / safe_name
    if not full.is_file():
        raise HTTPException(404, "ไม่พบไฟล์ backup")
    if only not in ("all", "databases", "web", "dns"):
        raise HTTPException(400, "ตัวเลือก only ไม่ถูกต้อง")

    cmd = ["plesk", "bin", "pleskrestore", "--restore", str(full)]
    if only == "databases":
        cmd += ["-only-databases"]
        if domain:
            safe_sql_value(domain)
            cmd += ["-domain-name", domain]
    elif only == "web":
        if not domain:
            raise HTTPException(400, "ต้องระบุ domain ตอนเลือก only=web")
        safe_sql_value(domain)
        cmd += ["-only-web-content", "list:/", "-domain-name", domain]
    elif only == "dns":
        if not domain:
            raise HTTPException(400, "ต้องระบุ domain ตอนเลือก only=dns")
        safe_sql_value(domain)
        cmd += ["-only-dns-zones", f"list:{domain}", "-domain-name", domain]

    audit(request, "restore", file=safe_name, only=only, domain=domain)
    return StreamingResponse(stream_process(cmd, success_msg=f"restored from {safe_name}"),
                             media_type="text/plain")


@app.post("/backup/file-delete", dependencies=[Depends(require_csrf)])
async def backup_file_delete(request: Request, filename: str = Form(...)):
    if not is_authed(request):
        raise HTTPException(401)
    safe_name = Path(filename).name
    full = Path(BACKUP_DIR) / safe_name
    if not full.is_file():
        raise HTTPException(404)
    full.unlink()
    audit(request, "backup_delete", file=safe_name)
    return RedirectResponse("/backup", status_code=303)


@app.get("/backup/download")
async def backup_download(request: Request, filename: str):
    if not is_authed(request):
        raise HTTPException(401)
    safe_name = Path(filename).name
    full = Path(BACKUP_DIR) / safe_name
    if not full.is_file():
        raise HTTPException(404)
    return FileResponse(str(full), filename=safe_name)


# ---------- main ----------

def hash_password(pw: str):
    print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash-password", help="สร้าง bcrypt hash สำหรับใส่ใน config.json")
    parser.add_argument("--http-only", action="store_true", help="รัน HTTP เท่านั้น (ไม่ใช้ SSL)")
    args = parser.parse_args()

    if args.hash_password:
        hash_password(args.hash_password)
        return

    if not USERS:
        print("WARNING: ยังไม่มี user ใน config — เข้าระบบไม่ได้", file=sys.stderr)
        print("  สร้าง: python3 server.py --hash-password 'PASSWORD'", file=sys.stderr)
        print("  แล้วเอา hash ไปใส่ใน users ของ config.json", file=sys.stderr)

    use_https = (not args.http_only and SSL_CERT and SSL_KEY
                 and Path(SSL_CERT).exists() and Path(SSL_KEY).exists())
    if use_https:
        print(f"==> Plesk Dashboard: https://{HOST}:{HTTPS_PORT}")
        uvicorn.run(app, host=HOST, port=HTTPS_PORT,
                    ssl_certfile=SSL_CERT, ssl_keyfile=SSL_KEY)
    else:
        print(f"==> Plesk Dashboard: http://{HOST}:{HTTP_PORT}")
        uvicorn.run(app, host=HOST, port=HTTP_PORT)


if __name__ == "__main__":
    main()
