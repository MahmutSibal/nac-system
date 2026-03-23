"""
NAC Policy Engine — FastAPI
FreeRADIUS'ın rlm_rest modülü üzerinden çağırdığı policy engine.

Endpoint özeti:
  POST /auth            → Kullanıcı doğrulama + rate-limiting
  POST /authorize       → VLAN/policy atribütleri (rlm_rest authorize)
  POST /accounting      → Oturum verisi kaydet (rlm_rest accounting)
  GET  /users           → Kullanıcı listesi ve durum
  GET  /sessions/active → Redis'teki aktif oturumlar
  GET  /health          → Servis sağlığı (healthcheck için)
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone

import asyncpg
import bcrypt
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="NAC Policy Engine", version="1.0.0")

# ---- Konfigürasyon ----
DB_URL          = os.getenv("DATABASE_URL", "postgresql://radius:radius@postgres:5432/radius")
REDIS_URL       = os.getenv("REDIS_URL", "redis://redis:6379")
RATE_LIMIT_MAX  = int(os.getenv("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WIN  = int(os.getenv("RATE_LIMIT_WINDOW", "300"))  # saniye

# Grup → VLAN eşlemesi
VLAN_MAP = {
    "admin":    "10",
    "employee": "20",
    "guest":    "30",
}

# ---- Global bağlantı nesneleri ----
db_pool: asyncpg.Pool   = None
redis_cli: aioredis.Redis = None


# =============================================================
# Uygulama yaşam döngüsü
# =============================================================

@app.on_event("startup")
async def startup():
    global db_pool, redis_cli
    db_pool   = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    redis_cli = await aioredis.from_url(REDIS_URL, decode_responses=True)


@app.on_event("shutdown")
async def shutdown():
    await db_pool.close()
    await redis_cli.aclose()


# =============================================================
# Yardımcı fonksiyonlar
# =============================================================

def extract(body: dict, attr: str, default=None):
    """
    FreeRADIUS rlm_rest JSON formatından atribüt değeri çıkarır.

    FreeRADIUS 3.x rlm_rest iki farklı format gönderebilir:
      Format A (list): {"User-Name": [{"type": "string", "value": "alice"}]}
      Format B (dict): {"User-Name": {"type": "string", "value": ["alice"]}}

    Direkt API testi için fallback:
      {"username": "alice"}
    """
    if attr in body:
        item = body[attr]
        # Format A: değer liste içinde
        if isinstance(item, list) and item:
            val = item[0].get("value", default) if isinstance(item[0], dict) else item[0]
        # Format B: değer doğrudan dict
        elif isinstance(item, dict):
            val = item.get("value", default)
        else:
            val = item
        # value kendisi liste olabilir: ["alice"] → "alice"
        if isinstance(val, list):
            return val[0] if val else default
        return val
    # Direkt çağrı için fallback (snake_case ve orijinal key)
    snake = attr.lower().replace("-", "_")
    return body.get(snake, body.get(attr, default))


def verify_password(plaintext: str, attribute: str, stored: str) -> bool:
    """Atribüt tipine göre şifre doğrulaması yapar."""
    if attribute == "Cleartext-Password":
        return plaintext == stored
    elif attribute == "MD5-Password":
        # PostgreSQL md5() ile aynı formatta: lowercase hex
        return hashlib.md5(plaintext.encode()).hexdigest() == stored
    elif attribute == "Crypt-Password":
        # bcrypt — API üzerinden oluşturulan kullanıcılar için
        return bcrypt.checkpw(plaintext.encode(), stored.encode())
    return False


def is_mac(value: str) -> bool:
    """MAC adresi formatını tespit et (MAB istekleri için)."""
    return bool(re.match(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$", value))


async def rate_limit_increment(key: str):
    """Başarısız deneme sayacını artır."""
    await redis_cli.incr(key)
    await redis_cli.expire(key, RATE_LIMIT_WIN)


# =============================================================
# Endpoint: /health
# =============================================================

@app.get("/health")
async def health():
    return {"status": "ok"}


# =============================================================
# Endpoint: POST /auth
# Kullanıcı doğrulama + Redis rate-limiting
# FreeRADIUS'ın authenticate aşamasında veya direkt curl ile çağrılır.
# =============================================================

@app.post("/auth")
async def auth(body: dict):
    username = extract(body, "User-Name") or body.get("username")
    password = extract(body, "User-Password") or body.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username ve password zorunlu")

    # ---- Rate limiting (Redis) ----
    rl_key   = f"rl:{username}"
    attempts = await redis_cli.get(rl_key)
    if attempts and int(attempts) >= RATE_LIMIT_MAX:
        ttl = await redis_cli.ttl(rl_key)
        # HTTP 401 → FreeRADIUS rlm_rest bunu REJECT olarak yorumlar
        raise HTTPException(status_code=401,
                            detail=f"Rate limited. {ttl}s sonra tekrar dene.")

    # ---- Veritabanından kullanıcıyı getir ----
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    if not row:
        await rate_limit_increment(rl_key)
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")

    # ---- Şifre doğrulama ----
    if verify_password(password, row["attribute"], row["value"]):
        await redis_cli.delete(rl_key)  # başarılı girişte sayacı sıfırla
        # HTTP 200 → FreeRADIUS rlm_rest bunu ACCEPT olarak yorumlar
        return {"code": 2, "message": "Access-Accept"}
    else:
        await rate_limit_increment(rl_key)
        raise HTTPException(status_code=401, detail="Hatalı şifre")


# =============================================================
# Endpoint: POST /authorize
# FreeRADIUS authorize aşamasında rlm_rest tarafından çağrılır.
# VLAN atribütlerini döner. MAB (MAC auth) desteği dahil.
# =============================================================

@app.post("/authorize")
async def authorize(body: dict):
    logger.debug("AUTHORIZE IN: %s", json.dumps(body, default=str))
    username = extract(body, "User-Name") or body.get("username")
    if not username:
        return {}

    # ---- Kullanıcının grubunu bul ----
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1 ORDER BY priority LIMIT 1",
            username,
        )

    mab_request = is_mac(username)

    if not row:
        if mab_request:
            # Bilinmeyen MAC → guest VLAN (PDF: "reject veya guest VLAN" — biz guest seçiyoruz)
            vlan = VLAN_MAP["guest"]
        else:
            return {}  # normal kullanıcı ama grubu yok
    else:
        vlan = VLAN_MAP.get(row["groupname"], VLAN_MAP["guest"])

    # Şifre hash'ini al — FreeRADIUS PAP modülü bunu control listesiyle doğrular
    async with db_pool.acquire() as conn:
        pwd_row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    # ---- FreeRADIUS rlm_rest RESPONSE formatı ----
    # Önemli: nested dict/list değil, düz "list:Attr": "değer" formatı
    # "control:Attr" → FreeRADIUS iç listesi (şifre kontrolü için)
    # "reply:Attr"   → Access-Accept paketine eklenir (VLAN)
    response = {
        "reply:Tunnel-Type":             "13",  # 13 = VLAN
        "reply:Tunnel-Medium-Type":      "6",   # 6 = IEEE-802
        "reply:Tunnel-Private-Group-Id": vlan,
    }

    if pwd_row:
        # Bilinen kullanıcı: DB'deki hash ile PAP doğrulaması
        response[f"control:{pwd_row['attribute']}"] = pwd_row["value"]
    elif mab_request:
        # Bilinmeyen MAC: MAB convention'ı gereği User-Password = MAC adresi
        # Cleartext-Password olarak MAC'i set et → PAP doğrulayabilir
        response["control:Cleartext-Password"] = username

    logger.debug("AUTHORIZE OUT: %s", json.dumps(response, default=str))
    return response


# =============================================================
# Endpoint: POST /accounting
# FreeRADIUS accounting aşamasında rlm_rest tarafından çağrılır.
# Start/Interim-Update/Stop paketlerini işler.
# =============================================================

@app.post("/accounting")
async def accounting(body: dict):
    username       = extract(body, "User-Name",          "unknown")
    session_id     = extract(body, "Acct-Session-Id",    "")
    status_type    = extract(body, "Acct-Status-Type",   "")
    nas_ip         = extract(body, "NAS-IP-Address",     "")
    session_time   = int(extract(body, "Acct-Session-Time",    0) or 0)
    input_octets   = int(extract(body, "Acct-Input-Octets",    0) or 0)
    output_octets  = int(extract(body, "Acct-Output-Octets",   0) or 0)

    now = datetime.now(timezone.utc)

    async with db_pool.acquire() as conn:

        if status_type in ("Start", "1"):
            # Yeni oturum başladı → DB'ye yaz, Redis'e cache'le
            await conn.execute(
                """
                INSERT INTO radacct
                    (acctsessionid, username, nasipaddress, acctstarttime, acctstatustype)
                VALUES ($1, $2, $3, $4, 'Start')
                ON CONFLICT (acctsessionid) DO NOTHING
                """,
                session_id, username, nas_ip, now,
            )
            # Redis: 24 saat TTL ile aktif oturum cache'i
            session_data = {
                "session_id": session_id,
                "username":   username,
                "nas_ip":     nas_ip,
                "start":      now.isoformat(),
            }
            await redis_cli.setex(f"session:{session_id}", 86400, json.dumps(session_data))
            await redis_cli.sadd("active_sessions", session_id)

        elif status_type in ("Interim-Update", "3"):
            # Oturum devam ediyor → istatistikleri güncelle
            await conn.execute(
                """
                UPDATE radacct
                SET acctsessiontime  = $1,
                    acctinputoctets  = $2,
                    acctoutputoctets = $3,
                    acctstatustype   = 'Interim-Update',
                    acctupdatetime   = $4
                WHERE acctsessionid = $5
                """,
                session_time, input_octets, output_octets, now, session_id,
            )

        elif status_type in ("Stop", "2"):
            # Oturum bitti → DB'yi kapat, Redis'ten sil
            await conn.execute(
                """
                UPDATE radacct
                SET acctstoptime     = $1,
                    acctsessiontime  = $2,
                    acctinputoctets  = $3,
                    acctoutputoctets = $4,
                    acctstatustype   = 'Stop'
                WHERE acctsessionid = $5
                """,
                now, session_time, input_octets, output_octets, session_id,
            )
            await redis_cli.delete(f"session:{session_id}")
            await redis_cli.srem("active_sessions", session_id)

    return {"status": "ok"}


# =============================================================
# Endpoint: GET /users
# Kullanıcı listesi, grup bilgisi ve aktif oturum sayısı
# =============================================================

@app.get("/users")
async def users():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                rc.username,
                rug.groupname,
                COUNT(ra.radacctid) FILTER (WHERE ra.acctstatustype != 'Stop') AS active_sessions
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            LEFT JOIN radacct ra       ON rc.username = ra.username
            WHERE rc.attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            GROUP BY rc.username, rug.groupname
            ORDER BY rc.username
            """
        )
    return [
        {
            "username":        r["username"],
            "group":           r["groupname"],
            "active_sessions": r["active_sessions"] or 0,
        }
        for r in rows
    ]


# =============================================================
# Endpoint: GET /sessions/active
# Redis'teki aktif oturumları döner (hızlı sorgulama)
# =============================================================

@app.get("/sessions/active")
async def sessions_active():
    session_ids = await redis_cli.smembers("active_sessions")
    sessions = []
    for sid in session_ids:
        data = await redis_cli.get(f"session:{sid}")
        if data:
            sessions.append(json.loads(data))

    return {"count": len(sessions), "sessions": sessions}


# =============================================================
# Endpoint: GET /dashboard
# Tarayıcı tabanlı test ve izleme arayüzü
# =============================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NAC System Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; }
  header { background: #1a1d2e; border-bottom: 1px solid #2d3148; padding: 16px 32px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.3rem; font-weight: 600; color: #7c83fd; }
  header span { font-size: 0.8rem; color: #64748b; }
  .main { padding: 24px 32px; display: grid; gap: 24px; }
  .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }
  .card { background: #1a1d2e; border: 1px solid #2d3148; border-radius: 12px; padding: 20px; }
  .card h2 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .08em; color: #64748b; margin-bottom: 14px; }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .dot-green { background: #22c55e; box-shadow: 0 0 6px #22c55e88; }
  .dot-red   { background: #ef4444; box-shadow: 0 0 6px #ef444488; }
  .dot-gray  { background: #64748b; }
  .stat { font-size: 2rem; font-weight: 700; color: #7c83fd; }
  .stat-label { font-size: 0.78rem; color: #64748b; margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { text-align: left; padding: 8px 10px; color: #64748b; font-weight: 500; border-bottom: 1px solid #2d3148; }
  td { padding: 9px 10px; border-bottom: 1px solid #1e2235; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }
  .badge-admin    { background: #7c3aed22; color: #a78bfa; border: 1px solid #7c3aed44; }
  .badge-employee { background: #0ea5e922; color: #38bdf8; border: 1px solid #0ea5e944; }
  .badge-guest    { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b44; }
  .badge-vlan     { background: #10b98122; color: #34d399; border: 1px solid #10b98144; font-family: monospace; }
  .form-row { display: flex; gap: 10px; flex-wrap: wrap; }
  input[type=text], input[type=password] {
    flex: 1; min-width: 140px; background: #0f1117; border: 1px solid #2d3148;
    color: #e2e8f0; padding: 9px 14px; border-radius: 8px; font-size: 0.9rem; outline: none;
  }
  input:focus { border-color: #7c83fd; }
  button {
    background: #7c83fd; color: #fff; border: none; padding: 9px 20px;
    border-radius: 8px; font-size: 0.9rem; cursor: pointer; font-weight: 600; transition: opacity .15s;
  }
  button:hover { opacity: .85; }
  button.secondary { background: #2d3148; color: #a0aec0; }
  .result { margin-top: 12px; padding: 12px 16px; border-radius: 8px; font-size: 0.88rem; display: none; }
  .result.ok    { background: #14532d44; border: 1px solid #22c55e44; color: #86efac; }
  .result.fail  { background: #7f1d1d44; border: 1px solid #ef444444; color: #fca5a5; }
  .result.info  { background: #1e3a5f44; border: 1px solid #3b82f644; color: #93c5fd; }
  .empty { color: #64748b; font-size: 0.85rem; padding: 8px 0; }
  .refresh-btn { background: none; border: 1px solid #2d3148; color: #64748b; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; float: right; }
  .refresh-btn:hover { color: #e2e8f0; border-color: #4a5568; }
  .section-title { font-size: 1rem; font-weight: 600; color: #c4c9ff; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
</style>
</head>
<body>

<header>
  <h1>NAC System Dashboard</h1>
  <span>S3M Security — Staj Değerlendirmesi</span>
  <span style="margin-left:auto; font-size:.78rem" id="last-update">—</span>
</header>

<div class="main">

  <!-- Durum Kartları -->
  <div class="row" id="status-row">
    <div class="card">
      <h2>API Durumu</h2>
      <div id="api-status"><span class="status-dot dot-gray"></span>Kontrol ediliyor...</div>
    </div>
    <div class="card">
      <h2>Aktif Oturumlar</h2>
      <div class="stat" id="session-count">—</div>
      <div class="stat-label">Redis'teki canlı bağlantılar</div>
    </div>
    <div class="card">
      <h2>Kayıtlı Kullanıcılar</h2>
      <div class="stat" id="user-count">—</div>
      <div class="stat-label">Veritabanındaki hesaplar</div>
    </div>
  </div>

  <div class="row">

    <!-- Kullanıcı Tablosu -->
    <div class="card" style="flex:2">
      <h2>Kullanıcılar &amp; VLAN Ataması <button class="refresh-btn" onclick="loadUsers()">↻ Yenile</button></h2>
      <div id="users-table"><p class="empty">Yükleniyor...</p></div>
    </div>

    <!-- Auth Test -->
    <div class="card" style="flex:1; min-width:260px">
      <h2>Kimlik Doğrulama Testi</h2>
      <div class="form-row" style="flex-direction:column; gap:8px">
        <input type="text"     id="auth-user" placeholder="Kullanıcı adı (ör: admin)" />
        <input type="password" id="auth-pass" placeholder="Şifre (ör: admin123)" />
        <div style="display:flex;gap:8px">
          <button onclick="testAuth()">Test Et</button>
          <button class="secondary" onclick="clearAuth()">Temizle</button>
        </div>
      </div>
      <div class="result" id="auth-result"></div>

      <div style="margin-top:20px">
        <h2 style="margin-bottom:10px">MAB Testi</h2>
        <div class="form-row" style="flex-direction:column; gap:8px">
          <input type="text" id="mac-input" placeholder="MAC adresi (ör: aa:bb:cc:dd:ee:ff)" />
          <button onclick="testMAB()">MAB Test</button>
        </div>
        <div class="result" id="mab-result"></div>
      </div>
    </div>
  </div>

  <!-- Aktif Oturumlar -->
  <div class="card">
    <h2>Aktif Oturumlar (Redis) <button class="refresh-btn" onclick="loadSessions()">↻ Yenile</button></h2>
    <div id="sessions-table"><p class="empty">Yükleniyor...</p></div>
  </div>

</div>

<script>
const VLAN_LABELS = { "10": "VLAN 10 — Admin", "20": "VLAN 20 — Employee", "30": "VLAN 30 — Guest" };
const VLAN_MAP    = { admin: "10", employee: "20", guest: "30" };

async function api(path, opts) {
  try {
    const r = await fetch(path, opts);
    const data = await r.json();
    return { ok: r.ok, status: r.status, data };
  } catch(e) { return { ok: false, status: 0, data: { detail: e.message } }; }
}

async function checkHealth() {
  const r = await api("/health");
  const el = document.getElementById("api-status");
  if (r.ok) {
    el.innerHTML = '<span class="status-dot dot-green"></span><strong style="color:#22c55e">Çalışıyor</strong>';
  } else {
    el.innerHTML = '<span class="status-dot dot-red"></span><strong style="color:#ef4444">Hata</strong>';
  }
}

async function loadUsers() {
  const r = await api("/users");
  const el = document.getElementById("users-table");
  const cnt = document.getElementById("user-count");
  if (!r.ok || !r.data.length) { el.innerHTML = '<p class="empty">Kullanıcı bulunamadı.</p>'; return; }
  cnt.textContent = r.data.length;
  const rows = r.data.map(u => {
    const grp   = u.group || "—";
    const vlan  = VLAN_MAP[grp] || "—";
    const gbadge = grp !== "—" ? `<span class="badge badge-${grp}">${grp}</span>` : "—";
    const vbadge = vlan !== "—" ? `<span class="badge badge-vlan">VLAN ${vlan}</span>` : "—";
    const sess  = u.active_sessions > 0 ? `<span style="color:#22c55e">${u.active_sessions} aktif</span>` : '<span style="color:#64748b">0</span>';
    return `<tr><td><strong>${u.username}</strong></td><td>${gbadge}</td><td>${vbadge}</td><td>${sess}</td></tr>`;
  }).join("");
  el.innerHTML = `<table><thead><tr><th>Kullanıcı</th><th>Grup</th><th>VLAN</th><th>Oturum</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadSessions() {
  const r = await api("/sessions/active");
  const el = document.getElementById("sessions-table");
  const cnt = document.getElementById("session-count");
  cnt.textContent = r.data?.count ?? "—";
  if (!r.data?.sessions?.length) { el.innerHTML = '<p class="empty">Aktif oturum yok.</p>'; return; }
  const rows = r.data.sessions.map(s => {
    const start = s.start ? new Date(s.start).toLocaleString("tr-TR") : "—";
    return `<tr><td><code>${s.session_id}</code></td><td>${s.username}</td><td>${s.nas_ip || "—"}</td><td>${start}</td></tr>`;
  }).join("");
  el.innerHTML = `<table><thead><tr><th>Oturum ID</th><th>Kullanıcı</th><th>NAS IP</th><th>Başlangıç</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function testAuth() {
  const u = document.getElementById("auth-user").value.trim();
  const p = document.getElementById("auth-pass").value.trim();
  const el = document.getElementById("auth-result");
  if (!u || !p) { showResult(el, "fail", "Kullanıcı adı ve şifre gerekli."); return; }
  const r = await api("/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: u, password: p })
  });
  if (r.ok) {
    showResult(el, "ok", `✓ Access-Accept — Kimlik doğrulandı`);
  } else {
    const msg = r.data?.detail || "Bilinmeyen hata";
    showResult(el, "fail", `✗ ${msg}`);
  }
  loadUsers(); loadSessions();
}

async function testMAB() {
  const mac = document.getElementById("mac-input").value.trim();
  const el  = document.getElementById("mab-result");
  if (!mac) { showResult(el, "fail", "MAC adresi girin."); return; }
  const r = await api("/authorize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ "User-Name": mac, "User-Password": mac })
  });
  if (r.ok && r.data["reply:Tunnel-Private-Group-Id"]) {
    const vlan = r.data["reply:Tunnel-Private-Group-Id"];
    showResult(el, "ok", `✓ MAC kabul edildi → VLAN ${vlan} (${VLAN_LABELS[vlan] || vlan})`);
  } else if (r.ok && Object.keys(r.data).length === 0) {
    showResult(el, "fail", "✗ Bilinmeyen MAC, yanıt boş döndü.");
  } else {
    showResult(el, "info", `Yanıt: ${JSON.stringify(r.data)}`);
  }
}

function clearAuth() {
  document.getElementById("auth-user").value = "";
  document.getElementById("auth-pass").value = "";
  const el = document.getElementById("auth-result");
  el.style.display = "none";
}

function showResult(el, type, msg) {
  el.className = "result " + type;
  el.textContent = msg;
  el.style.display = "block";
}

function updateTimestamp() {
  document.getElementById("last-update").textContent =
    "Son güncelleme: " + new Date().toLocaleTimeString("tr-TR");
}

async function refreshAll() {
  await Promise.all([checkHealth(), loadUsers(), loadSessions()]);
  updateTimestamp();
}

refreshAll();
setInterval(refreshAll, 10000);  // 10 saniyede bir otomatik yenile
</script>
</body>
</html>""")
