"""
OAuth2 Client App (Relying Party)
Runs on port 8001
Initiates flows, handles callbacks, displays results + live tracer
"""

import hashlib
import base64
import secrets
import httpx
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Optional

app = FastAPI(title="OAuth2 Client App", version="1.0.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

AUTH_SERVER = "http://localhost:8000"
CLIENT_ID = "playground-client"
CLIENT_SECRET = "playground-secret"
REDIRECT_URI = "http://localhost:8001/callback"

# Session store (in-memory, single user playground)
session = {}


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{AUTH_SERVER}/trace")
        events = resp.json().get("events", [])
    return templates.TemplateResponse("home.html", {
        "request": request,
        "session": session,
        "events": events,
    })


@app.get("/clear")
async def clear_session():
    session.clear()
    async with httpx.AsyncClient() as client:
        await client.delete(f"{AUTH_SERVER}/trace")
    return RedirectResponse(url="/")


# -------------------------
# Flow 1: Authorization Code + PKCE (front channel)
# -------------------------
@app.get("/login/pkce")
async def login_pkce():
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    session["pkce_verifier"] = verifier
    session["state"] = state
    session["flow"] = "authorization_code_pkce"

    url = (
        f"{AUTH_SERVER}/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid+profile+email"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )
    return RedirectResponse(url=url)


# -------------------------
# Flow 2: Authorization Code without PKCE (back channel secret)
# -------------------------
@app.get("/login/code")
async def login_code():
    state = secrets.token_urlsafe(16)
    session["state"] = state
    session["flow"] = "authorization_code"

    url = (
        f"{AUTH_SERVER}/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid+profile"
        f"&state={state}"
    )
    return RedirectResponse(url=url)


# -------------------------
# Callback handler (both auth code flows)
# -------------------------
@app.get("/callback")
async def callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
):
    if error:
        session["error"] = error
        return RedirectResponse(url="/")

    if state != session.get("state"):
        session["error"] = "State mismatch - possible CSRF"
        return RedirectResponse(url="/")

    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code": code,
    }

    if session.get("flow") == "authorization_code_pkce":
        token_data["code_verifier"] = session["pkce_verifier"]
    else:
        token_data["client_secret"] = CLIENT_SECRET

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_SERVER}/token", data=token_data)

    if resp.status_code != 200:
        session["error"] = f"Token exchange failed: {resp.text}"
        return RedirectResponse(url="/")

    token_resp = resp.json()
    session["access_token"] = token_resp.get("access_token")
    session["scope"] = token_resp.get("scope")
    session["token_type"] = token_resp.get("token_type")
    session.pop("error", None)
    return RedirectResponse(url="/")


# -------------------------
# Flow 3: Client Credentials (back channel only)
# -------------------------
@app.get("/login/client-credentials")
async def client_credentials():
    session["flow"] = "client_credentials"
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_SERVER}/token", data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "read write",
        })

    if resp.status_code != 200:
        session["error"] = f"Client credentials failed: {resp.text}"
        return RedirectResponse(url="/")

    token_resp = resp.json()
    session["access_token"] = token_resp.get("access_token")
    session["scope"] = token_resp.get("scope")
    session["token_type"] = token_resp.get("token_type")
    session.pop("error", None)
    return RedirectResponse(url="/")


# -------------------------
# Token introspection
# -------------------------
@app.get("/introspect")
async def introspect():
    token = session.get("access_token")
    if not token:
        session["error"] = "No access token to introspect"
        return RedirectResponse(url="/")

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_SERVER}/introspect", data={
            "token": token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        })

    session["introspect_result"] = resp.json()
    return RedirectResponse(url="/")
