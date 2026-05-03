"""
OAuth2 Authorization Server (IdP simulation)
Runs on port 8000
Supports: Authorization Code + PKCE, Client Credentials
"""

import hashlib
import base64
import secrets
import time
import json
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

app = FastAPI(title="OAuth2 Authorization Server", version="1.0.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# In-memory stores (playground only - not for production)
CLIENTS = {
    "playground-client": {
        "client_secret": "playground-secret",
        "redirect_uris": ["http://localhost:8001/callback", "http://localhost:8001/guided/callback"],
        "grant_types": ["authorization_code", "client_credentials"],
        "scopes": ["openid", "profile", "email", "read", "write"],
    }
}

USERS = {
    "alice": {"password": "alice123", "name": "Alice Example", "email": "alice@example.com"},
    "bob": {"password": "bob123", "name": "Bob Example", "email": "bob@example.com"},
}

# Runtime state
auth_codes = {}   # code -> {client_id, redirect_uri, scope, user, pkce_challenge, expires_at}
access_tokens = {}  # token -> {client_id, scope, user, expires_at}
trace_log = []    # ordered list of trace events for the flow tracer


def add_trace(channel: str, direction: str, label: str, data: dict):
    trace_log.append({
        "ts": round(time.time() * 1000),
        "channel": channel,   # "front" or "back"
        "direction": direction,  # "request" or "response"
        "label": label,
        "data": data,
    })
    # Keep last 100 events
    if len(trace_log) > 100:
        trace_log.pop(0)


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return computed == code_challenge
    return code_verifier == code_challenge  # plain method


# -------------------------
# Discovery endpoint
# -------------------------
@app.get("/.well-known/openid-configuration")
async def discovery():
    return {
        "issuer": "http://localhost:8000",
        "authorization_endpoint": "http://localhost:8000/authorize",
        "token_endpoint": "http://localhost:8000/token",
        "introspection_endpoint": "http://localhost:8000/introspect",
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "profile", "email", "read", "write"],
    }


# -------------------------
# Front channel: /authorize
# -------------------------
@app.get("/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid"),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query("S256"),
):
    add_trace("front", "request", "Authorization Request (browser redirect)", {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "pkce": bool(code_challenge),
        "code_challenge_method": code_challenge_method,
    })

    if client_id not in CLIENTS:
        raise HTTPException(status_code=400, detail="Unknown client")
    if redirect_uri not in CLIENTS[client_id]["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code supported")

    return templates.TemplateResponse("login.html", {
        "request": request,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state or "",
        "code_challenge": code_challenge or "",
        "code_challenge_method": code_challenge_method or "S256",
    })


@app.post("/authorize", response_class=HTMLResponse)
async def authorize_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("openid"),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
):
    user = USERS.get(username)
    if not user or user["password"] != password:
        add_trace("front", "response", "Login Failed", {"reason": "invalid credentials"})
        return templates.TemplateResponse("login.html", {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "error": "Invalid username or password",
        })

    code = generate_token(16)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "user": username,
        "pkce_challenge": code_challenge,
        "pkce_method": code_challenge_method,
        "expires_at": time.time() + 300,  # 5 min for guided learning mode
    }

    add_trace("front", "response", "Authorization Code Issued (redirect)", {
        "code": code[:8] + "...",
        "state": state,
        "user": username,
    })

    location = f"{redirect_uri}?code={code}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(url=location, status_code=302)


# -------------------------
# Back channel: /token
# -------------------------
@app.post("/token")
async def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
):
    add_trace("back", "request", "Token Request (server-to-server)", {
        "grant_type": grant_type,
        "client_id": client_id,
        "has_secret": bool(client_secret),
        "has_code": bool(code),
        "has_verifier": bool(code_verifier),
    })

    client = CLIENTS.get(client_id)
    if not client:
        raise HTTPException(status_code=401, detail="Unknown client")

    if grant_type == "authorization_code":
        if code not in auth_codes:
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        stored = auth_codes.pop(code)
        if stored["expires_at"] < time.time():
            raise HTTPException(status_code=400, detail="Code expired")
        if stored["client_id"] != client_id:
            raise HTTPException(status_code=400, detail="Code belongs to different client")
        if stored["redirect_uri"] != redirect_uri:
            raise HTTPException(status_code=400, detail="redirect_uri mismatch")

        # PKCE check
        if stored["pkce_challenge"]:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier required")
            if not verify_pkce(code_verifier, stored["pkce_challenge"], stored["pkce_method"]):
                raise HTTPException(status_code=400, detail="PKCE verification failed")
        else:
            # No PKCE: require client_secret
            if client_secret != client["client_secret"]:
                raise HTTPException(status_code=401, detail="Invalid client_secret")

        access_token = generate_token()
        access_tokens[access_token] = {
            "client_id": client_id,
            "scope": stored["scope"],
            "user": stored["user"],
            "expires_at": time.time() + 3600,
        }

        add_trace("back", "response", "Access Token Issued", {
            "token": access_token[:8] + "...",
            "scope": stored["scope"],
            "user": stored["user"],
            "expires_in": 3600,
        })

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": stored["scope"],
        }

    elif grant_type == "client_credentials":
        if client_secret != client["client_secret"]:
            raise HTTPException(status_code=401, detail="Invalid client_secret")

        token_scope = scope or "read"
        access_token = generate_token()
        access_tokens[access_token] = {
            "client_id": client_id,
            "scope": token_scope,
            "user": None,
            "expires_at": time.time() + 3600,
        }

        add_trace("back", "response", "Client Credentials Token Issued", {
            "token": access_token[:8] + "...",
            "scope": token_scope,
            "client_id": client_id,
        })

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": token_scope,
        }

    raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


# -------------------------
# Back channel: /introspect
# -------------------------
@app.post("/introspect")
async def introspect(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
):
    client = CLIENTS.get(client_id)
    if not client or client_secret != client["client_secret"]:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    stored = access_tokens.get(token)
    add_trace("back", "request", "Token Introspection", {
        "token": token[:8] + "...",
        "client_id": client_id,
    })

    if not stored or stored["expires_at"] < time.time():
        add_trace("back", "response", "Introspection: inactive", {})
        return {"active": False}

    result = {
        "active": True,
        "scope": stored["scope"],
        "client_id": stored["client_id"],
        "exp": int(stored["expires_at"]),
        "token_type": "bearer",
    }
    if stored["user"]:
        result["sub"] = stored["user"]

    add_trace("back", "response", "Introspection: active", result)
    return result


# -------------------------
# Tracer API (consumed by client UI)
# -------------------------
@app.get("/trace")
async def get_trace():
    return {"events": trace_log}


@app.delete("/trace")
async def clear_trace():
    trace_log.clear()
    return {"cleared": True}
