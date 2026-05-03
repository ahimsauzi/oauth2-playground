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
from .flow_store import flow_store

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


# =========================================================
# Guided step-through mode
# Each route renders a pause page. The user reads, clicks,
# and the next route executes the actual network call.
# =========================================================

TOTAL_PKCE_STEPS = 5
TOTAL_CC_STEPS = 2


def p(value: str, note: str = "") -> dict:
    """Helper: parameter entry with optional explanatory note."""
    return {"value": value, "note": note}


# -------------------------
# Guided PKCE flow
# -------------------------

@app.get("/guided/pkce/step1", response_class=HTMLResponse)
async def guided_pkce_step1(request: Request):
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    flow_store.start_pkce(verifier, challenge, state)

    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 1, "step_total": TOTAL_PKCE_STEPS,
        "step_title": "Generate PKCE Pair",
        "channel": "front",
        "what_happening": (
            "Before touching the network, we generate a PKCE pair locally in the client app. "
            "The <strong>code_verifier</strong> is a random secret that never leaves this app. "
            "The <strong>code_challenge</strong> is a SHA-256 hash of the verifier sent to the auth server. "
            "When we later exchange the code for a token, we send the verifier. "
            "The auth server hashes it and checks it matches the challenge. "
            "This proves the token request comes from the same party that started the login."
        ),
        "security_note": "The verifier is never sent to the browser and never sent to the auth server during the front-channel step. It only travels on the back channel.",
        "request_params": {
            "code_verifier": p(verifier, "Random 32-byte secret, base64url encoded. Stays in the app."),
            "code_challenge": p(challenge, "SHA-256(code_verifier), base64url encoded. Sent to auth server."),
            "code_challenge_method": p("S256", "Tells the auth server which hash algorithm to use when verifying."),
        },
        "response_params": None,
        "action_label": "Step 2: Send Authorization Request",
        "action_url": "/guided/pkce/step2",
        "action_method": "get",
    })


@app.get("/guided/pkce/step2", response_class=HTMLResponse)
async def guided_pkce_step2(request: Request):
    if not flow_store.active:
        return RedirectResponse(url="/guided/pkce/step1")

    guided_redirect = "http://localhost:8001/guided/callback"
    auth_url = (
        f"{AUTH_SERVER}/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={guided_redirect}"
        f"&scope=openid+profile+email"
        f"&state={flow_store.state}"
        f"&code_challenge={flow_store.challenge}"
        f"&code_challenge_method=S256"
    )

    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 2, "step_total": TOTAL_PKCE_STEPS,
        "step_title": "Authorization Request (Front Channel)",
        "channel": "front",
        "what_happening": (
            "We redirect the browser to the auth server's <strong>/authorize</strong> endpoint. "
            "This is the <strong>front channel</strong>: the request travels through the browser as a URL redirect, "
            "fully visible in browser history and network logs. "
            "The user logs in on the auth server's login page (not our app), "
            "approves the scopes, and the server redirects back with a short-lived authorization code. "
            "The code is not the token. It is a one-time voucher that expires in 60 seconds."
        ),
        "security_note": "Never put sensitive data in the authorization request URL. It appears in browser history, server logs, and HTTP Referer headers.",
        "request_params": {
            "response_type": p("code", "We want an authorization code back, not a token directly."),
            "client_id": p(CLIENT_ID, "Identifies our app to the auth server."),
            "redirect_uri": p(REDIRECT_URI, "Must match exactly what is registered on the auth server."),
            "scope": p("openid profile email", "Permissions being requested on behalf of the user."),
            "state": p(flow_store.state, "Random CSRF token. We verify it matches when the code comes back."),
            "code_challenge": p(flow_store.challenge[:20] + "...", "The PKCE challenge. Auth server stores this to verify later."),
            "code_challenge_method": p("S256", "SHA-256 hashing."),
        },
        "response_params": None,
        "action_label": "Redirect to Auth Server (login required)",
        "action_url": auth_url,
        "action_method": "get",
    })


@app.get("/guided/callback", response_class=HTMLResponse)
async def guided_callback(
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
):
    if error or not code:
        return RedirectResponse(url="/")
    flow_store.save_code(code, state or "")
    return RedirectResponse(url="/guided/pkce/step3")


@app.get("/guided/pkce/step3", response_class=HTMLResponse)
async def guided_pkce_step3(request: Request):
    if not flow_store.active or not flow_store.auth_code:
        return RedirectResponse(url="/guided/pkce/step1")

    state_ok = flow_store.state == flow_store.returned_state

    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 3, "step_total": TOTAL_PKCE_STEPS,
        "step_title": "Authorization Code Received",
        "channel": "front",
        "what_happening": (
            "The auth server redirected the browser back to our <strong>/guided/callback</strong> endpoint "
            "with an authorization code in the URL. "
            "This is still the front channel: the code arrived via a browser redirect, visible in the URL bar. "
            "We checked the <strong>state</strong> parameter matches what we sent. "
            f"State match: <strong>{'yes' if state_ok else 'NO - CSRF possible'}</strong>. "
            "The code is a one-time voucher. In production it typically expires in 60 seconds. "
            "This playground gives you 5 minutes to read and continue. "
            "It is not an access token. It proves the user logged in but gives us nothing on its own. "
            "Next we exchange it on the back channel."
        ),
        "security_note": "The authorization code is single-use. If an attacker intercepts it and races to exchange it first, PKCE prevents them: they don't have the code_verifier.",
        "request_params": None,
        "response_params": {
            "code": p(flow_store.auth_code[:12] + "...", "Short-lived one-time authorization code. Expires in 60 seconds."),
            "state": p(flow_store.returned_state, "Must match what we sent. Validates this response is for our request."),
            "state_valid": p("yes" if state_ok else "NO", "CSRF check result."),
        },
        "action_label": "Step 4: Exchange Code for Token (Back Channel)",
        "action_url": "/guided/pkce/step4",
        "action_method": "post",
    })


@app.post("/guided/pkce/step4", response_class=HTMLResponse)
async def guided_pkce_step4_exec(request: Request):
    if not flow_store.active or not flow_store.auth_code:
        return RedirectResponse(url="/guided/pkce/step1", status_code=303)

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_SERVER}/token", data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:8001/guided/callback",
            "code": flow_store.auth_code,
            "code_verifier": flow_store.verifier,
        })

    if resp.status_code != 200:
        return templates.TemplateResponse("step.html", {"request": request,
            "step_num": 4, "step_total": TOTAL_PKCE_STEPS,
            "step_title": "Token Exchange Failed",
            "channel": "back",
            "what_happening": f"The token request failed: {resp.text}",
            "security_note": "",
            "request_params": None,
            "response_params": {"error": p(resp.text)},
            "action_label": "Start over",
            "action_url": "/guided/pkce/step1",
            "action_method": "get",
        })

    token_resp = resp.json()
    flow_store.save_token(token_resp)
    return RedirectResponse(url="/guided/pkce/step4", status_code=303)


@app.get("/guided/pkce/step4", response_class=HTMLResponse)
async def guided_pkce_step4_show(request: Request):
    if not flow_store.active or not flow_store.token_resp:
        return RedirectResponse(url="/guided/pkce/step1")

    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 4, "step_total": TOTAL_PKCE_STEPS,
        "step_title": "Token Exchange (Back Channel)",
        "channel": "back",
        "what_happening": (
            "We POST directly from our server to the auth server's <strong>/token</strong> endpoint. "
            "This is the <strong>back channel</strong>: server-to-server, never touches the browser. "
            "We send the authorization code AND the <strong>code_verifier</strong>. "
            "The auth server hashes the verifier and checks it against the challenge we sent in Step 2. "
            "If they match, it knows this token request comes from the same party that started the login. "
            "No client secret needed: PKCE replaces the secret for public clients."
        ),
        "security_note": "The code_verifier is the proof of possession. An attacker who intercepted the authorization code cannot complete this step without it.",
        "request_params": {
            "grant_type": p("authorization_code", "Tells the token endpoint which flow we are completing."),
            "client_id": p(CLIENT_ID, "Identifies our app."),
            "redirect_uri": p(REDIRECT_URI, "Must match the original authorization request."),
            "code": p(flow_store.auth_code[:12] + "...", "The authorization code from the front channel."),
            "code_verifier": p(flow_store.verifier[:20] + "...", "The secret we generated in Step 1. Never sent to the browser."),
        },
        "response_params": {
            "access_token": p(flow_store.token_resp.get("access_token", "")[:16] + "...", "Opaque bearer token. Present this to resource servers."),
            "token_type": p(flow_store.token_resp.get("token_type", ""), "Always 'bearer' for OAuth2."),
            "expires_in": p(str(flow_store.token_resp.get("expires_in", "")), "Seconds until the token expires."),
            "scope": p(flow_store.token_resp.get("scope", ""), "What the token is authorized to do."),
        },
        "action_label": "Step 5: Introspect the Token",
        "action_url": "/guided/pkce/step5",
        "action_method": "post",
    })


@app.post("/guided/pkce/step5", response_class=HTMLResponse)
async def guided_pkce_step5_exec(request: Request):
    token = flow_store.token_resp.get("access_token", "")
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_SERVER}/introspect", data={
            "token": token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        })
    flow_store.save_introspect(resp.json())
    return RedirectResponse(url="/guided/pkce/step5", status_code=303)


@app.get("/guided/pkce/step5", response_class=HTMLResponse)
async def guided_pkce_step5_show(request: Request):
    if not flow_store.active:
        return RedirectResponse(url="/guided/pkce/step1")

    result = flow_store.introspect
    flow_store.clear()

    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 5, "step_total": TOTAL_PKCE_STEPS,
        "step_title": "Token Introspection (Back Channel)",
        "channel": "back",
        "what_happening": (
            "Token introspection (RFC 7662) lets a resource server ask the auth server: "
            "<strong>is this token still valid?</strong> "
            "We POST the token to <strong>/introspect</strong> along with our client credentials. "
            "The auth server returns the token's metadata: active status, scope, subject, expiry. "
            "This is how a resource server validates an opaque token it cannot decode itself. "
            "The full Authorization Code + PKCE flow is now complete."
        ),
        "security_note": "Introspection is a back-channel call. The token is never exposed in the browser. Only trusted resource servers should have introspection access.",
        "request_params": {
            "token": p(flow_store.token_resp.get("access_token", "")[:16] + "..." if flow_store.active else "token", "The access token to validate."),
            "client_id": p(CLIENT_ID, "Resource server's identifier."),
            "client_secret": p("***", "Resource server's credential. Proves it is authorized to introspect."),
        },
        "response_params": {k: p(str(v)) for k, v in result.items()},
        "action_label": "Done - back to dashboard",
        "action_url": "/",
        "action_method": "get",
    })


# -------------------------
# Guided Client Credentials flow
# -------------------------

@app.get("/guided/cc/step1", response_class=HTMLResponse)
async def guided_cc_step1(request: Request):
    flow_store.start_cc()
    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 1, "step_total": TOTAL_CC_STEPS,
        "step_title": "Client Credentials Request (Back Channel)",
        "channel": "back",
        "what_happening": (
            "Client Credentials is the simplest OAuth2 grant. "
            "There is no user, no browser, no authorization code. "
            "The client app POSTs its own credentials directly to the token endpoint. "
            "This is machine-to-machine authorization: the client is both the requester and the resource owner. "
            "Common uses: background jobs, microservices, API-to-API calls. "
            "Because there is no user involved, the token represents the <strong>application</strong>, not a person."
        ),
        "security_note": "The client_secret must be kept confidential. If it is exposed, any attacker can obtain tokens with the client's full scope. Rotate secrets regularly.",
        "request_params": {
            "grant_type": p("client_credentials", "No user, no code, just the client authenticating itself."),
            "client_id": p(CLIENT_ID, "Identifies the application."),
            "client_secret": p("***", "The application's password. Sent on the back channel only."),
            "scope": p("read write", "Requested permissions. No user consent screen needed."),
        },
        "response_params": None,
        "action_label": "Execute Token Request",
        "action_url": "/guided/cc/step2",
        "action_method": "post",
    })


@app.post("/guided/cc/step2", response_class=HTMLResponse)
async def guided_cc_step2_exec(request: Request):
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{AUTH_SERVER}/token", data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "read write",
        })
    token_resp = resp.json()
    flow_store.save_token(token_resp)
    return RedirectResponse(url="/guided/cc/step2", status_code=303)


@app.get("/guided/cc/step2", response_class=HTMLResponse)
async def guided_cc_step2_show(request: Request):
    result = flow_store.token_resp
    flow_store.clear()

    return templates.TemplateResponse("step.html", {"request": request,
        "step_num": 2, "step_total": TOTAL_CC_STEPS,
        "step_title": "Token Issued - No User Required",
        "channel": "back",
        "what_happening": (
            "The auth server validated the client credentials and issued an access token. "
            "Notice what is missing: no <strong>sub</strong> (subject) claim, "
            "because there is no user. The token belongs to the application. "
            "This is how microservices authenticate to each other. "
            "The token is opaque to the recipient; introspection would reveal the client_id and scope. "
            "The entire flow happened server-to-server: the browser was never involved."
        ),
        "security_note": "Client Credentials tokens should have narrow scope. A broad-scope machine token is a high-value target: if stolen, it provides application-level access with no user friction.",
        "request_params": None,
        "response_params": {
            "access_token": p(result.get("access_token", "")[:16] + "...", "Machine token. Represents the application, not a user."),
            "token_type": p(result.get("token_type", ""), "Bearer: any holder can use it."),
            "expires_in": p(str(result.get("expires_in", "")), "Short-lived. Clients should cache and reuse until near expiry."),
            "scope": p(result.get("scope", ""), "What this application token can do."),
        },
        "action_label": "Done - back to dashboard",
        "action_url": "/",
        "action_method": "get",
    })
