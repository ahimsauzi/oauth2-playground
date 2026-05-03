# OAuth2 Playground

Dev and learning tool inside ccode-pipeline. Runs two local servers to demonstrate OAuth2 flows with a live tracer showing which calls are front channel (browser) vs back channel (server-to-server).

## Start

```bash
cd tools/oauth2-playground
pip install -r requirements.txt
python run.py
```

Open http://localhost:8001

## Flows

| Flow | Channel | Description |
|---|---|---|
| Authorization Code + PKCE | Front + Back | Redirect to IdP, login, exchange code with PKCE verifier. No client secret. |
| Authorization Code (secret) | Front + Back | Same redirect flow but uses client_secret instead of PKCE. |
| Client Credentials | Back only | No user, no browser. Server-to-server token request. |
| Token Introspection | Back only | Validate an active token with the auth server. |

## Architecture

```
localhost:8001 (Client App)         localhost:8000 (Auth Server / IdP)
     |                                        |
     |-- front channel (browser redirect) --> |
     |<-- authorization code --------------- |
     |                                        |
     |-- back channel (server POST) --------> |
     |<-- access token -------------------- |
```

## Test Users

alice / alice123
bob / bob123

## Notes

Put observations and learnings in `notes/`. Sage monitors this folder for content drafts.
