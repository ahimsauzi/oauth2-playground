"""
Carries in-progress OAuth flow data between guided step pause pages.
Cleared after the final step is shown.
"""
import time


class FlowStore:
    def __init__(self):
        self._data: dict = {}

    def start_pkce(self, verifier: str, challenge: str, state: str) -> None:
        self._data = {
            "flow": "pkce",
            "verifier": verifier,
            "challenge": challenge,
            "state": state,
            "started_at": time.time(),
        }

    def start_code(self, state: str) -> None:
        self._data = {
            "flow": "code",
            "state": state,
            "started_at": time.time(),
        }

    def start_cc(self) -> None:
        self._data = {"flow": "client_credentials", "started_at": time.time()}

    def save_code(self, code: str, state: str) -> None:
        self._data["auth_code"] = code
        self._data["returned_state"] = state

    def save_token(self, token_resp: dict) -> None:
        self._data["token_resp"] = token_resp

    def save_introspect(self, result: dict) -> None:
        self._data["introspect"] = result

    def clear(self) -> None:
        self._data = {}

    @property
    def active(self) -> bool:
        return bool(self._data)

    @property
    def flow(self) -> str:
        return self._data.get("flow", "")

    @property
    def verifier(self) -> str:
        return self._data.get("verifier", "")

    @property
    def challenge(self) -> str:
        return self._data.get("challenge", "")

    @property
    def state(self) -> str:
        return self._data.get("state", "")

    @property
    def auth_code(self) -> str:
        return self._data.get("auth_code", "")

    @property
    def returned_state(self) -> str:
        return self._data.get("returned_state", "")

    @property
    def token_resp(self) -> dict:
        return self._data.get("token_resp", {})

    @property
    def introspect(self) -> dict:
        return self._data.get("introspect", {})


flow_store = FlowStore()
