"""MobSF HTTP transport (SRP: HTTP only, no analysis knowledge)."""

from __future__ import annotations

from typing import Any

import requests


class MobSFError(RuntimeError):
    pass


class MobSFTransport:
    """Authenticated POST transport with separate quick/scan timeout budgets."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 20, scan_timeout: int = 600):
        if not api_key:
            raise MobSFError("MobSF API key missing (AUTOTEST_MOBSF_API_KEY / --mobsf-api-key)")
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": api_key}
        self.timeout = timeout
        self.scan_timeout = scan_timeout

    def post(self, path: str, timeout: int | None = None, **kwargs: Any) -> Any:
        try:
            resp = requests.post(
                self.base_url + path,
                headers=self.headers,
                timeout=timeout or self.timeout,
                **kwargs,
            )
        except requests.RequestException as e:
            raise MobSFError(f"MobSF unreachable at {self.base_url}: {e}") from e
        if resp.status_code != 200:
            raise MobSFError(f"MobSF {path} -> HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()
