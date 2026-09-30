"""Frida runner (M4.2): attach + load hook script + collect AUTOTEST_HOOK lines.

Graceful degradation: no `frida` CLI / no frida-server on device /
no target process -> FridaUnavailable (callers emit INCONCLUSIVE, never fail).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import env as env_mod

SCRIPTS_DIR = Path(__file__).parent / "frida"


class FridaUnavailable(RuntimeError):
    pass


@dataclass
class HookHit:
    hook: str
    detail: dict = field(default_factory=dict)


def check_ready(package: str) -> None:
    if not shutil.which("frida"):
        raise FridaUnavailable("frida CLI not installed (pip install frida-tools)")
    try:
        ps = env_mod._adb("shell ps -A", timeout=30)
    except env_mod.DynamicEnvError as e:
        raise FridaUnavailable(f"adb unavailable: {e}") from e
    if "frida-server" not in ps:
        raise FridaUnavailable("frida-server not running on device")
    try:
        pids = env_mod._adb("shell pidof " + package, timeout=30).strip()
    except env_mod.DynamicEnvError:
        pids = ""
    if not pids:
        raise FridaUnavailable(f"target {package} not running")


def run_script(package: str, script: str, dwell: int = 60) -> list[HookHit]:
    """Attach to PACKAGE, stream SCRIPT output for DWELL seconds, return hits."""
    check_ready(package)
    path = SCRIPTS_DIR / script
    if not path.is_file():
        raise FridaUnavailable(f"hook script missing: {path.name}")
    serial = env_mod.selected_serial()
    cmd = ["frida", "-U", "-n", package, "-l", str(path)]
    if serial:
        cmd[1:1] = ["-D", serial]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=dwell, check=False)
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        out += e.stderr if isinstance(e.stderr, str) else ""
        return parse_hits(out)
    except FileNotFoundError as e:
        raise FridaUnavailable("frida CLI vanished") from e
    return parse_hits((proc.stdout or "") + (proc.stderr or ""))


def parse_hits(output: str) -> list[HookHit]:
    import json

    hits: list[HookHit] = []
    for line in output.splitlines():
        if "AUTOTEST_HOOK " not in line:
            continue
        try:
            obj = json.loads(line.split("AUTOTEST_HOOK ", 1)[1])
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(obj, dict) and "hook" in obj:
            hits.append(HookHit(hook=str(obj.pop("hook")), detail=obj))
    return hits
