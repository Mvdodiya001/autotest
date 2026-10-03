"""Frida runner (M4.2): attach or spawn, load hook scripts, collect AUTOTEST_HOOK lines.

Graceful degradation: no `frida` CLI / no frida-server on device /
no target process -> FridaUnavailable (callers emit INCONCLUSIVE, never fail).

`run_script` attaches to a process that is already running. `start_hooks`
cold-starts the package with the scripts loaded so startup code is observed.
The caller stops that session when the exercise pass returns.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import env as env_mod

SCRIPTS_DIR = Path(__file__).parent / "frida"
# Quiet-mode ceiling above the UI dwell. The caller stops the session when
# exercise returns; this only bounds a session that is not closed. Component
# probes run before the UI dwell, so the ceiling has to outlast that preamble.
HOOK_SLACK_S = 120
SPAWN_WAIT_S = 45
# Pid can appear while Frida still has the process suspended. If the resume
# line is missed, wait this long after the pid shows up before exercising.
PID_READY_S = 3
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class FridaUnavailable(RuntimeError):
    pass


@dataclass
class HookHit:
    hook: str
    detail: dict = field(default_factory=dict)


def check_toolchain(serial: str = "") -> None:
    """Frida CLI and frida-server. Does not require the target process."""
    if not shutil.which("frida"):
        raise FridaUnavailable("frida CLI not installed (pip install frida-tools)")
    try:
        ps = env_mod._adb("shell", "ps -A", serial=serial, timeout=30)
    except env_mod.DynamicEnvError as e:
        raise FridaUnavailable(f"adb unavailable: {e}") from e
    if "frida-server" not in ps:
        raise FridaUnavailable("frida-server not running on device")


def check_ready(package: str, serial: str = "") -> None:
    check_toolchain(serial)
    if not _pidof(package, serial):
        raise FridaUnavailable(f"target {package} not running")


def _pidof(package: str, serial: str) -> str:
    try:
        return env_mod._adb("shell", "pidof " + package, serial=serial, timeout=15).strip()
    except env_mod.DynamicEnvError:
        return ""


def _reset_package(package: str, serial: str) -> None:
    """Force-stop so the next spawn is a cold start the hooks can see."""
    try:
        env_mod._adb("shell", "am", "force-stop", package, serial=serial, timeout=30)
    except env_mod.DynamicEnvError as exc:
        raise FridaUnavailable(f"could not reset {package} before hooks: {exc}") from exc
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not _pidof(package, serial):
            return
        time.sleep(0.2)
    raise FridaUnavailable(f"{package} still running after force-stop")


def _failure_reason(output: str) -> str:
    cleaned = _ANSI.sub("", output)
    reason = next(
        (
            line.strip()
            for line in cleaned.splitlines()
            if line.strip() and "____" not in line and not line.startswith(" ")
        ),
        "",
    )
    return reason[:300]


def _hook_command(
    package: str, paths: Sequence[Path], dwell: int, serial: str, log_path: Path
) -> list[str]:
    # -f spawns suspended, loads scripts, then resumes (no --pause). -D and -U
    # cannot be combined. -q -t keeps the session up; -o flushes hook lines.
    # No --kill-on-exit: logcat and JDWP still need the process afterwards.
    cap = max(int(dwell), 0) + HOOK_SLACK_S
    cmd = ["frida", "-f", package]
    for path in paths:
        cmd.extend(["-l", str(path)])
    cmd.extend(["-q", "-t", str(cap), "-o", str(log_path)])
    if serial:
        cmd[1:1] = ["-D", serial]
    else:
        cmd[1:1] = ["-U"]
    return cmd


def _drain(pipe, sink: list[str], lock: threading.Lock) -> None:
    if pipe is None:
        return
    try:
        for line in pipe:
            with lock:
                sink.append(line)
    except OSError:
        return


class HookSession:
    """One observe-only Frida process. `finish` is safe to call twice."""

    def __init__(self, proc: subprocess.Popen[str], log_path: Path) -> None:
        self._proc = proc
        self._log_path = log_path
        self._lock = threading.Lock()
        self._out: list[str] = []
        self._err: list[str] = []
        self._finished = False
        self._hits: list[HookHit] = []
        self._error = ""
        self._threads = [
            threading.Thread(target=_drain, args=(proc.stdout, self._out, self._lock), daemon=True),
            threading.Thread(target=_drain, args=(proc.stderr, self._err, self._lock), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def output_so_far(self) -> str:
        with self._lock:
            return "".join(self._out) + "".join(self._err)

    def finish(self) -> tuple[list[HookHit], str]:
        if self._finished:
            return self._hits, self._error
        self._finished = True
        try:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait(timeout=5)
            for thread in self._threads:
                thread.join(timeout=2)
            try:
                logged = self._log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logged = ""
            console = self.output_so_far()
            hits = parse_hits(logged) or parse_hits(console)
            error = ""
            rc = self._proc.returncode
            if not hits and rc not in (0, None) and (rc or 0) > 0:
                error = _failure_reason(console) or _failure_reason(logged) or f"frida exited {rc}"
            self._hits = hits
            self._error = error
            return hits, error
        finally:
            self._log_path.unlink(missing_ok=True)


def start_hooks(
    package: str,
    scripts: Sequence[str] = ("crypto_hooks.js", "api_map.js"),
    dwell: int = 60,
    serial: str = "",
) -> HookSession:
    """Spawn PACKAGE with SCRIPTS loaded. Caller must `finish` the session.

    Toolchain checks run first. A missing CLI or frida-server raises before
    the package is force-stopped. The returned session is already attached
    (or has already exited with hits) and stays up until `finish`.
    """
    check_toolchain(serial)
    paths: list[Path] = []
    for name in scripts:
        path = SCRIPTS_DIR / name
        if not path.is_file():
            raise FridaUnavailable(f"hook script missing: {path.name}")
        paths.append(path)
    _reset_package(package, serial)
    fd, raw_path = tempfile.mkstemp(prefix="autotest-hooks-", suffix=".log")
    os.close(fd)
    log_path = Path(raw_path)
    cmd = _hook_command(package, paths, dwell, serial, log_path)
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    except FileNotFoundError as exc:
        log_path.unlink(missing_ok=True)
        raise FridaUnavailable("frida CLI vanished") from exc
    session = HookSession(proc, log_path)
    deadline = time.monotonic() + SPAWN_WAIT_S
    pid_since: float | None = None
    while True:
        if proc.poll() is not None:
            hits, err = session.finish()
            if hits:
                return session
            raise FridaUnavailable(err or "frida exited before the app was instrumented")
        if "Resuming main thread" in _ANSI.sub("", session.output_so_far()):
            return session
        if _pidof(package, serial):
            now = time.monotonic()
            if pid_since is None:
                pid_since = now
            if now - pid_since >= PID_READY_S:
                return session
        elif pid_since is not None:
            pid_since = None
        if time.monotonic() >= deadline:
            session.finish()
            raise FridaUnavailable(f"frida did not spawn {package}")
        time.sleep(0.25)


def run_script(package: str, script: str, dwell: int = 60, serial: str = "") -> list[HookHit]:
    """Attach to a running PACKAGE, stream SCRIPT for DWELL seconds, return hits."""
    check_ready(package, serial=serial)
    path = SCRIPTS_DIR / script
    if not path.is_file():
        raise FridaUnavailable(f"hook script missing: {path.name}")
    # -N is the Android package identifier; -n is the app label (e.g. "FAM").
    # -D and -U cannot be combined. -q -t holds the session for dwell — a closed
    # stdin would exit the REPL immediately and drop the dwell window.
    cmd = ["frida", "-N", package, "-l", str(path), "-q", "-t", str(dwell)]
    if serial:
        cmd[1:1] = ["-D", serial]
    else:
        cmd[1:1] = ["-U"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=dwell + 30, check=False)
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        out += e.stderr if isinstance(e.stderr, str) else ""
        return parse_hits(out)
    except FileNotFoundError as e:
        raise FridaUnavailable("frida CLI vanished") from e
    out = (proc.stdout or "") + (proc.stderr or "")
    hits = parse_hits(out)
    if proc.returncode != 0 and not hits:
        raise FridaUnavailable(_failure_reason(out) or f"frida exited {proc.returncode}")
    return hits


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
