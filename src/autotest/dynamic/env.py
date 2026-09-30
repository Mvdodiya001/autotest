"""Dynamic-analysis environment (M4.0): emulator bring-up via mobsf-lab scripts."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class DynamicEnvError(RuntimeError):
    pass


@dataclass
class EmulatorInfo:
    serial: str  # e.g. emulator-5554
    rooted: bool
    system_writable: bool


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as e:
        raise DynamicEnvError(f"missing tool: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise DynamicEnvError(f"timed out: {' '.join(cmd)}") from e


_SERIAL: str = ""


def selected_serial() -> str:
    return _SERIAL


def _adb(*args: str, timeout: int = 60) -> str:
    import os

    if not shutil.which("adb"):
        raise DynamicEnvError("adb not on PATH (source ~/mobsf-lab/env.sh?)")
    adb_env = dict(os.environ)
    if _SERIAL:
        adb_env["ANDROID_SERIAL"] = _SERIAL
    try:
        proc = subprocess.run(
            ["adb", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=adb_env,
        )
    except FileNotFoundError as e:
        raise DynamicEnvError("adb not on PATH (source ~/mobsf-lab/env.sh?)") from e
    except subprocess.TimeoutExpired as e:
        raise DynamicEnvError(f"adb timed out: {' '.join(args)}") from e
    if proc.returncode != 0:
        raise DynamicEnvError(f"adb {' '.join(args)} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def ensure_emulator(lab_dir: str | Path | None = None) -> EmulatorInfo:
    """Boot the MobSF emulator via start-emulator.sh and verify adb/root state."""
    script = Path(lab_dir or Path.home() / "mobsf-lab") / "start-emulator.sh"
    if not script.is_file():
        raise DynamicEnvError(f"mobsf-lab script missing: {script}")
    proc = _run(["bash", str(script)], timeout=600)
    if proc.returncode != 0:
        raise DynamicEnvError(f"start-emulator.sh failed: {proc.stderr[-2000:]}")
    serials = [ln.split()[0] for ln in _adb("devices").splitlines()[1:] if ln.strip()]
    emu = next((s for s in serials if s.startswith("emulator-")), "")
    if not emu:
        raise DynamicEnvError(f"no emulator serial in adb devices: {serials}")
    global _SERIAL
    _SERIAL = emu  # pin all later adb calls (MobSF leaves duplicate TCP entries)
    _adb("root")
    _adb("wait-for-device")
    touch = _run(["adb", "shell", "touch /system/.autotest_probe && rm /system/.autotest_probe"])
    return EmulatorInfo(serial=emu, rooted=True, system_writable=touch.returncode == 0)


def install_apk(apk: str | Path) -> str:
    """Install (or reinstall) APK on the attached emulator. Returns package name."""
    out = _adb("install", "-r", str(apk), timeout=180)
    if "Success" not in out:
        raise DynamicEnvError(f"adb install failed: {out.strip()[:300]}")
    return out.strip().splitlines()[-1]
