"""Dynamic-analysis environment (M4.0): emulator bring-up via mobsf-lab scripts."""

from __future__ import annotations

import os
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


def adb_environ(serial: str = "") -> dict[str, str]:
    """Process environment, with ANDROID_SERIAL pinned when ``serial`` is set.

    Pinning avoids MobSF's duplicate TCP device entries on later adb calls.
    """
    adb_env = dict(os.environ)
    if serial:
        adb_env["ANDROID_SERIAL"] = serial
    return adb_env


def _adb_proc(*args: str, serial: str = "", timeout: int = 60) -> subprocess.CompletedProcess[str]:
    if not shutil.which("adb"):
        raise DynamicEnvError("adb not on PATH (source ~/mobsf-lab/env.sh?)")
    try:
        return subprocess.run(
            ["adb", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=adb_environ(serial),
        )
    except FileNotFoundError as e:
        raise DynamicEnvError("adb not on PATH (source ~/mobsf-lab/env.sh?)") from e
    except subprocess.TimeoutExpired as e:
        raise DynamicEnvError(f"adb timed out: {' '.join(args)}") from e


def _adb(*args: str, serial: str = "", timeout: int = 60) -> str:
    proc = _adb_proc(*args, serial=serial, timeout=timeout)
    if proc.returncode != 0:
        raise DynamicEnvError(f"adb {' '.join(args)} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def ensure_emulator(lab_dir: str | Path | None = None) -> EmulatorInfo:
    """Boot the MobSF emulator via start-emulator.sh and verify adb/root state.

    Returns the emulator serial; callers pass it into later adb calls.
    """
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
    _adb("root", serial=emu)
    _adb("wait-for-device", serial=emu)
    touch = _adb_proc(
        "shell",
        "touch /system/.autotest_probe && rm /system/.autotest_probe",
        serial=emu,
    )
    return EmulatorInfo(serial=emu, rooted=True, system_writable=touch.returncode == 0)


def install_apk(apk: str | Path, serial: str = "") -> str:
    """Install (or reinstall) APK on the attached emulator. Returns package name."""
    out = _adb("install", "-r", str(apk), serial=serial, timeout=180)
    if "Success" not in out:
        raise DynamicEnvError(f"adb install failed: {out.strip()[:300]}")
    return out.strip().splitlines()[-1]
