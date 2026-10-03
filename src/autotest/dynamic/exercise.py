"""Read-only interaction pass: exported components, deep links, bounded UI taps.

No typed input, no runtime-permission grants, no extra installs. Results land on
the dynamic report so analyzers can turn delivered components into verdicts.
"""

from __future__ import annotations

import re
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any

from ..models import Verdict, Verification
from . import analyzers
from . import env as env_mod
from .probe import parse_am_result

_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")
_CLASS_IN_PARENS = re.compile(r"\(([A-Za-z0-9_.$]+)\)")
_UI_DUMP = "/data/local/tmp/autotest-ui.xml"


def adb_shell(args: list[str], serial: str = "", timeout: int = 30) -> str:
    """Run ``adb shell`` and return combined output. Never raises for a refused component."""
    try:
        proc = subprocess.run(
            ["adb", "shell", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env_mod.adb_environ(serial),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"probe error: {type(exc).__name__}"
    return ((proc.stdout or "") + (proc.stderr or "")).strip()


def component_arg(package: str, name: str) -> str:
    """Normalize a manifest class name to the ``package/class`` form ``am`` expects."""
    name = name.strip()
    if "/" in name:
        return name
    if package and name.startswith("."):
        return f"{package}/{name}"
    if package and name:
        return f"{package}/{name}"
    return name


def _manifest_findings(report: dict[str, Any]) -> list[Any]:
    raw = report.get("manifest_analysis")
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        findings = raw.get("manifest_findings")
        if isinstance(findings, list):
            return findings
    return []


def exported_activity_names(report: dict[str, Any]) -> list[str]:
    raw = report.get("exported_activities") or []
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if item]


def exported_receiver_names(report: dict[str, Any]) -> list[str]:
    """Exported receiver class names.

    Prefer a string list on ``exported_receivers``. MobSF's
    ``exported_count.exported_receivers`` is only an integer, so names otherwise
    come from manifest findings that identify a Broadcast Receiver as exported.
    """
    raw = report.get("exported_receivers")
    if isinstance(raw, list) and all(not isinstance(item, dict) for item in raw):
        return [str(item) for item in raw if item]
    names: list[str] = []
    for finding in _manifest_findings(report):
        if not isinstance(finding, dict):
            continue
        rule = str(finding.get("rule") or "")
        title = str(finding.get("title") or "")
        label = str(finding.get("name") or "")
        component = finding.get("component")
        kind = ""
        comp_name = ""
        if isinstance(component, (list, tuple)) and len(component) >= 2:
            kind, comp_name = str(component[0]), str(component[1])
        elif isinstance(component, str):
            comp_name = component
        blob = f"{rule} {title} {label} {kind}".lower()
        if "receiver" not in blob:
            continue
        if "exported" not in blob and not rule.startswith("exported"):
            continue
        if not comp_name:
            match = _CLASS_IN_PARENS.search(title)
            comp_name = match.group(1) if match else ""
        if comp_name:
            names.append(comp_name)
    seen: set[str] = set()
    ordered: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def _data_uris(info: dict[str, Any]) -> list[str]:
    explicit = info.get("data") or info.get("url") or ""
    schemes = [str(item) for item in (info.get("schemes") or []) if item]
    if not schemes:
        return [str(explicit)] if explicit else []
    hosts = [str(item) for item in (info.get("hosts") or [])] or [""]
    paths = [str(item) for item in (info.get("paths") or [])]
    if not paths:
        paths = [str(item) for item in (info.get("path_prefixs") or [])]
    if not paths:
        paths = [str(item) for item in (info.get("path_patterns") or [])]
    if not paths:
        paths = [""]
    ports = [str(item) for item in (info.get("ports") or []) if item]
    uris: list[str] = []
    for scheme in schemes:
        base = scheme if "://" in scheme else f"{scheme}://"
        for host in hosts:
            port = f":{ports[0]}" if host and ports else ""
            for path in paths:
                suffix = path
                if suffix and not suffix.startswith("/"):
                    suffix = "/" + suffix
                uri = f"{base}{host}{port}{suffix}"
                if uri not in uris:
                    uris.append(uri)
    return uris


def deeplink_targets(report: dict[str, Any]) -> list[tuple[str, str]]:
    """(activity, uri) from MobSF ``browsable_activities``.

    That field is populated only for BROWSABLE activities that declare a data
    scheme. When an entry also lists ``actions``, VIEW is required.
    """
    raw = report.get("browsable_activities") or {}
    if not isinstance(raw, dict):
        return []
    targets: list[tuple[str, str]] = []
    for activity, info in raw.items():
        if not isinstance(info, dict) or info.get("browsable") is False:
            continue
        actions = info.get("actions")
        if isinstance(actions, list) and actions and "android.intent.action.VIEW" not in actions:
            continue
        for uri in _data_uris(info):
            targets.append((str(activity), uri))
    return targets


def clickable_centers(xml_text: str) -> list[tuple[int, int, str]]:
    """Centers of ``clickable="true"`` nodes. Empty when the dump is not XML."""
    start = xml_text.find("<hierarchy")
    if start == -1:
        start = xml_text.find("<node")
    if start == -1:
        return []
    try:
        root = ET.fromstring(xml_text[start:])
    except ET.ParseError:
        return []
    found: list[tuple[int, int, str]] = []
    for node in root.iter("node"):
        if node.attrib.get("clickable") != "true":
            continue
        match = _BOUNDS.fullmatch(node.attrib.get("bounds", ""))
        if not match:
            continue
        x1, y1, x2, y2 = (int(value) for value in match.groups())
        if x2 <= x1 or y2 <= y1:
            continue
        key = f"{node.attrib.get('bounds')}|{node.attrib.get('resource-id', '')}"
        found.append(((x1 + x2) // 2, (y1 + y2) // 2, key))
    return found


def _ui_pass(serial: str, dwell: int, clock) -> dict[str, Any]:
    ui: dict[str, Any] = {"taps": 0, "dwell_s": dwell, "clickable": 0, "stopped": "dwell"}
    if dwell <= 0:
        return ui
    deadline = clock() + dwell
    seen: set[str] = set()
    while clock() < deadline:
        dump_out = adb_shell(["uiautomator", "dump", _UI_DUMP], serial=serial, timeout=20)
        xml = adb_shell(["cat", _UI_DUMP], serial=serial, timeout=20)
        if "<hierarchy" not in xml and "<node" not in xml:
            xml = dump_out
        nodes = clickable_centers(xml)
        ui["clickable"] = len(nodes)
        fresh = [node for node in nodes if node[2] not in seen]
        if not fresh:
            ui["stopped"] = "idle"
            break
        if clock() >= deadline:
            ui["stopped"] = "cap"
            break
        x, y, key = fresh[0]
        seen.add(key)
        adb_shell(["input", "tap", str(x), str(y)], serial=serial)
        adb_shell(["input", "keyevent", "4"], serial=serial)
        ui["taps"] += 1
    else:
        ui["stopped"] = "cap"
    return ui


def exercise_app(
    static_report: dict[str, Any],
    serial: str = "",
    dwell: int = 60,
    clock=None,
) -> dict[str, Any]:
    """Start exported activities, broadcast to exported receivers, open deep links, tap."""
    clock = clock or time.monotonic
    package = str(static_report.get("package_name") or "")
    activities: list[dict[str, str]] = []
    for name in exported_activity_names(static_report):
        component = component_arg(package, name)
        ok, evidence = parse_am_result(adb_shell(["am", "start", "-n", component], serial=serial))
        activities.append(
            {"component": component, "result": "started" if ok else "refused", "evidence": evidence}
        )
    receivers: list[dict[str, str]] = []
    for name in exported_receiver_names(static_report):
        component = component_arg(package, name)
        ok, evidence = parse_am_result(
            adb_shell(["am", "broadcast", "-n", component], serial=serial)
        )
        receivers.append(
            {
                "component": component,
                "result": "delivered" if ok else "refused",
                "evidence": evidence,
            }
        )
    deeplinks: list[dict[str, str]] = []
    for activity, uri in deeplink_targets(static_report):
        component = component_arg(package, activity)
        ok, evidence = parse_am_result(
            adb_shell(
                [
                    "am",
                    "start",
                    "-a",
                    "android.intent.action.VIEW",
                    "-c",
                    "android.intent.category.BROWSABLE",
                    "-d",
                    uri,
                    "-n",
                    component,
                ],
                serial=serial,
            )
        )
        deeplinks.append(
            {
                "activity": component,
                "uri": uri,
                "result": "started" if ok else "refused",
                "evidence": evidence,
            }
        )
    return {
        "exported": {"activities": activities, "receivers": receivers},
        "deeplinks": deeplinks,
        "ui": _ui_pass(serial, dwell, clock),
    }


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.]", "_", value)[-60:]


class InteractionSurface:
    """Turn delivered receivers and opened deep links into dyn: verdicts."""

    name = "dynamic:interaction"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        out: list[Verification] = []
        exported = dynamic_report.get("exported") or {}
        receivers = exported.get("receivers", []) if isinstance(exported, dict) else []
        for row in receivers:
            if not isinstance(row, dict) or row.get("result") != "delivered":
                continue
            component = str(row.get("component", ""))
            out.append(
                Verification(
                    candidate_id=f"dyn:receiver:{_slug(component)}",
                    verifier=self.name,
                    verdict=Verdict.VERIFIED,
                    evidence=f"explicit broadcast delivered: {component}",
                )
            )
        for row in dynamic_report.get("deeplinks") or []:
            if not isinstance(row, dict) or row.get("result") != "started":
                continue
            uri = str(row.get("uri", ""))
            out.append(
                Verification(
                    candidate_id=f"dyn:deeplink:{_slug(uri)}",
                    verifier=self.name,
                    verdict=Verdict.VERIFIED,
                    evidence=f"browsable view opened: {uri}",
                )
            )
        return out


analyzers.register(InteractionSurface())
