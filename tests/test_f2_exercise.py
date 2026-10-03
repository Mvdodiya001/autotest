"""F2: read-only exercise pass with fake adb output."""

from autotest.dynamic import analyzers, exercise
from autotest.models import Verdict


def _scripted(replies: dict[tuple[str, str], str], calls: list):
    def fake(args, serial="", timeout=30):
        calls.append((list(args), serial))
        key = (args[0], args[1] if len(args) > 1 else "")
        if args[:2] == ["am", "start"] and "-d" in args:
            return replies.get(("deeplink", args[args.index("-d") + 1]), "Error: denied")
        if args[:2] == ["am", "start"]:
            return replies.get(("start", args[-1]), "Error: denied")
        if args[:2] == ["am", "broadcast"]:
            return replies.get(("broadcast", args[-1]), "Error: denied")
        if args[0] == "cat":
            return replies.get(("cat", ""), "")
        if args[0] == "uiautomator":
            return replies.get(("uiautomator", ""), "dumped")
        if args[:2] == ["input", "tap"]:
            return "ok"
        if args[:2] == ["input", "keyevent"]:
            return "ok"
        return replies.get(key, "")

    return fake


def test_activities_receivers_and_dwell_zero(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        exercise,
        "adb_shell",
        _scripted(
            {
                ("start", "com.x/com.x.Main"): "Starting: Intent { cmp=com.x/.Main }",
                ("start", "com.x/com.x.Hidden"): "Error: Permission Denial",
                ("broadcast", "com.x/com.x.Ping"): "Broadcast completed: result=0",
            },
            calls,
        ),
    )
    out = exercise.exercise_app(
        {
            "package_name": "com.x",
            "exported_activities": ["com.x.Main", "com.x.Hidden"],
            "exported_receivers": ["com.x.Ping"],
        },
        serial="emulator-5554",
        dwell=0,
    )
    acts = {row["component"]: row["result"] for row in out["exported"]["activities"]}
    assert acts == {"com.x/com.x.Main": "started", "com.x/com.x.Hidden": "refused"}
    rec = out["exported"]["receivers"][0]
    assert rec["result"] == "delivered" and rec["component"] == "com.x/com.x.Ping"
    assert out["ui"] == {"taps": 0, "dwell_s": 0, "clickable": 0, "stopped": "dwell"}
    assert all(serial == "emulator-5554" for _, serial in calls)
    assert not any(
        args[:2] in (["input", "text"], ["input", "tap"], ["pm", "grant"]) for args, _ in calls
    )


def test_deeplink_from_browsable_activities(monkeypatch):
    calls: list = []
    uri = "myapp://example.com/open"
    monkeypatch.setattr(
        exercise,
        "adb_shell",
        _scripted({("deeplink", uri): "Starting: Intent { dat=myapp }"}, calls),
    )
    out = exercise.exercise_app(
        {
            "package_name": "com.x",
            "browsable_activities": {
                "com.x.Deep": {
                    "schemes": ["myapp://"],
                    "hosts": ["example.com"],
                    "ports": [],
                    "paths": ["/open"],
                    "browsable": True,
                },
                "com.x.Skip": {
                    "schemes": ["other://"],
                    "hosts": ["nope"],
                    "actions": ["android.intent.action.MAIN"],
                    "browsable": True,
                },
            },
        },
        dwell=0,
    )
    assert out["deeplinks"] == [
        {
            "activity": "com.x/com.x.Deep",
            "uri": uri,
            "result": "started",
            "evidence": "Starting: Intent { dat=myapp }",
        }
    ]
    opened = [args for args, _ in calls if args[:2] == ["am", "start"]]
    assert len(opened) == 1
    assert opened[0][2:6] == [
        "-a",
        "android.intent.action.VIEW",
        "-c",
        "android.intent.category.BROWSABLE",
    ]
    assert uri in opened[0]


def test_receivers_from_manifest_findings():
    report = {
        "manifest_analysis": [
            {
                "rule": "explicitly_exported",
                "title": "Broadcast Receiver is not Protected.",
                "component": ["Broadcast Receiver", "com.x.FromList"],
            }
        ]
    }
    assert exercise.exported_receiver_names(report) == ["com.x.FromList"]
    nested = {
        "manifest_analysis": {
            "manifest_findings": [
                {
                    "title": "Broadcast Receiver (com.x.FromTitle) is exported [android:exported=true]"
                }
            ]
        }
    }
    assert exercise.exported_receiver_names(nested) == ["com.x.FromTitle"]
    assert exercise.exported_receiver_names({"exported_count": {"exported_receivers": 2}}) == []


def test_ui_taps_clickable_then_back_and_stops_at_cap(monkeypatch):
    xml = '<hierarchy><node clickable="true" bounds="[0,0][10,20]" resource-id="btn"/></hierarchy>'
    calls: list = []
    monkeypatch.setattr(exercise, "adb_shell", _scripted({("cat", ""): xml}, calls))
    ticks = iter([0, 0, 0, 100])

    def clock():
        return next(ticks)

    out = exercise.exercise_app({"package_name": "com.x"}, dwell=30, clock=clock)
    assert out["ui"]["taps"] == 1
    assert out["ui"]["stopped"] == "cap"
    assert out["ui"]["clickable"] == 1
    tapped = [args for args, _ in calls if args[:2] == ["input", "tap"]]
    backed = [args for args, _ in calls if args[:3] == ["input", "keyevent", "4"]]
    assert tapped == [["input", "tap", "5", "10"]]
    assert backed == [["input", "keyevent", "4"]]
    assert not any(args[:2] in (["input", "text"], ["pm", "grant"]) for args, _ in calls)


def test_interaction_analyzer_reads_report_keys():
    dyn = {
        "exported": {
            "activities": [{"component": "com.x/com.x.Main", "result": "started"}],
            "receivers": [
                {"component": "com.x/com.x.Ping", "result": "delivered"},
                {"component": "com.x/com.x.Nope", "result": "refused"},
            ],
        },
        "deeplinks": [
            {"uri": "myapp://example.com/open", "result": "started"},
            {"uri": "myapp://example.com/no", "result": "refused"},
        ],
        "ui": {"taps": 1},
    }
    out = [v for v in analyzers.run_all({}, dyn) if v.verifier == "dynamic:interaction"]
    assert {v.candidate_id for v in out} == {
        "dyn:receiver:com.x_com.x.Ping",
        "dyn:deeplink:myapp___example.com_open",
    }
    assert all(v.verdict == Verdict.VERIFIED for v in out)
    assert [v for v in analyzers.run_all({}, {}) if v.verifier == "dynamic:interaction"] == []
