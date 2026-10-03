# Implementation plan (F1–F5)

Build order is F1 → F2 → F3 → F4 → F5. Each feature is linted and unit-tested
before the next. Live checks use `fam-ctf.apk` when `AUTOTEST_MOBSF_API_KEY` is
set and MobSF answers; otherwise they are skipped. Output stays under a temp
dir.

## F1 — One command

`autotest run <apk>` calls scan → verify-only → dyn-verify → report-only and
writes the same workdir files as scan (`findings.json`, `mobsf_report.json`,
HTML). `--skip-dynamic` stops after static verify + report. `--main-activity`
is passed into the dynamic stage. A missing APK or a failed MobSF scan stops
the run. A missing emulator becomes an inconclusive dynamic verdict and the
HTML report is still written.

Files: `src/autotest/pipeline.py`, `src/autotest/cli.py`, `tests/test_f1_run.py`.

Test: monkeypatched scanner and dynamic stage (no MobSF). Live: `autotest run`
on `fam-ctf.apk` when MobSF is up.

## F2 — Exercise the app

Read-only interaction in `src/autotest/dynamic/exercise.py`, invoked from
`run_dynamic` before logcat and probes, on the pinned serial.

MobSF report fields actually used:

- Activities: `exported_activities` (list of class names). `am start -n`.
- Receivers: a string list `exported_receivers` when present. Otherwise
  `manifest_analysis` findings (list, or `manifest_findings` under a dict)
  whose component/title is a Broadcast Receiver and whose rule/title says
  exported. `exported_count.exported_receivers` is only an integer, so it is
  not used as the name list. Explicit `am broadcast -n`. Record
  `started`/`refused` and `delivered`/`refused`.
- Deep links: `browsable_activities`. MobSF fills this only when the activity
  has category `BROWSABLE` and at least one `<data>` scheme (schemes are stored
  already suffixed with `://`, plus `hosts`, `ports`, `paths`,
  `path_prefixs`, `path_patterns`). There is no raw intent-filter list. If an
  entry also has `actions`, `android.intent.action.VIEW` is required; otherwise
  the MobSF browsable set is treated as the VIEW+BROWSABLE set. URIs are opened
  with `am start -a VIEW -c BROWSABLE -d`.

UI: `uiautomator dump`, tap every `clickable="true"` center on that screen
(at most 8; password fields skipped), then BACK and dump again. Stop when
the next layout matches or `dynamic_dwell` runs out (default 60,
`--dwell` / `AUTOTEST_DYNAMIC_DWELL`). Dwell 0 performs no taps.
`ui.tapped` stores a resource id or bounds, not node text. No typed input,
no `pm grant`, no extra installs.

Results are stored on the dynamic report as `exported`, `deeplinks`, and `ui`.
Activity launches still feed `autotest.probes.exported` so the existing
exported-launch analyzer keeps working. Delivered receivers and opened deep
links get `dyn:` verdicts.

Files: `dynamic/exercise.py`, `dynamic/run.py`, `dynamic/__init__.py`,
`dynamic/probe.py`, `config.py`, `cli.py`, `pipeline.py`,
`tests/test_f2_exercise.py`, `tests/test_m4_session.py`.

Test: fake adb output. Live: `dyn-verify` on fam-ctf when the emulator is up.

## F3 — Frida inside dyn-verify

`run_dynamic` cold-starts the package with `crypto_hooks.js` and `api_map.js`
already loaded and keeps them attached through the exercise. Hits stay on
`autotest.hooks` and the existing crypto / permission analyzers emit `dyn:`
ids. `FridaUnavailable` adds inconclusive verdicts for those two checks only.
`--skip-frida` skips hook collection and does not add those verdicts. The dev
group pins `frida==16.7.19` and `frida-tools==13.7.1`. An offline second app
profile (`org.example.catalog`) covers exercise and hook order.

Files: `dynamic/run.py`, `cli.py`, `pipeline.py`, `tests/test_f3_frida.py`,
`docs/frida-live.md`.

Test: fixture JSONL through `run_dynamic`; missing-Frida still returns logcat,
exported, cleartext, and debuggable verdicts. Live: same `dyn-verify` as F2.

## F4 — Prove unverified candidates

New `@verifier` types, mocked HTTP in the style of `tests/test_m2_verifiers.py`.
Previews only; full values stay in memory and are dropped before
`findings.json`, same rule as AWS `paired_secret`.

- F4.1 `HardcodedSecret`: noise / label / localization → refuted. A value that
  is itself a Firebase/Google key, AWS access key id, JWT, Slack, GitHub,
  Stripe, or PEM key is not probed again (unverified, dedicated verifier owns
  it). Anything else → inconclusive, no network call.
- F4.2 `GoogleApiKey` when an `AIza` key is outside Firebase context
  (`firebase_urls`, or the same key already seen there, or the word `firebase`
  in that secret). One read-only GET to the Geocoding API. Accepted →
  verified. Invalid or restricted → refuted. Network error → inconclusive.
  The key is not written into evidence.
- F4.3 `FirebaseStorageUrl` and `FirestoreUrl` extractors, plus open-read GETs
  next to the RTDB probe (`maxResults=1` / `pageSize=1`). HTTP 200 → verified.
  401/403 or permission denied → refuted. Network error → inconclusive.
- F4.4 Extractors: `SlackToken`, `GitHubToken`, `StripeSecretKey`,
  `PemPrivateKey`. PEM preview is the header name and length only.
- F4.5 One read-only GET each: Slack `auth.test`, GitHub `/user`, Stripe
  `/v1/account`. 401/403 (and Slack `ok: false`) → refuted. 200 → verified.
  Network error → inconclusive. Response bodies are not stored. PEM is a
  structural parse only: recognizable header → inconclusive, evidence names
  RSA, EC, or generic PKCS and says there is no live acceptor; garbage →
  refuted. The key is never used to sign or authenticate. A hardcoded string
  that matches Slack, GitHub, Stripe, Google, Firebase, an AWS pair, or a
  JWT is stored as that type. An unrecognized string stays inconclusive
  (`no live probe for this shape`).
- F4.6 Replay hints for each new type. HTML test rejects a rendered full secret.

Files: `extract/mobsf_extract.py`, `verify/firebase.py`, `verify/secrets.py`,
`verify/__init__.py`, `report.py`, `tests/test_f4_verifiers.py`.

Test: mocked HTTP. Live: `verify-only` on a fam-ctf scan when MobSF is up.

## F5 — Report as a retest gate

- Stable id = SHA-256 of `secret_type`, redacted preview, and provenance file
  (first 20 hex chars), stored on `Candidate.stable_id` (default `""`, schema
  version stays 1).
- Severity: verified=high, inconclusive=medium, refuted and unverified=info.
  HTML scoreboard shows those counts.
- `autotest diff previous.json current.json` prints added, removed, and
  changed verdicts. Exit 0 with no new verified row. Exit 1 when one appears.
- `report-only --format sarif` writes SARIF 2.1.0 instead of HTML. `--format
  both` writes SARIF beside HTML. HTML stays the default. SARIF carries the
  stable id and severity, and no full secret.
- README snippet for an app repo CI gate. This repo's lint workflow stays.

Files: `models.py`, `pipeline.py`, `report.py`, `dynamic/merge.py`, `cli.py`,
`templates/report.html`, `tests/test_f5_gate.py`, `tests/fixtures/diff_*.json`,
`README.md`, `docs/development-cycle.md`.
