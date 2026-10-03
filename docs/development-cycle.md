# autotest — development cycle & architecture

How this tool was built, in which order, how each module works, and the
principles behind the design. Start here before changing anything.

## 1. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python ≥ 3.12 | lab standard, MobSF is Python |
| Packaging | `uv` + `uv_build` | fast, lockfile (`uv.lock`), dev groups |
| CLI | `click` | groups + subcommands (`scan`, `verify-only`, `report-only`, `dyn-verify`, `run`, `diff`) |
| Config / models | `pydantic` + `pydantic-settings` | validated settings (`AUTOTEST_*` env or flags), `findings.json` schema |
| HTTP | `requests` | MobSF REST, Firebase/AWS/Google probes |
| Report | `jinja2` | single-file HTML dashboard, no external assets |
| Tests | `pytest` (+ `responses` for mocked HTTP) | unit + live-gated golden tests |
| Lint/format | `ruff` | `check` + `format`, line-length 100, py312 |
| Static engine | MobSF (Docker `mobsf` container, REST-first) | proven analyzer; vendored tree kept for a future local backend |
| Dynamic lab | Android emulator (API 30, `-writable-system`) + `adb` + Frida | `~/mobsf-lab` owns boot (`AUTOTEST_LAB_DIR` or `--lab-dir`); not vendored; autotest only drives it |

## 2. Architecture

```
APK ──▶ ingest ──▶ Scanner ──▶ Extractor(s) ──▶ candidates ──▶ Verifier(s) ──▶ report
         (pipeline)  (M1)        (M1)            findings.json    (M2)          (M3, Jinja2)
                                                          │
APK ──▶ dynamic env ──▶ MobSF session ──▶ probes/hooks ──▶ Analyzers ──▶ merge ──┘
         (mobsf-lab)     (M4.0)            (M4.1/M4.2)      (M4.1/M4.2)   (M4.3)
```

Data contract between every stage: `findings.json`
(`ScanResult`: `candidates[]` + `verifications[]`, verdict ∈
`verified | refuted | inconclusive | unverified`).
Full secret values are **never persisted** — findings store redacted previews;
verifiers re-extract values from the sibling `mobsf_report.json` by stable
`cand-NNN` id.

Module map (`src/autotest/`):

| Module | Responsibility | SOLID role |
|---|---|---|
| `config.py` | `Settings` (env/flags, timeouts, `lab_dir`) | — |
| `models.py` | `ScanResult/Candidate/Verification/Verdict` | shared kernel |
| `workdir.py` | per-scan layout (`findings.json`, `mobsf_report.json`) | — |
| `mobsf/transport.py` | auth POST + timeout budgets | S: transport only |
| `mobsf/static_client.py` | upload/scan/report_json | S: static only |
| `mobsf/dynamic_client.py` | start/stop/report_json | S: dynamic only |
| `mobsf_client.py` | legacy combined facade (kept for compat) | — |
| `scanners.py` | `Scanner` ABC, `ApiScanner`, `NullScanner`, `for_settings()` | D/O: pipeline depends on abstraction |
| `extract/` | `Extractor` ABC + registry; `MobSFExtractor` (keys, URLs, Firebase, hardcoded refs, noise filter) | O: new sources plug in |
| `verify/` | `Verifier` ABC + `FunctionVerifier` adapter + type registry | O/L: functions serve as Verifiers |
| `verify/firebase.py` | anon-auth key proof, RTDB open-read probe | — |
| `verify/misc.py` | JWT inspection, AWS STS, URL reachability | — |
| `dynamic/env.py` | emulator bring-up; serial on `EmulatorInfo` (no process-global); `ANDROID_SERIAL` on later adb; install | — |
| `dynamic/session.py` | setup → collect → teardown; keeps the emulator serial | — |
| `dynamic/probe.py` | `am start` exported launch, JDWP map | — |
| `dynamic/collect.py` | adb logcat pull + MobSF report merge | — |
| `dynamic/frida_run.py` | hook runner (`-D` and `ANDROID_SERIAL` when given a serial), degrades to `FridaUnavailable` | — |
| `dynamic/frida/*.js` | read-only `crypto_hooks.js`, `api_map.js` (`AUTOTEST_HOOK` JSONL) | — |
| `dynamic/core.py` | logcat-leak, exported-launch, cleartext, debuggable | — |
| `dynamic/core2.py` | crypto-hooks (ECB/IV-reuse/setSeed/weak-hash), perm-api-map | — |
| `dynamic/merge.py` | orphan `dyn:*` verdicts → synthesized `Dynamic:*` candidates | — |
| `dynamic/exercise.py` | read-only activity, broadcast, deep-link, and UI pass | — |
| `dynamic/run.py` | `run_dynamic()` orchestration, including Frida hook collection | — |
| `report.py` | `ReportRenderer` (template + hint registry) and SARIF 2.1.0 | O: new hint types register |
| `pipeline.py` | `run_scan`, `run_verify_only`, `run_report_only`, `run_pipeline`, `diff_findings` | thin wiring over ABCs |
| `cli.py` | `scan`, `verify-only`, `report-only`, `dyn-verify`, `run`, `diff` | — |

Design rules: verifiers/analyzers/hooks are **read-only** (no writes to targets);
evidence never contains secret material; live tests gate on
`AUTOTEST_MOBSF_API_KEY` and skip cleanly without it.

## 3. Development cycle (build order)

### M0 — skeleton
CLI skeleton (`scan`, `verify-only`, `report-only`), `Settings`, `Workdir`,
`findings.json` schema (`ScanResult`). `scan` hashed the APK and wrote empty
findings. Tests: CLI round-trips on fake APKs.

### M1 — static extraction
`MobSFClient` (upload/scan/report_json) → `extract_candidates()`:
`FirebaseApiKey` (incl. `key=` inside Firebase URLs), `RtdbUrl`,
`PrivateHttpUrl`/`GenericUrl` (private-IP split), `HardcodedSecret`,
`HardcodedRef` (non-library `android_hardcoded` files). `AwsAccessKey` is
emitted when an `AKIA` access key id and a secret access key share one MobSF
secrets bucket (one file, or the file-less secrets list) or one code-analysis
finding; the secret stays on the in-memory candidate as `paired_secret` and is
not written to `findings.json` (the full secret remains in the sibling
`mobsf_report.json`). Pairing is appearance order inside that one bucket, so a
decoy 40-character mixed-case token before the real secret can be zipped to the
access key (STS then refutes); hex digests are ignored. Noise filter for
`*.credentials.*` localization strings (found live: 38 junk entries).
Golden test: `fam-ctf.apk` → 7 candidates; DIVA regression test added after a
**real timeout bug** (fresh-APK static analysis > 20 s) forced a separate
`mobsf_scan_timeout` (600 s) budget. DIVA yields 2 candidates.

### M2 — live verifiers
`verify/` registry + `Ctx` (values re-extracted from `mobsf_report.json`).
`verify_firebase_key` (anonymous `signUp` proof + auth'd RTDB probe),
`verify_rtdb_open` (unauth shallow read), `verify_jwt` (alg/claims inspection),
`verify_aws_key` (SigV4 `GetCallerIdentity`), `verify_url_reachable`.
`verify-only` loads an AWS `paired_secret` into `ctx.values["<id>:secret"]` for
that read-only STS call; without a pair the AWS verdict stays INCONCLUSIVE.
`verify-only` is idempotent. Mocked suite via `responses`; live proof on
`fam-ctf.apk`: key VERIFIED, RTDB REFUTED-unauth, `172.16` INCONCLUSIVE.

### M3 — dashboard
Jinja2 single-file report: scoreboard, verified cards with per-type replay
commands, collapsed refuted/unverified, appendix. Test-locked: full secrets
never render (previews only).

### M4.0 — dynamic plumbing
`dynamic/env.py` (mobsf-lab bring-up from `Settings.lab_dir`, adb/root/writable
checks), `dynamic/session.py` (install → start/collect/stop, serial kept on the
session), `dynamic/analyzers.py` registry. Endpoint contracts verified against
the vendored MobSF tree (`dynamic/*` need POST `hash`).

### M4.1 — core analyzers
`extract_with_ids()` shared id scheme; `dynamic/probe.py` (`am start` parse,
JDWP map); `dynamic/collect.py` (adb logcat pull + merge); analyzers:
logcat-leak (extracted values + secret-shaped tokens incl. 32+-hex),
exported-launch, cleartext, debuggable. Two live fixes: the emulator serial
comes back on `EmulatorInfo` and is passed explicitly into install, logcat,
probes, and launch (`ANDROID_SERIAL`) because MobSF leaves duplicate TCP
entries — `adb devices` stays unpinned, and there is no process-global serial —
and hex-token shapes (the real request signature is 64-hex). Frida takes the
same serial (`ANDROID_SERIAL` and `-D`) on `run_script`. Live: leak + launch
VERIFIED.

### M4.2 — Frida hooks
Read-only `crypto_hooks.js` / `api_map.js` (`node --check` in suite),
`frida_run.py` (dwell-bounded, partial capture, `FridaUnavailable`
degradation), `dynamic:crypto-hooks` (ECB/IV-reuse/setSeed/weak-hash) and
`dynamic:perm-api-map` (undeclared sensitive-API use) analyzers.

### M4.3 — merge + command
`dynamic/merge.py` (orphan synthesis, idempotent), `dyn-verify` CLI, replay
hints for `Dynamic:*` families, live Frida runbook (`docs/frida-live.md`).
Live `dyn-verify` on fam: 7 static + 2 dynamic verdicts, 9 rendered rows.

### One command, exercise, hooks, verifiers, retest gate
`autotest run` chains scan → verify-only → dyn-verify → report. `--skip-dynamic`
stops after the static report. A missing emulator is an inconclusive dynamic
verdict and the HTML report is still written. Before logcat, `exercise.py`
starts `exported_activities`, broadcasts to exported receivers (string list
`exported_receivers`, else manifest findings), and opens `browsable_activities`
deep links. The UI pass then taps every clickable node on the current dump,
at most 8, skips password fields, presses Back, and dumps again. It stops
when that layout matches the previous dump or `dynamic_dwell` (`--dwell`,
default 60s) runs out. Dwell 0 performs no taps. `ui.tapped` records a
resource id, or bounds when there is no id. There is no typed input.
Hooks cold-start with the app and stay attached through that pass
(`crypto_hooks.js` and `api_map.js` on the pinned serial); missing Frida is
inconclusive for those two checks only (`--skip-frida` skips them). Host
tools are pinned in the dev group: `frida==16.7.19`, `frida-tools==13.7.1`.

New read-only verifiers: `HardcodedSecret` (no network), `GoogleApiKey` (one
Geocoding GET), `FirebaseStorageUrl`, `FirestoreUrl`, `SlackToken`,
`GitHubToken`, `StripeSecretKey`, and structural `PemPrivateKey`. A hardcoded
string that matches one of those shapes is stored as that type. An
unrecognized string stays inconclusive (`no live probe for this shape`).
PEM evidence names RSA, EC, or generic PKCS and says there is no live
acceptor. `merge_dynamic` keeps a static row when a different dynamic
verifier hits the same candidate id; the same verifier re-run replaces its
own row. Each candidate stores `stable_id`. Severity is high / medium / info.
`autotest diff` exits 1 when a new verified row appears.
`report-only --format sarif` writes SARIF 2.1.0. An offline second app
profile (`org.example.catalog` in `tests/test_f3_frida.py`) covers exercise
and hook order without another APK.

### Refactor (SOLID pass)
Split the god-client (`transport`/`static_client`/`dynamic_client`, facade kept
for compat); `Scanner` ABC + `for_settings()` factory (pipeline no longer
branches on backend strings); `Extractor` ABC + registry (`run_extractors`
keeps id order stable); `Verifier` ABC + `FunctionVerifier` adapter (existing
functions untouched, LSP-safe); `ReportRenderer` with hint registry (longest-
prefix match — fixed a real dispatch bug where `Dynamic:` shadowed longer keys).
Full suite green before and after (36/36 with key).

## 4. Test matrix (run it all)

```bash
uv run ruff check src tests && uv run ruff format --check src tests
uv run pytest -q                                            # offline: mocks + skips
AUTOTEST_MOBSF_API_KEY=<key> uv run pytest -q               # full: golden + DIVA live
AUTOTEST_MOBSF_API_KEY=<key> uv run autotest scan <apk> --out-dir ./out
uv run autotest verify-only ./out/findings.json
uv run autotest dyn-verify ./out/findings.json --main-activity <pkg/.Main>
uv run autotest report-only ./out/findings.json
uv run autotest run <apk> --out-dir ./out
uv run autotest diff previous.json current.json
```

CI (`.github/workflows/ci.yml`) runs lint + the offline `pytest` line on every
push and pull request (uv, Python 3.12). Live MobSF tests skip without
`AUTOTEST_MOBSF_API_KEY`.

## 5. Extending (cookbook)

* New secret source → subclass `Extractor`, append to `EXTRACTORS` (ids stay stable).
* New live check → `@verifier("NewType")` function, or subclass `Verifier` for
  stateful checks; add mocked test in `tests/test_m2_verifiers.py` style.
* New dynamic check → `Analyzer` in `dynamic/core*.py` (auto-registered on import
  via `dynamic/__init__.py`); orphan ids must start with `dyn:` for merge.
* New replay hint → `ReportRenderer.register_hint("TypeOrPrefix:", fn)`.
