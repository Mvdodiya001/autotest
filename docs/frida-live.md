# Live Frida runbook (autotest dynamic hooks)

`frida_run.py` degrades to INCONCLUSIVE when the toolchain is absent. For a live
run you need all three layers. Everything below is read-only against the target.

## 1. Host tools

```bash
pip install frida-tools          # provides the `frida` CLI
frida --version
```

## 2. frida-server on the emulator

```bash
# Lab checkout defaults to ~/mobsf-lab (AUTOTEST_LAB_DIR or --lab-dir). Not vendored.
source "${AUTOTEST_LAB_DIR:-$HOME/mobsf-lab}/env.sh"
# adb devices stays unpinned. autotest then uses the emulator-* serial from
# ensure_emulator (EmulatorInfo, kept on DynamicSession) and sets ANDROID_SERIAL
# on later adb calls. Pin the same serial here when more than one device is listed:
export ANDROID_SERIAL=emulator-5554
# match the server build to the device arch (x86_64 emulator here) and to your
# frida-tools major version, e.g. frida-server-16.x-android-x86_64(.xz)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"   # adb root first (see runbook)
adb shell ps -A | grep frida-server
```

(MobSF's dynamic flow installs its own server; either one satisfies `check_ready`.)

## 3. Target running + hook scripts

```bash
adb shell am start -n <package>/.MainActivity
ls src/autotest/dynamic/frida/   # crypto_hooks.js, api_map.js (node --check in suite)
```

## 4. Run through autotest

`dyn-verify` (and `run`, unless `--skip-dynamic`) collects hooks after the
read-only exercise pass. Both scripts run on the emulator serial from
`ensure_emulator`, for the same `--dwell` as the UI pass (default 60s):

```bash
uv run autotest dyn-verify ./out/findings.json --main-activity com.ctf.fam/.MainActivity
uv run autotest dyn-verify ./out/findings.json --skip-frida   # logcat and probes only
```

`--skip-frida` skips hook collection only. Logcat, exported, cleartext, and
debuggable still run. If `frida` or `frida-server` is missing, those two hook
checks are INCONCLUSIVE (`dyn:crypto:unavailable`, `dyn:permapi:unavailable`)
and the other dynamic checks are unchanged.

The same runner is available directly. The serial is the one `ensure_emulator`
returned. There is no process-global serial. With it set, adb checks use
`ANDROID_SERIAL` and frida is invoked as `-D <serial>`.

```python
from autotest.dynamic import frida_run
hits = frida_run.run_script(
    "com.ctf.fam", "crypto_hooks.js", dwell=60, serial="emulator-5554"
)
# -> [HookHit(hook='cipher.init', detail={...}), ...]
```

Dwell expiry surfaces as partial output (TimeoutExpired is parsed, not raised).
`run_dynamic` stores hits on `autotest.hooks` and feeds them to the analyzers.

## 5. Interpreting results

* `dynamic:crypto-hooks` VERIFIED (ECB / IV-reuse / setSeed / MD5-SHA1) → concrete
  finding, replay with the same script while exercising the crypto feature.
* `dynamic:perm-api-map` VERIFIED `dyn:permapi:undeclared` → sensitive API without
  manifest permission; INCONCLUSIVE `observed` → review aid, not a finding.

## Safety rules

* Hook scripts only **observe** (no retval tampering, no method replacement).
* `dwell` bounds every run; output is parsed as JSONL, non-hook lines ignored.
* Findings reference truncated prefixes only — full key material never lands in
  `findings.json` or the HTML report.
