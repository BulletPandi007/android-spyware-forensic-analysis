# Sandbox Dynamic Analysis — Results Summary

**Platform:** ANY.RUN (Interactive Android Sandbox)
**Environment:** Android 14, ARM-based
**Duration per run:** 60 seconds (free tier limit)
**Date range:** March – April 2026

---

## Submission Log

| Sample | Task ID | Date | Verdict | Report |
|--------|---------|------|---------|--------|
| spynote.apk | 9505dc11-c46f-4830-a8dc-f81c3292841f | 2026-03-31 | Malicious | [Link](https://app.any.run/tasks/9505dc11-c46f-4830-a8dc-f81c3292841f) |
| antidot.apk | 573db37c-c219-4b21-b0f1-7ed72efc3b8a | 2026-04-07 | Malicious | [Link](https://app.any.run/tasks/573db37c-c219-4b21-b0f1-7ed72efc3b8a) |
| brata.apk | — | 2026-04-01 | Malicious | — |
| clayrat.apk | — | 2026-04-01 | Malicious | — |
| spymax.apk | — | 2026-04-01 | Malicious | — |
| truthspy.apk | — | 2026-04-01 | Suspicious | — |
| selfspy.apk | N/A | N/A | Not submitted | APK exceeds 16MB upload limit |

---

## Key Findings by Sample

### Antidot
- **Verdict:** Malicious activity
- **Package:** com.wetpacd1d.psyd1d
- **C2:** ping.ynrkone.top + aliyuncs.com (147.139.146.211)
- **Network:** 18 HTTP requests, 12 TCP connections
- **Files dropped:** 39 (21 suspicious + 18 text)
- **Threats:** 12 SURICATA alerts — custom C2 protocol
- **Notable:** Screen state check, device admin check, clipboard access, installed app scan confirmed at runtime

### SpyNote
- **Verdict:** Malicious activity
- **Package:** com.appd.mercantil (disguised as merchant app)
- **C2:** None observed (dormant)
- **Network:** 4 HTTP requests, 8 TCP connections (Google only)
- **Files dropped:** 1 binary cache file
- **Evasion:** C2-dependent dormancy confirmed — no malicious behavior in 60s window

### ClayRAT
- **Verdict:** Malicious activity
- **C2:** losthed.clay.rest (64.188.83.172) — Python Werkzeug
- **Network:** 90 HTTP requests, 30 TCP connections
- **Files dropped:** 11 (VPN configs, WebSocket files, state files)
- **Threats:** Network Trojan detected — Python Werkzeug HTTP check-in
- **Notable:** App hides from display, wake locks, broadcast receivers registered

### BraTA
- **Verdict:** Malicious activity
- **Package:** sh.abc.shabd
- **C2:** Firebase (blending with legitimate traffic)
- **Network:** 7 HTTP requests, 10 TCP connections
- **Files dropped:** 11 (Firebase installation data, config files)
- **Notable:** 2 malicious processes, system commands executed

### SpyMax
- **Verdict:** Malicious activity (tagged)
- **C2:** None observed (dormant)
- **Network:** 5 HTTP requests, 8 TCP connections (Google only)
- **Files dropped:** 0
- **Evasion:** C2-dependent dormancy — full features require operator activation

### TruthSpy
- **Verdict:** Suspicious activity
- **C2:** None observed in 60s window
- **Network:** 5 HTTP requests, 8 TCP connections
- **Files dropped:** 0
- **Notable:** TCP connections consistent with C2 check-in attempt

### Selfspy
- **Status:** Not submitted — APK size >16MB exceeds free tier limit
- **Note:** Consistent with 6 dex files (largest codebase in dataset)

---

## Analysis Limitations

The 60-second analysis window is the primary constraint of this study. SpyNote and SpyMax demonstrated C2-dependent dormancy, producing no malicious behavior during the analysis window. A longer analysis duration (5–15 minutes) with active user simulation would likely reveal substantially more behavioral indicators for these samples.

For future analysis, consider:
- ANY.RUN paid tier (up to 10 minutes)
- Local MobSF on Android Studio emulator (no time limit)
- Frida-based dynamic instrumentation for anti-emulation bypass
