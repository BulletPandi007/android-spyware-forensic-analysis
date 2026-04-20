import pandas as pd
import json
import os
from datetime import date

# ── Load master CSV ───────────────────────────────────────
df = pd.read_csv(r"D:\Major_Project\forensic_analysis_final.csv")

# ── Dynamic findings collected so far ────────────────────
# Fill this in as you get results from ANY.RUN
# Each entry = one sandbox submission
dynamic_results = [
    {
        'apk_file': 'spynote.apk',
        'sandbox': 'ANY.RUN',
        'task_id': '9505dc11-c46f-4830-a8dc-f81c3292841f',
        'analysis_date': '2026-03-31',
        'duration_seconds': 60,
        'verdict': 'Malicious activity',
        'package_name': 'com.appd.mercantil',
        'c2_ips': '',
        'c2_domains': '',
        'dns_queries': 'google.com, connectivitycheck.gstatic.com, time.android.com',
        'http_requests': 4,
        'tcp_connections': 8,
        'files_dropped': 1,
        'files_dropped_detail': 'base.2841.tmp (binary cache)',
        'runtime_permissions': '',
        'malicious_indicators': 0,
        'suspicious_indicators': 0,
        'evasion_detected': True,
        'evasion_detail': (
            'SpyNote remained dormant during 60s window — no C2 contact, '
            'no malicious behavior triggered. Consistent with C2-dependent '
            'activation — RAT requires live operator connection to act.'
        ),
        'notable_finding': 'Package disguised as com.appd.mercantil (merchant/payment app)',
        'report_url': 'https://app.any.run/tasks/9505dc11-c46f-4830-a8dc-f81c3292841f',
    },
    {
    'apk_file': 'antidot.apk',
    'sandbox': 'ANY.RUN',
    'task_id': '573db37c-c219-4b21-b0f1-7ed72efc3b8a',
    'analysis_date': '2026-04-07',
    'duration_seconds': 60,
    'verdict': 'Malicious activity',
    'package_name': 'com.wetpacd1d.psyd1d',
    'c2_ips': '147.139.146.211, 147.139.146.209, 147.139.146.144',
    'c2_domains': 'log-service-553108611941314 8-ap-southeast-5.log.aliyuncs.com, ping.ynrkone.top, pip.uiimoss.top',
    'dns_queries': 'google.com, aliyuncs.com, ping.ynrkone.top, pip.uiimoss.top',
    'http_requests': 18,
    'tcp_connections': 12,
    'files_dropped': 39,
    'files_dropped_detail': '21 suspicious + 18 text files under com.wetpacd1d.psyd1d — WebView cache, LevelDB databases, profile data',
    'runtime_permissions': '',
    'malicious_indicators': 1,
    'suspicious_indicators': 9,
    'evasion_detected': False,
    'evasion_detail': '',
    'notable_finding': (
        'Package com.wetpacd1d.psyd1d. Live C2 confirmed: ping.ynrkone.top + '
        'aliyuncs.com logging endpoint (147.139.146.211). 12 SURICATA alerts for '
        'unrecognized HTTP auth method — custom C2 protocol. Checks screen state, '
        'device admin, clipboard, installed apps. Dynamically loads classes at runtime '
        '— confirms Ghidra VM protection finding. Scans for banking apps to overlay.'
    ),
    'report_url': 'https://app.any.run/tasks/573db37c-c219-4b21-b0f1-7ed72efc3b8a',
},
    
   {
    'apk_file': 'clayrat.apk',
    'sandbox': 'ANY.RUN',
    'task_id': '',  # paste your task ID
    'analysis_date': '2026-04-01',
    'duration_seconds': 60,
    'verdict': 'Malicious activity',
    'package_name': '',
    'c2_ips': '64.188.83.172',
    'c2_domains': 'losthed.clay.rest',
    'dns_queries': 'youtube.com, google.com, losthed.clay.rest',
    'http_requests': 90,
    'tcp_connections': 30,
    'files_dropped': 11,
    'files_dropped_detail': 'VPN configs, WebSocket client files, work profiles, temp binaries in /data/user/0/.../cache/',
    'runtime_permissions': '',
    'malicious_indicators': 1,
    'suspicious_indicators': 0,
    'evasion_detected': False,
    'evasion_detail': '',
    'notable_finding': 'Live C2 confirmed: losthed.clay.rest (64.188.83.172) — Python Werkzeug server. App hides from display, uses awake locks, registers broadcast receivers.',
    'report_url': '',
},
{
    'apk_file': 'brata.apk',
    'sandbox': 'ANY.RUN',
    'task_id': '',
    'analysis_date': '2026-04-01',
    'duration_seconds': 60,
    'verdict': 'Malicious activity',
    'package_name': 'sh.abc.shabd',
    'c2_ips': '',
    'c2_domains': 'firebaseinstallations.googleapis.com, app-measurement.com',
    'dns_queries': 'firebaseinstallations.googleapis.com, app-measurement.com',
    'http_requests': 7,
    'tcp_connections': 10,
    'files_dropped': 11,
    'files_dropped_detail': 'PersistedInstallation*.json, Firebase config, measurement prefs in /data/user/0/sh.abc.shabd/',
    'runtime_permissions': '',
    'malicious_indicators': 2,
    'suspicious_indicators': 0,
    'evasion_detected': False,
    'evasion_detail': '',
    'notable_finding': 'Package sh.abc.shabd. 2 malicious processes. Firebase used for C2 blending. No direct C2 in 60s window.',
    'report_url': '',
},
{
    'apk_file': 'spymax.apk',
    'sandbox': 'ANY.RUN',
    'task_id': '',
    'analysis_date': '2026-04-01',
    'duration_seconds': 60,
    'verdict': 'Malicious activity',
    'package_name': '',
    'c2_ips': '',
    'c2_domains': '',
    'dns_queries': 'google.com, connectivitycheck.gstatic.com',
    'http_requests': 5,
    'tcp_connections': 8,
    'files_dropped': 0,
    'files_dropped_detail': '',
    'runtime_permissions': '',
    'malicious_indicators': 0,
    'suspicious_indicators': 0,
    'evasion_detected': True,
    'evasion_detail': 'SpyMax showed no malicious behavior in 60s — full features require longer runtime or user interaction.',
    'notable_finding': 'Known Android spyware. Limited activity suggests C2-dependent activation similar to SpyNote.',
    'report_url': '',
},
{
    'apk_file': 'truthspy.apk',
    'sandbox': 'ANY.RUN',
    'task_id': '',
    'analysis_date': '2026-04-01',
    'duration_seconds': 60,
    'verdict': 'Suspicious activity',
    'package_name': '',
    'c2_ips': '',
    'c2_domains': '',
    'dns_queries': 'google.com, connectivitycheck.gstatic.com',
    'http_requests': 5,
    'tcp_connections': 8,
    'files_dropped': 0,
    'files_dropped_detail': '',
    'runtime_permissions': '',
    'malicious_indicators': 0,
    'suspicious_indicators': 0,
    'evasion_detected': False,
    'evasion_detail': '',
    'notable_finding': 'Marked suspicious. No C2 observed. Full spying features need longer runtime.',
    'report_url': '',
},
{
    'apk_file': 'selfspy.apk',
    'sandbox': 'ANY.RUN',
    'task_id': 'N/A',
    'analysis_date': '2026-04-01',
    'duration_seconds': 0,
    'verdict': 'Not submitted',
    'package_name': '',
    'c2_ips': '',
    'c2_domains': '',
    'dns_queries': '',
    'http_requests': 0,
    'tcp_connections': 0,
    'files_dropped': 0,
    'files_dropped_detail': '',
    'runtime_permissions': '',
    'malicious_indicators': 0,
    'suspicious_indicators': 0,
    'evasion_detected': False,
    'evasion_detail': '',
    'notable_finding': 'APK exceeds ANY.RUN free tier upload limit (>16MB). Consistent with 6 dex files — largest sample in dataset. Dynamic analysis not possible without paid sandbox tier.',
    'report_url': '',
},
]

# ── Build dynamic dataframe ───────────────────────────────
dyn_df = pd.DataFrame(dynamic_results)

# ── Merge static + dynamic ────────────────────────────────
merged = df.merge(dyn_df, on='apk_file', how='left')

# ── Correlation flags ─────────────────────────────────────
def correlate(row):
    flags = []
    notes = []

    # Flag 1: Static socket hits confirmed by dynamic TCP connections
    sockets = row.get('socket-connection', 0)
    tcp = row.get('tcp_connections', 0)
    if pd.notna(sockets) and pd.notna(tcp):
        if sockets >= 1 and tcp >= 1:
            flags.append('C2_CONFIRMED')
            notes.append(f'Socket hits ({int(sockets)}) confirmed by {int(tcp)} TCP connections')

    # Flag 2: Static HTTP POST confirmed by dynamic HTTP requests
    http_static = row.get('http-post-data', 0)
    http_dynamic = row.get('http_requests', 0)
    if pd.notna(http_static) and pd.notna(http_dynamic):
        if http_static >= 1 and http_dynamic >= 1:
            flags.append('HTTP_EXFIL_LIKELY')
            notes.append(f'HTTP POST static hits ({int(http_static)}) + {int(http_dynamic)} runtime HTTP requests')

    # Flag 3: Evasion detected
    if row.get('evasion_detected') == True:
        flags.append('SANDBOX_EVASION')
        notes.append(str(row.get('evasion_detail', '')))

    # Flag 4: No sandbox data
    if pd.isna(row.get('sandbox')):
        flags.append('NO_DYNAMIC_DATA')
        notes.append('Sample not yet submitted to sandbox')

    # Flag 5: Files dropped
    if pd.notna(row.get('files_dropped')) and row.get('files_dropped', 0) > 0:
        flags.append('FILES_DROPPED')
        notes.append(str(row.get('files_dropped_detail', '')))

    return (
        ', '.join(flags) if flags else 'NO_FLAGS',
        ' | '.join(notes) if notes else ''
    )

merged['correlation_flags'], merged['correlation_notes'] = zip(
    *merged.apply(correlate, axis=1)
)

# ── Adjust stealth score based on dynamic findings ────────
def dynamic_stealth_adjustment(row):
    adjustment = 0
    reasons = []

    if row.get('evasion_detected') == True:
        adjustment += 1
        reasons.append('sandbox evasion confirmed (+1)')

    if 'C2_CONFIRMED' in str(row.get('correlation_flags', '')):
        adjustment += 1
        reasons.append('C2 communication confirmed at runtime (+1)')

    return adjustment, '; '.join(reasons)

merged['dynamic_stealth_adjustment'], merged['dynamic_adjustment_reason'] = zip(
    *merged.apply(dynamic_stealth_adjustment, axis=1)
)
merged['final_stealth_score'] = (
    merged['stealth_score'] + merged['dynamic_stealth_adjustment']
).clip(upper=10)

# ── Print correlation summary ─────────────────────────────
print("=" * 70)
print("STATIC vs DYNAMIC CORRELATION SUMMARY")
print(f"Generated: {date.today()}")
print("=" * 70)

for _, row in merged.iterrows():
    print(f"\n── {row['apk_file']} {'─'*(50-len(str(row['apk_file'])))}")
    print(f"  Static stealth score : {row.get('stealth_score', 'N/A')}/10")
    print(f"  Dynamic adjustment   : +{row.get('dynamic_stealth_adjustment', 0)}")
    print(f"  Final stealth score  : {row.get('final_stealth_score', 'N/A')}/10")
    print(f"  Correlation flags    : {row.get('correlation_flags', 'N/A')}")
    if row.get('correlation_notes'):
        print(f"  Notes                : {row.get('correlation_notes', '')[:80]}...")
    if pd.notna(row.get('sandbox')):
        print(f"  Sandbox              : {row.get('sandbox')} — {row.get('verdict', '')}")
        print(f"  Evasion detected     : {row.get('evasion_detected', False)}")

# ── Save ──────────────────────────────────────────────────
output_path = r"D:\Major_Project\forensic_analysis_correlated.csv"
merged.to_csv(output_path, index=False)
print(f"\n\nCorrelated CSV saved to: {output_path}")