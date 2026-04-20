import xml.etree.ElementTree as ET
import os
import re
from zipfile import ZipFile
import pandas as pd
from collections import Counter

def extract_permissions(manifest_path):
    if not os.path.exists(manifest_path):
        return []
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}  
    permissions = []
    for perm in root.findall(".//uses-permission", ns):
        name = perm.get(f"{{{ns['android']}}}name")
        if name:
            permissions.append(name)
    return permissions

def find_components(manifest_path):
    if not os.path.exists(manifest_path):
        return {'services': [], 'receivers': [], 'activities': []}
    
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    components = {
        'services': [],
        'receivers': [],
        'activities': []
    }
    
    for tag, list_key in [
        ('service', 'services'),
        ('receiver', 'receivers'),
        ('activity', 'activities')
    ]:
        for comp in root.findall(f".//{tag}", ns):
            name = comp.get(f"{{{ns['android']}}}name", "Unnamed")
            exported = comp.get(f"{{{ns['android']}}}exported")
            intent_filters = len(comp.findall(".//intent-filter")) > 0
            
            # Build descriptive entry
            status_parts = []
            if exported == "true":
                status_parts.append("exported=true")
            elif exported == "false":
                status_parts.append("exported=false")
            else:
                status_parts.append("exported=not-set")
            
            if intent_filters:
                status_parts.append("has-intent-filter")
            
            # Check for common dangerous intent actions
            dangerous_intents = []
            for intent in comp.findall(".//intent-filter//action", ns):
                action_name = intent.get(f"{{{ns['android']}}}name", "")
                if any(x in action_name.lower() for x in [
                    'boot_completed', 'sms_received', 'phone_state', 'user_present',
                    'screen_on', 'connectivity_change', 'location'
                ]):
                    dangerous_intents.append(action_name.split('.')[-1])
            
            if dangerous_intents:
                status_parts.append(f"dangerous: {', '.join(dangerous_intents[:2])}")
            
            entry = f"{name} ({' | '.join(status_parts)})"
            components[list_key].append(entry)
    
    return components

def scan_strings_for_iocs(apk_path):
    findings = []
    # Extended keyword list — partial matches, case insensitive
    keywords = [
        'http', 'https', 'api', 'panel', 'gate', 'c2', 'command', 'control', 'server',
        'exfil', 'upload', 'telegram', 'bot', 'whatsapp', 'sms', 'send', 'keylog',
        'logger', 'camera', 'mic', 'record', 'audio', 'video', 'location', 'gps',
        'track', 'contacts', 'call', 'password', 'key', 'token', 'firebase',
        'onesignal', 'hook', 'inject', 'root', 'su', 'magisk'
    ]
    
    if not os.path.exists(apk_path):
        return ["APK not found"]
    
    try:
        with ZipFile(apk_path) as z:
            for file_info in z.infolist():
                file = file_info.filename
                # Scan more file types
                if file.endswith(('.smali', '.xml', '.json', '.properties', '.txt', '.js')) or 'string' in file.lower():
                    try:
                        content = z.read(file).decode('utf-8', errors='ignore').lower()
                        found = []
                        for kw in keywords:
                            if kw in content:
                                count = content.count(kw)
                                found.append(f"{kw} ({count}x)")
                        if found:
                            findings.append(f"{file}: {', '.join(found)}")
                    except:
                        pass
    except Exception as e:
        findings.append(f"ZIP read error: {str(e)}")
    
    return findings if findings else ["No keywords matched in scanned files"]

def analyze_apk(apk_path, decompiled_dir):
    manifest = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    data = {
        'apk_file': os.path.basename(apk_path),
        'decompiled_dir': decompiled_dir,
        'permissions': extract_permissions(manifest),
        'components': find_components(manifest),
        'suspicious_strings': scan_strings_for_iocs(apk_path)
    }
    return data

# Instead of showing all, summarize top keywords
def summarize_suspicious(x):
    if not x:
        return ''
    from collections import Counter
    kws = []
    for item in x:
        parts = item.split(': ')[1].split(', ') if ': ' in item else []
        for p in parts:
            if ' (' in p:
                kw = p.split(' (')[0].strip()
                kws.append(kw)
    if not kws:
        return ''
    cnt = Counter(kws)
    top = cnt.most_common(5)  # top 5 keywords
    return f"Top keywords: {', '.join([f'{k} ({c}x)' for k,c in top])}; Total entries: {len(x)}"

# ======================
#   CONFIGURE YOUR PATHS HERE
# ======================
analysis_list = [
    # Format: (original_apk_path, decompiled_folder_path)
    (r"D:\Major_Project\samples\antidot\antidot.apk", r"D:\Major_Project\Decomplied_samples\antidot"),
    (r"D:\Major_Project\samples\Brata\brata.apk", r"D:\Major_Project\Decomplied_samples\brata"),
    (r"D:\Major_Project\samples\clayrat\clayrat.apk",r"D:\Major_Project\Decomplied_samples\clayrat"),
    (r"D:\Major_Project\samples\selfspy.apk",r"D:\Major_Project\Decomplied_samples\selfmade"),
    (r"D:\Major_Project\samples\spymax\spymax.apk",r"D:\Major_Project\Decomplied_samples\spymax"),
    (r"D:\Major_Project\samples\spynote\spynote.apk",r"D:\Major_Project\Decomplied_samples\spynote"),
    (r"D:\Major_Project\samples\truthspy\truthspy.apk",r"D:\Major_Project\Decomplied_samples\truthspy"),
    
    # Add your actual paths here — one tuple per sample
    # Example:
    # (r"/home/bullet/samples/mspy.apk", r"/home/bullet/decompiled/mspy_folder"),
]

# Run analysis
results = []
for apk_path, decomp_dir in analysis_list:
    if not os.path.exists(apk_path):
        print(f"APK not found: {apk_path}")
        continue
    if not os.path.exists(decomp_dir):
        print(f"Decompiled folder not found: {decomp_dir}")
        continue
    
    result = analyze_apk(apk_path, decomp_dir)
    if result:
        results.append(result)

# Save to CSV
if results:
    df = pd.DataFrame(results)
    # Expand lists for better readability in CSV
    df_expanded = df.copy()
    
# ────────────────────────────────────────────────
#   Dangerous permissions classification
# ────────────────────────────────────────────────

DANGEROUS_PERMS = [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.CALL_PHONE',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.PACKAGE_USAGE_STATS',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    'android.permission.SYSTEM_ALERT_WINDOW'  # overlay - common in stalkerware
]

def count_dangerous(perms_list):
    if not isinstance(perms_list, list):
        return 0
    return sum(1 for p in perms_list if p in DANGEROUS_PERMS)

def list_dangerous(perms_list):
    if not isinstance(perms_list, list):
        return ''
    dangerous = [p.split('.')[-1] for p in perms_list if p in DANGEROUS_PERMS]
    return ', '.join(dangerous) if dangerous else 'None'

# ────────────────────────────────────────────────
#   Basic Obfuscation Detection (focus on res/ folder)
# ────────────────────────────────────────────────

def detect_obfuscated_res(apk_path):
    if not os.path.exists(apk_path):
        return 0, "APK not found"

    short_obfuscated_count = 0
    indicators = []

    try:
        with ZipFile(apk_path) as z:
            res_files = [f for f in z.namelist() if f.startswith('res/') and f.endswith('.xml')]
            
            # Count very short/obfuscated filenames (typical in obfuscated spyware)
            for f in res_files:
                filename = os.path.basename(f)
                # Common obfuscation patterns: very short name, starts with -, number/letter mix
                if len(filename) <= 6 or filename.startswith('-') or re.match(r'^[0-9A-Za-z_-]{1,5}\.xml$', filename):
                    short_obfuscated_count += 1
            
            total_res_xml = len(res_files)
            
            if short_obfuscated_count >= 20:
                indicators.append(f"High: {short_obfuscated_count} short/obfuscated res/*.xml files")
            elif short_obfuscated_count >= 8:
                indicators.append(f"Medium: {short_obfuscated_count} suspicious res/*.xml files")
            elif short_obfuscated_count > 0:
                indicators.append(f"Low: {short_obfuscated_count} short res/*.xml files")
            
            if total_res_xml > 100 and short_obfuscated_count / total_res_xml > 0.4:
                indicators.append("Many resources likely obfuscated")
    
    except Exception as e:
        indicators.append(f"Error scanning ZIP: {str(e)}")

    summary = '; '.join(indicators) if indicators else "No obvious obfuscation in res/"
    return short_obfuscated_count, summary




# 1. Add counts if not already there 
if 'permissions' in df_expanded.columns:
    df_expanded['permissions_count'] = df_expanded['permissions'].apply(len)
if 'components' in df_expanded.columns:
    df_expanded['services_count'] = df_expanded['components'].apply(lambda c: len(c.get('services', [])))
    df_expanded['receivers_count'] = df_expanded['components'].apply(lambda c: len(c.get('receivers', [])))
if 'suspicious_strings' in df_expanded.columns:
    df_expanded['suspicious_strings_count'] = df_expanded['suspicious_strings'].apply(len)
    df_expanded['dangerous_permissions_count'] = df_expanded['permissions'].apply(count_dangerous)
    df_expanded['dangerous_permissions_list'] = df_expanded['permissions'].apply(list_dangerous)
    df_expanded['obfuscated_res_files_count'], df_expanded['obfuscation_indicators'] = zip(
    *df_expanded['apk_file'].apply(lambda f: detect_obfuscated_res(
        next((p for p, _ in analysis_list if os.path.basename(p) == f), None)
    ))
)
else:
    print("No valid samples analyzed. Check paths.")

# 2. Summarize suspicious strings 
def summarize_suspicious(x):
    if not isinstance(x, list) or not x:
        return 'No keywords detected'
    
    kws = []
    for item in x:
        # Example item: 'res/1M.xml: http (1x), bot (3x)'
        if ': ' in item:
            after = item.split(': ', 1)[1]
            parts = after.split(', ')
            for p in parts:
                if ' (' in p:
                    kw = p.split(' (')[0].strip()
                    kws.append(kw)
    
    if not kws:
        return 'No keywords detected'
    
    cnt = Counter(kws)
    top = cnt.most_common(6)
    summary = ', '.join([f'{k} ({c}x)' for k, c in top])
    return f"Top: {summary} | Total entries: {len(x)}"
    
df_expanded['suspicious_strings_summary'] = df_expanded['suspicious_strings'].apply(summarize_suspicious)
df_expanded.to_csv('initial_forensic_analysis_readable.csv', index=False)
print("Updated readable CSV saved!")
    
    
