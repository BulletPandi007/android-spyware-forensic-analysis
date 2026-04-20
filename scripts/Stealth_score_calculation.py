import pandas as pd

df = pd.read_csv(r"D:\Major_Project\forensic_analysis_with_semgrep.csv")

def calculate_stealth_score(row):
    score = 0
    reasons = []

    # ── Dangerous Permissions (max 2 pts) ─────────────────
    dp = row.get('dangerous_permissions_count', 0)
    if dp >= 10:
        score += 2
        reasons.append(f"very high dangerous perms ({dp})")
    elif dp >= 6:
        score += 1
        reasons.append(f"high dangerous perms ({dp})")

    # ── Obfuscation (max 2 pts) ───────────────────────────
    obf = row.get('obfuscated_res_files_count', 0)
    if obf >= 20:
        score += 2
        reasons.append(f"heavy obfuscation ({obf} files)")
    elif obf >= 8:
        score += 1
        reasons.append(f"moderate obfuscation ({obf} files)")

    # ── Persistence (max 1 pt) ────────────────────────────
    components = str(row.get('components', ''))
    if 'BOOT_COMPLETED' in components or 'boot' in components.lower():
        score += 1
        reasons.append("boot persistence")

    # ── Background Services (max 1 pt) ────────────────────
    if row.get('services_count', 0) >= 5:
        score += 1
        reasons.append(f"many services ({row['services_count']})")

    # ── Evasion Techniques (max 1 pt) ─────────────────────
    if row.get('emulator-detection', 0) >= 1:
        score += 1
        reasons.append("emulator detection")

    # ── C2 / Network (max 1 pt) ───────────────────────────
    if row.get('socket-connection', 0) >= 1 or row.get('http-post-data', 0) >= 3:
        score += 1
        reasons.append("C2 communication patterns")

    # ── Surveillance APIs (max 2 pts) ─────────────────────
    surveillance = (
        row.get('audio-record', 0) +
        row.get('camera-capture', 0) +
        row.get('gps-location-request', 0) +
        row.get('call-log-access', 0)
    )
    if surveillance >= 10:
        score += 2
        reasons.append(f"heavy surveillance API use ({surveillance} hits)")
    elif surveillance >= 4:
        score += 1
        reasons.append(f"moderate surveillance API use ({surveillance} hits)")
        
    # ── Accessibility Service Abuse (max 1 pt) ────────────────
    components_str = str(row.get('components', ''))
    if 'accessibility' in components_str.lower():
        score += 1
        reasons.append("accessibility service abuse (permission-less spying)")    
    
    # ── Unnamed Components (max 1 pt) ─────────────────────────
    components = row.get('components', {})
    if isinstance(components, str):
        import ast
        try:
            components = ast.literal_eval(components)
        except:
            components = {}

    all_components = (
        components.get('services', []) +
        components.get('receivers', []) +
        components.get('activities', [])
    )
    unnamed_count = sum(1 for c in all_components if 'Unnamed' in str(c))
    if unnamed_count >= 3:
        score += 1
        reasons.append(f"heavily unnamed components ({unnamed_count}) — manifest obfuscation")

    # ── Empty Permissions + Active Behavior (max 1 pt) ────────
    perms = row.get('permissions', [])
    if isinstance(perms, str):
        try:
            perms = ast.literal_eval(perms)
        except:
            perms = []

    semgrep_hits = row.get('semgrep_total_hits', 0)
    if len(perms) == 0 and semgrep_hits >= 10:
        score += 1
        reasons.append("zero declared permissions but high API activity — likely Accessibility abuse")

    return min(score, 10), '; '.join(reasons)

# Apply scoring
df['stealth_score'], df['stealth_reasons'] = zip(*df.apply(calculate_stealth_score, axis=1))

# Print summary
summary = df[['apk_file', 'dangerous_permissions_count', 
              'obfuscated_res_files_count', 'semgrep_total_hits',
              'stealth_score', 'stealth_reasons']].sort_values('stealth_score', ascending=False)

print(summary.to_string(index=False))

# Save
df.to_csv(r"D:\Major_Project\forensic_analysis_final.csv", index=False)
print("\nFinal CSV saved!")