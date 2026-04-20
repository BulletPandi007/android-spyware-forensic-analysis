import pandas as pd

# ── Ghidra findings summary ───────────────────────────────
ghidra_findings = [
    {
        'apk_file': 'antidot.apk',
        'ghidra_analyzed': True,
        'native_libs_analyzed': 'libx2.so, libnmmp.so',
        'key_native_findings': (
            'libx2.so: manufacturer-specific overlay engine (Samsung/Huawei/OPPO/Vivo/'
            'OnePlus/Xiaomi/Redmi/Motorola/Realme) — 8 OEM-specific window layout functions; '
            'hideEnable() stealth toggle @ 0x141000; c_initSDK JNI bridge'
        ),
        'native_vm_protection': True,
        'native_vm_detail': (
            'libnmmp.so: nmmedit protect SDK — custom VM interpreter (vmInterpret) '
            'encrypts core Java logic into native bytecode, invisible to static analysis'
        ),
        'native_urls_found': 'None',
        'native_dlopen_dlsym': False,
        'native_suspicious_functions': (
            'hideEnable, setupSamsungWindowLayout, setupHuaWeiWindowLayout, '
            'setupOPPOWindowLayout, setupVivoWindowLayout, setupOnePlusWindowLayout, '
            'setupXiaomiWindowLayout, setupRedMiWindowLayout, setupMotoRolaWindowLayout, '
            'setupRealmeWindowLayout, c_initSDK, CallObjectMethod, CallVoidMethod, '
            'JNU_CallMethodByName, JNU_CallStaticMethodByName'
        ),
        'native_stealth_notes': (
            'Most sophisticated native layer found — professional OEM-specific overlay '
            'bypasses + VM-based code encryption. Core spying logic fully hidden from '
            'Java-level static analysis.'
        )
    },
    {
        'apk_file': 'truthspy.apk',
        'ghidra_analyzed': True,
        'native_libs_analyzed': 'libandroidlame.so',
        'key_native_findings': (
            'libandroidlame.so: open-source LAME MP3 encoder weaponized for audio exfil; '
            'JNI bridge: Java_com_naman14_androidlame_AndroidLame_lameEncode/Flush/Close; '
            'full encoding pipeline: PCM capture → MP3 compression → exfiltration'
        ),
        'native_vm_protection': False,
        'native_vm_detail': 'None detected',
        'native_urls_found': 'http://lame.sf.net (LAME project homepage — benign)',
        'native_dlopen_dlsym': False,
        'native_suspicious_functions': (
            'lameEncode, lameFlush, lameClose, initializeDefault, '
            'encode, encodeBufferInterleaved, mdct_sub48'
        ),
        'native_stealth_notes': (
            'Uses legitimate open-source library (naman14/AndroidLame) as audio '
            'exfiltration engine. MP3 compression reduces file size ~10x vs raw PCM, '
            'making network exfil harder to detect. classes.dex shows heavy ProGuard '
            'obfuscation — all function names single characters (a,b,c...).'
        )
    }
]

# ── Merge into master CSV ─────────────────────────────────
df = pd.read_csv(r"D:\Major_Project\forensic_analysis_final.csv")
ghidra_df = pd.DataFrame(ghidra_findings)

# Fill non-analyzed samples
all_samples = df['apk_file'].tolist()
analyzed = [g['apk_file'] for g in ghidra_findings]
for sample in all_samples:
    if sample not in analyzed:
        ghidra_df = pd.concat([ghidra_df, pd.DataFrame([{
            'apk_file': sample,
            'ghidra_analyzed': False,
            'native_libs_analyzed': 'None — no .so files',
            'key_native_findings': 'N/A',
            'native_vm_protection': False,
            'native_vm_detail': 'N/A',
            'native_urls_found': 'N/A',
            'native_dlopen_dlsym': False,
            'native_suspicious_functions': 'N/A',
            'native_stealth_notes': 'No native libraries present'
        }])], ignore_index=True)

df = df.merge(ghidra_df, on='apk_file', how='left')
df.to_csv(r"D:\Major_Project\forensic_analysis_final.csv", index=False)
print("Ghidra findings merged into forensic_analysis_final.csv")

# ── Print summary ─────────────────────────────────────────
print("\n── Ghidra Native Analysis Summary ─────────────────────")
for f in ghidra_findings:
    print(f"\n{f['apk_file']}")
    print(f"  Libraries  : {f['native_libs_analyzed']}")
    print(f"  VM Protect : {f['native_vm_protection']} — {f['native_vm_detail'][:60]}...")
    print(f"  URLs       : {f['native_urls_found']}")
    print(f"  Key finding: {f['native_stealth_notes'][:80]}...")