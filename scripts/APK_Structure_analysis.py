import os
import re
from zipfile import ZipFile
import pandas as pd


analysis_list = [
    (r"D:\Major_Project\samples\antidot\antidot.apk", r"D:\Major_Project\Decomplied_samples\antidot"),
    (r"D:\Major_Project\samples\Brata\brata.apk", r"D:\Major_Project\Decomplied_samples\brata"),
    (r"D:\Major_Project\samples\clayrat\clayrat.apk", r"D:\Major_Project\Decomplied_samples\clayrat"),
    (r"D:\Major_Project\samples\selfspy.apk", r"D:\Major_Project\Decomplied_samples\selfmade"),
    (r"D:\Major_Project\samples\spymax\spymax.apk", r"D:\Major_Project\Decomplied_samples\spymax"),
    (r"D:\Major_Project\samples\spynote\spynote.apk", r"D:\Major_Project\Decomplied_samples\spynote"),
    (r"D:\Major_Project\samples\truthspy\truthspy.apk", r"D:\Major_Project\Decomplied_samples\truthspy"),
]

def check_apk_structure(apk_path):
    if not os.path.exists(apk_path):
        return {}

    result = {
        'dex_count': 0,
        'dex_files': '',
        'has_native_libs': False,
        'native_libs': '',
        'native_archs': '',
        'signing_scheme': '',
        'unusual_entries': '',
        'unusual_entry_count': 0
    }

    try:
        with ZipFile(apk_path) as z:
            names = z.namelist()

            # ── Multi-dex detection ───────────────────────────
            dex_files = [f for f in names if f.endswith('.dex')]
            result['dex_count'] = len(dex_files)
            result['dex_files'] = ', '.join(dex_files)

            # ── Native library detection ──────────────────────
            so_files = [f for f in names if f.endswith('.so')]
            result['has_native_libs'] = len(so_files) > 0
            result['native_libs'] = ', '.join([os.path.basename(f) for f in so_files[:8]])

            archs = set()
            for f in so_files:
                parts = f.split('/')
                if len(parts) >= 2:
                    archs.add(parts[1])
            result['native_archs'] = ', '.join(sorted(archs))

            # ── Unusual ZIP entry detection ───────────────────
            expected_prefixes = (
                'res/', 'META-INF/', 'assets/', 'lib/',
                'classes', 'AndroidManifest.xml',
                'resources.arsc', 'kotlin/'
            )
            unusual = [
                f for f in names
                if not any(f.startswith(p) for p in expected_prefixes)
                and f not in ('resources.arsc', 'AndroidManifest.xml')
            ]
            result['unusual_entry_count'] = len(unusual)
            result['unusual_entries'] = ', '.join(unusual[:10])

    except Exception as e:
        result['unusual_entries'] = f"ZIP error: {str(e)}"

    # ── Signing scheme detection ──────────────────────────────
    try:
        with open(apk_path, 'rb') as f:
            data = f.read()

        sig_magic = b'APK Sig Block 42'
        has_v2_v3 = sig_magic in data

        with ZipFile(apk_path) as z:
            meta_files = [f for f in z.namelist() if f.startswith('META-INF/')]
            has_v1 = any(f.endswith(('.SF', '.RSA', '.DSA')) for f in meta_files)

        if has_v2_v3 and has_v1:
            result['signing_scheme'] = 'v1 + v2/v3 (standard modern)'
        elif has_v2_v3:
            result['signing_scheme'] = 'v2/v3 only (no v1)'
        elif has_v1:
            result['signing_scheme'] = 'v1 only (old — suspicious)'
        else:
            result['signing_scheme'] = 'unsigned or unknown'

    except Exception as e:
        result['signing_scheme'] = f"error: {str(e)}"

    return result



print("Running APK structure analysis...")

structure_rows = []
for apk_path, _ in analysis_list:
    if not os.path.exists(apk_path):
        print(f"  Skipping (not found): {apk_path}")
        continue
    structure = check_apk_structure(apk_path)
    structure['apk_file'] = os.path.basename(apk_path)
    structure_rows.append(structure)
    print(f"  Done: {os.path.basename(apk_path)}")



struct_df = pd.DataFrame(structure_rows)

# ── Merge into forensic_analysis_final.csv ───────────────
df = pd.read_csv(r"D:\Major_Project\forensic_analysis_final.csv")
df = df.merge(struct_df, on='apk_file', how='left')
df.to_csv(r"D:\Major_Project\forensic_analysis_final.csv", index=False)



# ── Print summary ─────────────────────────────────────────
print("\n── APK Structure Summary ──────────────────────────────")
summary_cols = ['apk_file', 'dex_count', 'has_native_libs',
                'native_archs', 'signing_scheme', 'unusual_entry_count']
print(df[summary_cols].to_string(index=False))
print("\nAPK structure analysis complete!")

# ── Inspect unusual entries in detail ────────────────────
SAMPLES_TO_INSPECT = [
    r"D:\Major_Project\samples\antidot\antidot.apk",
    r"D:\Major_Project\samples\spynote\spynote.apk",
    r"D:\Major_Project\samples\Brata\brata.apk",
    r"D:\Major_Project\samples\selfspy.apk",
    r"D:\Major_Project\samples\truthspy\truthspy.apk",
]

expected_prefixes = (
    'res/', 'META-INF/', 'assets/', 'lib/',
    'classes', 'AndroidManifest.xml',
    'resources.arsc', 'kotlin/'
)

def categorize_unusual(names):
    categories = {
        'hidden_dex': [],       # dex files with unusual names
        'embedded_apk': [],     # nested APKs or ZIPs
        'raw_data': [],         # .bin .dat .enc files
        'scripts': [],          # .js .sh .py files
        'other': []
    }
    unusual = [
        f for f in names
        if not any(f.startswith(p) for p in expected_prefixes)
        and f not in ('resources.arsc', 'AndroidManifest.xml')
    ]
    for f in unusual:
        lower = f.lower()
        if lower.endswith('.dex'):
            categories['hidden_dex'].append(f)
        elif lower.endswith(('.apk', '.zip', '.jar')):
            categories['embedded_apk'].append(f)
        elif lower.endswith(('.bin', '.dat', '.enc', '.db', '.so')):
            categories['raw_data'].append(f)
        elif lower.endswith(('.js', '.sh', '.py', '.lua')):
            categories['scripts'].append(f)
        else:
            categories['other'].append(f)
    return categories

print("\n── Unusual Entry Breakdown ────────────────────────────")
for apk_path in SAMPLES_TO_INSPECT:
    if not os.path.exists(apk_path):
        continue
    name = os.path.basename(apk_path)
    try:
        with ZipFile(apk_path) as z:
            cats = categorize_unusual(z.namelist())
            print(f"\n{name}:")
            for cat, entries in cats.items():
                if entries:
                    print(f"  [{cat}] ({len(entries)} files)")
                    for e in entries[:5]:   # show first 5 of each
                        print(f"    {e}")
                    if len(entries) > 5:
                        print(f"    ... and {len(entries) - 5} more")
    except Exception as e:
        print(f"  Error: {e}")