"""
Android Spyware Forensic Analysis Framework
Hybrid Static-Dynamic Analysis Pipeline
National Forensic Sciences University (NFSU) | 2026
Author: Yaswanth

Requirements:
    pip install rich pandas matplotlib numpy
"""

import os, re, ast, sys, json, time, glob, shutil
import xml.etree.ElementTree as ET
from zipfile import ZipFile
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich.live import Live
from rich.layout import Layout
from rich import box

# ─────────────────────────────────────────────────────────
# CONSOLE + THEME
# ─────────────────────────────────────────────────────────
console = Console()

PALETTE = {
    "primary":   "#00B4D8",
    "accent":    "#0077A8",
    "red":       "#E63946",
    "amber":     "#F4A261",
    "green":     "#2DC653",
    "purple":    "#A78BFA",
    "navy":      "#0D1B2A",
    "gray":      "#8B9DB0",
    "white":     "#FFFFFF",
}

# ─────────────────────────────────────────────────────────
# STATE — Samples and Config
# ─────────────────────────────────────────────────────────
STATE = {
    "samples": [],          # list of {"apk": path, "decompiled": path, "name": name}
    "output_dir": "",
    "semgrep_json": "",
    "csv_path": "",
    "steps_done": set(),
}

# ─────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def header():
    clear()
    title = Text()
    title.append("  ⬡  ", style="bold #00B4D8")
    title.append("ANDROID SPYWARE FORENSIC ANALYSIS FRAMEWORK", style="bold white")
    title.append("  ⬡", style="bold #00B4D8")
    subtitle = Text("  Hybrid Static-Dynamic Analysis Pipeline  |  NFSU 2026", style="dim #8B9DB0")
    console.print(Panel(
        Align.center(title + "\n" + subtitle),
        border_style="#0077A8",
        padding=(1, 4),
        style="on #0D1B2A",
    ))

def section_rule(title):
    console.print()
    console.rule(f"[bold #00B4D8] {title} ", style="#0077A8")
    console.print()

def ok(msg):    console.print(f"  [bold #2DC653]✔[/]  {msg}")
def info(msg):  console.print(f"  [bold #00B4D8]ℹ[/]  {msg}")
def warn(msg):  console.print(f"  [bold #F4A261]⚠[/]  {msg}")
def err(msg):   console.print(f"  [bold #E63946]✘[/]  {msg}")
def prog(msg):  console.print(f"  [bold #A78BFA]▶[/]  {msg}")

def done_panel(msg):
    console.print()
    console.print(Panel(
        f"[bold #2DC653] ✔  {msg}[/]",
        border_style="#2DC653",
        padding=(0, 2),
    ))
    console.print()

def pause():
    console.print()
    Prompt.ask("  [dim]Press Enter to continue[/]", default="")

def samples_table():
    if not STATE["samples"]:
        console.print("  [dim]No samples loaded yet.[/]")
        return
    t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
              show_lines=True, padding=(0,1))
    t.add_column("#",         style="bold #A78BFA", width=4,  justify="center")
    t.add_column("APK File",  style="bold white",   width=22)
    t.add_column("APK Path",  style="#8B9DB0",      width=40)
    t.add_column("Decompiled Folder", style="#8B9DB0", width=38)
    t.add_column("Status",    style="bold",          width=10, justify="center")
    for i, s in enumerate(STATE["samples"]):
        apk_ok  = "✔" if os.path.exists(s["apk"])        else "✘"
        dec_ok  = "✔" if os.path.exists(s["decompiled"]) else "✘"
        apk_col = "[#2DC653]✔[/]" if os.path.exists(s["apk"]) else "[#E63946]✘[/]"
        dec_col = "[#2DC653]✔[/]" if os.path.exists(s["decompiled"]) else "[#F4A261]?[/]"
        both_ok = os.path.exists(s["apk"]) and os.path.exists(s["decompiled"])
        status  = "[#2DC653]Ready[/]" if both_ok else "[#F4A261]Partial[/]"
        t.add_row(str(i+1), s["name"],
                  f"{apk_col} {s['apk'][:37]}",
                  f"{dec_col} {s['decompiled'][:35]}",
                  status)
    console.print(t)

# ─────────────────────────────────────────────────────────
# SAMPLE MANAGER
# ─────────────────────────────────────────────────────────
def sample_manager():
    while True:
        header()
        section_rule("SAMPLE MANAGER")
        info(f"[bold]Loaded samples:[/] {len(STATE['samples'])}")
        console.print()
        samples_table()
        console.print()

        t = Table(box=None, show_header=False, padding=(0,2))
        t.add_column(style="bold #00B4D8", width=5)
        t.add_column(style="white",        width=28)
        t.add_column(style="dim #8B9DB0")
        t.add_row("[1]", "Add sample manually",       "Enter APK path + decompiled folder path")
        t.add_row("[2]", "Add sample from folder",    "Point to a folder — auto-detects APK files")
        t.add_row("[3]", "Remove a sample",           "Remove by number from list")
        t.add_row("[4]", "Clear all samples",         "Start fresh")
        t.add_row("[5]", "Set output directory",      f"Current: {STATE['output_dir'] or 'Not set'}")
        t.add_row("[6]", "Set Semgrep JSON path",     f"Current: {STATE['semgrep_json'] or 'Not set'}")
        t.add_row("[B]", "Back to main menu",         "")
        console.print(t)

        choice = Prompt.ask("\n  [bold #00B4D8]Choice[/]").strip().upper()

        if choice == "1":
            _add_sample_manual()
        elif choice == "2":
            _add_samples_from_folder()
        elif choice == "3":
            _remove_sample()
        elif choice == "4":
            if Confirm.ask("  [bold #F4A261]Clear all samples?[/]"):
                STATE["samples"] = []
                ok("All samples cleared.")
                time.sleep(0.8)
        elif choice == "5":
            _set_output_dir()
        elif choice == "6":
            _set_semgrep_json()
        elif choice == "B":
            break

def _add_sample_manual():
    console.print()
    console.print(Panel("[bold #00B4D8]Add Sample Manually[/]", border_style="#0077A8", padding=(0,2)))
    console.print()
    info("Enter the full path to your APK file.")
    info("Example: [dim]D:\\Major_Project\\samples\\antidot\\antidot.apk[/]")
    console.print()
    apk = Prompt.ask("  [bold]APK path[/]").strip().strip('"')
    if not apk: return
    if not os.path.exists(apk):
        warn(f"APK file not found: {apk}")
        warn("Adding anyway — you can fix the path later.")
    console.print()
    info("Enter the full path to the decompiled folder (from APKTool/JADX).")
    info("Example: [dim]D:\\Major_Project\\Decompiled_samples\\antidot[/]")
    info("Leave blank to skip (you can add later).")
    console.print()
    dec = Prompt.ask("  [bold]Decompiled folder path[/]", default="").strip().strip('"')
    name = os.path.basename(apk)
    STATE["samples"].append({"apk": apk, "decompiled": dec, "name": name})
    ok(f"Added: {name}")
    time.sleep(0.8)

def _add_samples_from_folder():
    console.print()
    console.print(Panel("[bold #00B4D8]Add Samples from Folder[/]", border_style="#0077A8", padding=(0,2)))
    console.print()
    info("Point to a folder containing APK files.")
    info("The script will find all .apk files automatically.")
    info("Example: [dim]D:\\Major_Project\\samples[/]")
    console.print()
    folder = Prompt.ask("  [bold]Folder path[/]").strip().strip('"')
    if not os.path.isdir(folder):
        err(f"Folder not found: {folder}"); time.sleep(1); return

    apks = list(Path(folder).rglob("*.apk"))
    if not apks:
        warn(f"No APK files found in {folder}"); time.sleep(1); return

    console.print()
    info(f"Found [bold #2DC653]{len(apks)}[/] APK files:")
    for i, apk in enumerate(apks):
        console.print(f"    [dim]{i+1}.[/] {apk}")
    console.print()

    info("Now enter the parent decompiled folder (optional).")
    info("The script will look for subfolders matching each APK name.")
    info("Example: [dim]D:\\Major_Project\\Decompiled_samples[/]")
    dec_parent = Prompt.ask("  [bold]Decompiled parent folder[/]", default="").strip().strip('"')

    added = 0
    for apk in apks:
        name = apk.stem  # filename without .apk
        # Try to auto-match decompiled folder
        dec_path = ""
        if dec_parent and os.path.isdir(dec_parent):
            # Look for folder named like the apk
            candidates = [
                os.path.join(dec_parent, name),
                os.path.join(dec_parent, apk.name),
            ]
            for c in candidates:
                if os.path.isdir(c):
                    dec_path = c
                    break

        STATE["samples"].append({
            "apk":        str(apk),
            "decompiled": dec_path,
            "name":       apk.name
        })
        if dec_path:
            ok(f"Added: {apk.name} → decompiled: {dec_path}")
        else:
            warn(f"Added: {apk.name} → [dim]no decompiled folder found[/]")
        added += 1

    console.print()
    done_panel(f"{added} samples added successfully")
    pause()

def _remove_sample():
    if not STATE["samples"]:
        warn("No samples to remove."); time.sleep(0.8); return
    console.print()
    samples_table()
    console.print()
    idx = Prompt.ask("  [bold]Enter sample number to remove[/]").strip()
    try:
        i = int(idx) - 1
        if 0 <= i < len(STATE["samples"]):
            removed = STATE["samples"].pop(i)
            ok(f"Removed: {removed['name']}")
        else:
            err("Invalid number.")
    except:
        err("Invalid input.")
    time.sleep(0.8)

def _set_output_dir():
    console.print()
    info("Enter the output directory for all analysis results.")
    info("Example: [dim]D:\\Major_Project\\outputs[/]")
    console.print()
    path = Prompt.ask("  [bold]Output directory[/]", default=STATE["output_dir"]).strip().strip('"')
    STATE["output_dir"] = path
    STATE["csv_path"] = os.path.join(path, "forensic_analysis_master.csv")
    os.makedirs(path, exist_ok=True)
    os.makedirs(os.path.join(path, "visualizations"), exist_ok=True)
    os.makedirs(os.path.join(path, "detection_rules"), exist_ok=True)
    ok(f"Output directory set: {path}")
    time.sleep(0.8)

def _set_semgrep_json():
    console.print()
    info("Enter the path to your semgrep_results.json file.")
    info("Example: [dim]D:\\Major_Project\\semgrep_results.json[/]")
    console.print()
    path = Prompt.ask("  [bold]Semgrep JSON path[/]", default=STATE["semgrep_json"]).strip().strip('"')
    STATE["semgrep_json"] = path
    if os.path.exists(path):
        ok(f"Semgrep JSON found: {path}")
    else:
        warn(f"File not found yet — set path for later: {path}")
    time.sleep(0.8)

# ─────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────
def validate_setup():
    issues = []
    if not STATE["samples"]:
        issues.append("No samples loaded — go to Sample Manager first")
    if not STATE["output_dir"]:
        issues.append("Output directory not set — go to Sample Manager → Set output directory")
    ready = [s for s in STATE["samples"] if os.path.exists(s["apk"]) and os.path.exists(s["decompiled"])]
    if STATE["samples"] and not ready:
        issues.append("No samples have valid APK + decompiled folder paths")
    return issues

# ─────────────────────────────────────────────────────────
# DANGEROUS PERMISSIONS LIST
# ─────────────────────────────────────────────────────────
DANGEROUS_PERMS = [
    'android.permission.READ_SMS','android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS','android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS','android.permission.READ_CALL_LOG',
    'android.permission.PROCESS_OUTGOING_CALLS','android.permission.CALL_PHONE',
    'android.permission.RECORD_AUDIO','android.permission.CAMERA',
    'android.permission.ACCESS_FINE_LOCATION','android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION','android.permission.READ_PHONE_STATE',
    'android.permission.READ_EXTERNAL_STORAGE','android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_EXTERNAL_STORAGE','android.permission.QUERY_ALL_PACKAGES',
    'android.permission.PACKAGE_USAGE_STATS',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    'android.permission.SYSTEM_ALERT_WINDOW'
]

# ─────────────────────────────────────────────────────────
# ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────────────────
def extract_permissions(manifest_path):
    if not os.path.exists(manifest_path): return []
    tree = ET.parse(manifest_path); root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    return [p.get(f"{{{ns['android']}}}name") for p in root.findall(".//uses-permission", ns)
            if p.get(f"{{{ns['android']}}}name")]

def find_components(manifest_path):
    if not os.path.exists(manifest_path):
        return {'services':[],'receivers':[],'activities':[]}
    tree = ET.parse(manifest_path); root = tree.getroot()
    ns = {'android':'http://schemas.android.com/apk/res/android'}
    components = {'services':[],'receivers':[],'activities':[]}
    for tag, key in [('service','services'),('receiver','receivers'),('activity','activities')]:
        for comp in root.findall(f".//{tag}", ns):
            name = comp.get(f"{{{ns['android']}}}name","Unnamed")
            exported = comp.get(f"{{{ns['android']}}}exported")
            has_filter = len(comp.findall(".//intent-filter")) > 0
            parts = [f"exported={exported or 'not-set'}"]
            if has_filter: parts.append("has-intent-filter")
            dangerous = []
            for intent in comp.findall(".//intent-filter//action", ns):
                action = intent.get(f"{{{ns['android']}}}name","")
                if any(x in action.lower() for x in ['boot_completed','sms_received','phone_state',
                   'user_present','screen_on','connectivity_change','location']):
                    dangerous.append(action.split('.')[-1])
            if dangerous: parts.append(f"dangerous:{','.join(dangerous[:2])}")
            components[key].append(f"{name}({' | '.join(parts)})")
    return components

def scan_iocs(apk_path):
    keywords = ['http','https','api','panel','gate','c2','command','control','server',
                'exfil','upload','telegram','bot','whatsapp','sms','send','keylog',
                'logger','camera','mic','record','audio','video','location','gps',
                'track','contacts','call','password','key','token','firebase',
                'onesignal','hook','inject','root','su','magisk']
    findings = []
    if not os.path.exists(apk_path): return ["APK not found"]
    try:
        with ZipFile(apk_path) as z:
            for fi in z.infolist():
                f = fi.filename
                if f.endswith(('.smali','.xml','.json','.properties','.txt','.js')) or 'string' in f.lower():
                    try:
                        content = z.read(f).decode('utf-8',errors='ignore').lower()
                        found = [f"{kw}({content.count(kw)}x)" for kw in keywords if kw in content]
                        if found: findings.append(f"{f}: {', '.join(found)}")
                    except: pass
    except Exception as e: findings.append(f"ZIP error:{e}")
    return findings or ["No keywords matched"]

def detect_obfuscation(apk_path):
    count = 0; indicators = []
    try:
        with ZipFile(apk_path) as z:
            res_files = [f for f in z.namelist() if f.startswith('res/') and f.endswith('.xml')]
            for f in res_files:
                fn = os.path.basename(f)
                if len(fn)<=6 or fn.startswith('-') or re.match(r'^[0-9A-Za-z_-]{1,5}\.xml$',fn):
                    count += 1
            total = len(res_files)
            if count>=20: indicators.append(f"High:{count} obfuscated res files")
            elif count>=8: indicators.append(f"Medium:{count} suspicious res files")
            elif count>0:  indicators.append(f"Low:{count} short res files")
            if total>100 and count/total>0.4: indicators.append("Many resources obfuscated")
    except Exception as e: indicators.append(f"Error:{e}")
    return count, '; '.join(indicators) or "No obvious obfuscation"

def check_apk_structure(apk_path):
    result = {'dex_count':0,'dex_files':'','has_native_libs':False,'native_libs':'',
              'native_archs':'','signing_scheme':'','unusual_entries':'','unusual_entry_count':0}
    if not os.path.exists(apk_path): return result
    expected = ('res/','META-INF/','assets/','lib/','classes','AndroidManifest.xml','resources.arsc','kotlin/')
    try:
        with ZipFile(apk_path) as z:
            names = z.namelist()
            dex = [f for f in names if f.endswith('.dex')]
            so  = [f for f in names if f.endswith('.so')]
            result['dex_count'] = len(dex)
            result['dex_files'] = ', '.join(dex)
            result['has_native_libs'] = len(so) > 0
            result['native_libs'] = ', '.join([os.path.basename(f) for f in so[:8]])
            archs = set()
            for f in so:
                parts = f.split('/')
                if len(parts)>=2: archs.add(parts[1])
            result['native_archs'] = ', '.join(sorted(archs))
            unusual = [f for f in names
                       if not any(f.startswith(p) for p in expected)
                       and f not in ('resources.arsc','AndroidManifest.xml')]
            result['unusual_entry_count'] = len(unusual)
            result['unusual_entries'] = ', '.join(unusual[:10])
        with open(apk_path,'rb') as f: data = f.read()
        has_v2v3 = b'APK Sig Block 42' in data
        with ZipFile(apk_path) as z:
            meta = z.namelist()
            has_v1 = any(f.endswith(('.SF','.RSA','.DSA')) for f in meta if f.startswith('META-INF/'))
        if has_v2v3 and has_v1:  result['signing_scheme'] = 'v1+v2/v3 (modern)'
        elif has_v2v3:            result['signing_scheme'] = 'v2/v3 only'
        elif has_v1:              result['signing_scheme'] = 'v1 only (suspicious)'
        else:                     result['signing_scheme'] = 'unsigned/unknown'
    except Exception as e: result['unusual_entries'] = f"Error:{e}"
    return result

def summarize_iocs(x):
    if not isinstance(x,list) or not x: return 'No keywords detected'
    kws = []
    for item in x:
        if ': ' in item:
            for p in item.split(': ',1)[1].split(', '):
                if ' (' in p or '(' in p: kws.append(p.split('(')[0].strip())
    if not kws: return 'No keywords detected'
    cnt = Counter(kws)
    top = cnt.most_common(6)
    return f"Top: {', '.join([f'{k}({c}x)' for k,c in top])} | Entries: {len(x)}"

# ─────────────────────────────────────────────────────────
# STEP 1 — STATIC ANALYSIS
# ─────────────────────────────────────────────────────────
def run_static_analysis():
    header()
    section_rule("STEP 1 — STATIC ANALYSIS")
    issues = validate_setup()
    if issues:
        for i in issues: err(i)
        pause(); return

    ready = [s for s in STATE["samples"]
             if os.path.exists(s["apk"]) and os.path.exists(s["decompiled"])]
    info(f"Analyzing [bold #2DC653]{len(ready)}[/] samples...")
    console.print()

    results = []
    with Progress(
        SpinnerColumn(style="#00B4D8"),
        TextColumn("[bold #00B4D8]{task.description}"),
        BarColumn(bar_width=40, style="#0077A8", complete_style="#00B4D8"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing samples...", total=len(ready))
        for s in ready:
            progress.update(task, description=f"Analyzing [bold]{s['name']}[/]...")
            manifest = os.path.join(s["decompiled"], 'AndroidManifest.xml')
            perms  = extract_permissions(manifest)
            comps  = find_components(manifest)
            iocs   = scan_iocs(s["apk"])
            obf_c, obf_s = detect_obfuscation(s["apk"])
            struct = check_apk_structure(s["apk"])
            results.append({
                'apk_file': s["name"],
                'permissions': perms,
                'components': comps,
                'suspicious_strings': iocs,
                'permissions_count': len(perms),
                'services_count': len(comps.get('services',[])),
                'receivers_count': len(comps.get('receivers',[])),
                'suspicious_strings_count': len(iocs),
                'dangerous_permissions_count': sum(1 for p in perms if p in DANGEROUS_PERMS),
                'dangerous_permissions_list': ', '.join([p.split('.')[-1] for p in perms if p in DANGEROUS_PERMS]) or 'None',
                'obfuscated_res_files_count': obf_c,
                'obfuscation_indicators': obf_s,
                'suspicious_strings_summary': summarize_iocs(iocs),
                **struct
            })
            progress.advance(task)

    if results:
        df = pd.DataFrame(results)
        df.to_csv(STATE["csv_path"], index=False, encoding='utf-8')

        # Print results table
        console.print()
        t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
                  show_lines=True, title="[bold white]Static Analysis Results[/]", padding=(0,1))
        t.add_column("Sample",        style="bold white",   width=16)
        t.add_column("Perms",         justify="center",     width=7)
        t.add_column("Dangerous",     justify="center",     width=10)
        t.add_column("Services",      justify="center",     width=9)
        t.add_column("Obfusc Files",  justify="center",     width=12)
        t.add_column("Dex Count",     justify="center",     width=10)
        t.add_column("Signing",       width=18)
        t.add_column("Native Libs",   justify="center",     width=11)
        for r in results:
            dp = r['dangerous_permissions_count']
            obf = r['obfuscated_res_files_count']
            t.add_row(
                r['apk_file'],
                str(r['permissions_count']),
                f"[{'#E63946' if dp>=10 else '#F4A261' if dp>=5 else 'white'}]{dp}[/]",
                str(r['services_count']),
                f"[{'#E63946' if obf>=20 else '#F4A261' if obf>=8 else 'white'}]{obf}[/]",
                f"[{'#F4A261' if r['dex_count']>1 else 'white'}]{r['dex_count']}[/]",
                f"[{'#F4A261' if 'v1 only' in r['signing_scheme'] else 'white'}]{r['signing_scheme']}[/]",
                "[#2DC653]Yes[/]" if r['has_native_libs'] else "[dim]No[/]",
            )
        console.print(t)
        STATE["steps_done"].add(1)
        done_panel(f"Static analysis complete — {len(results)} samples saved to CSV")
    else:
        err("No samples analyzed. Check paths in Sample Manager.")
    pause()

# ─────────────────────────────────────────────────────────
# STEP 2 — SEMGREP PARSER
# ─────────────────────────────────────────────────────────
def run_semgrep_parser():
    header()
    section_rule("STEP 2 — SEMGREP RESULTS PARSER")
    if not STATE["semgrep_json"] or not os.path.exists(STATE["semgrep_json"]):
        err("semgrep_results.json not found.")
        console.print()
        info("Run Semgrep first in WSL:")
        console.print(Panel(
            "semgrep --config spyware_rules.yaml /path/to/decompiled/\n"
            "        --json --output semgrep_results.json",
            border_style="#0077A8", style="dim", padding=(0,2)
        ))
        info("Then set the path via [bold]Sample Manager → Set Semgrep JSON path[/]")
        pause(); return
    if not os.path.exists(STATE["csv_path"]):
        err("Master CSV not found. Run Step 1 first."); pause(); return

    with Progress(SpinnerColumn(style="#00B4D8"),
                  TextColumn("[bold #00B4D8]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Parsing Semgrep results...", total=None)
        with open(STATE["semgrep_json"],'r',encoding='utf-8') as f:
            data = json.load(f)
        progress.update(task, description="Aggregating rule hits per sample...")
        sample_hits = defaultdict(lambda: defaultdict(int))
        for result in data.get("results",[]):
            path = result["path"].replace("\\","/")
            parts = path.split("/")
            sample = parts[parts.index("sources")-1] if "sources" in parts else parts[-2]
            rule_id = result["check_id"].split(".")[-1]
            sample_hits[sample][rule_id] += 1
        hits_df = pd.DataFrame(sample_hits).T.fillna(0).astype(int)
        hits_df.index.name = "sample_name"
        hits_df.reset_index(inplace=True)
        rule_cols = [c for c in hits_df.columns if c != "sample_name"]
        hits_df["semgrep_total_hits"] = hits_df[rule_cols].sum(axis=1)
        progress.update(task, description="Merging into master CSV...")
        df = pd.read_csv(STATE["csv_path"])
        df["sample_name"] = df["apk_file"].apply(lambda x: os.path.splitext(x)[0])
        merged = df.merge(hits_df, on="sample_name", how="left")
        merged.drop(columns=["sample_name"], inplace=True)
        merged.to_csv(STATE["csv_path"], index=False, encoding='utf-8')

    console.print()
    t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
              show_lines=True, title="[bold white]Semgrep Hits Per Sample[/]", padding=(0,1))
    t.add_column("Sample",    style="bold white", width=15)
    for col in rule_cols[:8]: t.add_column(col[:12], justify="center", width=9)
    t.add_column("TOTAL", justify="center", style="bold #00B4D8", width=7)
    for _, row in hits_df.iterrows():
        vals = [str(int(row.get(c,0))) for c in rule_cols[:8]]
        total = int(row.get("semgrep_total_hits",0))
        colored = [f"[{'#E63946' if int(v)>=20 else '#F4A261' if int(v)>=10 else 'white'}]{v}[/]" for v in vals]
        t.add_row(str(row["sample_name"]), *colored,
                  f"[{'#E63946' if total>=40 else '#F4A261' if total>=20 else 'white'}]{total}[/]")
    console.print(t)
    STATE["steps_done"].add(2)
    done_panel("Semgrep results merged into master CSV")
    pause()

# ─────────────────────────────────────────────────────────
# STEP 3 — STEALTH SCORING
# ─────────────────────────────────────────────────────────
def calculate_stealth_score(row):
    score = 0; reasons = []
    dp = row.get('dangerous_permissions_count',0)
    if dp>=10: score+=2; reasons.append(f"very high dangerous perms({dp})")
    elif dp>=6: score+=1; reasons.append(f"high dangerous perms({dp})")
    obf = row.get('obfuscated_res_files_count',0)
    if obf>=20: score+=2; reasons.append(f"heavy obfuscation({obf} files)")
    elif obf>=8: score+=1; reasons.append(f"moderate obfuscation({obf} files)")
    comps = str(row.get('components',''))
    if 'BOOT_COMPLETED' in comps or 'boot' in comps.lower():
        score+=1; reasons.append("boot persistence")
    if row.get('services_count',0)>=5:
        score+=1; reasons.append(f"many services({row['services_count']})")
    if row.get('emulator-detection',0)>=1:
        score+=1; reasons.append("emulator detection")
    if row.get('socket-connection',0)>=1 or row.get('http-post-data',0)>=3:
        score+=1; reasons.append("C2 communication patterns")
    surv = (row.get('audio-record',0)+row.get('camera-capture',0)+
            row.get('gps-location-request',0)+row.get('call-log-access',0))
    if surv>=10: score+=2; reasons.append(f"heavy surveillance({surv} hits)")
    elif surv>=4: score+=1; reasons.append(f"moderate surveillance({surv} hits)")
    if 'accessibility' in comps.lower():
        score+=1; reasons.append("accessibility service abuse")
    components = row.get('components',{})
    if isinstance(components,str):
        try: components = ast.literal_eval(components)
        except: components = {}
    all_c = (components.get('services',[])+components.get('receivers',[])+components.get('activities',[]))
    unnamed = sum(1 for c in all_c if 'Unnamed' in str(c))
    if unnamed>=3: score+=1; reasons.append(f"unnamed components({unnamed})")
    perms = row.get('permissions',[])
    if isinstance(perms,str):
        try: perms = ast.literal_eval(perms)
        except: perms = []
    if len(perms)==0 and row.get('semgrep_total_hits',0)>=10:
        score+=1; reasons.append("zero perms + high API activity — Accessibility abuse")
    return min(score,10), '; '.join(reasons)

def score_bar(score):
    filled = int(score)
    empty  = 10 - filled
    color  = "#E63946" if score>=8 else "#F4A261" if score>=6 else "#00B4D8"
    return f"[{color}]{'█'*filled}[/][dim]{'░'*empty}[/] [{color}]{score}/10[/]"

def run_stealth_scoring():
    header()
    section_rule("STEP 3 — STEALTH SCORE CALCULATION")
    if not os.path.exists(STATE["csv_path"]):
        err("Master CSV not found. Run Steps 1 and 2 first."); pause(); return

    with Progress(SpinnerColumn(style="#00B4D8"),
                  TextColumn("[bold #00B4D8]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Calculating stealth scores...", total=None)
        df = pd.read_csv(STATE["csv_path"])
        df['stealth_score'], df['stealth_reasons'] = zip(*df.apply(calculate_stealth_score, axis=1))
        df.to_csv(STATE["csv_path"], index=False, encoding='utf-8')

    console.print()
    t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
              show_lines=True, title="[bold white]Stealth Scores[/]", padding=(0,1))
    t.add_column("Sample",       style="bold white",  width=16)
    t.add_column("Score",        width=28)
    t.add_column("Primary Reasons", style="dim #8B9DB0", width=55)

    for _, row in df.sort_values('stealth_score', ascending=False).iterrows():
        score = row.get('stealth_score',0)
        reasons = str(row.get('stealth_reasons',''))
        short_reasons = reasons[:52] + "..." if len(reasons) > 52 else reasons
        t.add_row(row['apk_file'], score_bar(score), short_reasons)
    console.print(t)
    STATE["steps_done"].add(3)
    done_panel("Stealth scores calculated and saved")
    pause()

# ─────────────────────────────────────────────────────────
# STEP 4 — VISUALIZATIONS
# ─────────────────────────────────────────────────────────
TEAL="#00B4D8"; RED="#E63946"; AMBER="#F4A261"; GREEN="#2DC653"
NAVY="#0D1B2A"; WHITE_C="#FFFFFF"; GRAY_C="#8B9DB0"
PLOT_THEME = {
    'figure.facecolor':NAVY,'axes.facecolor':'#1B2A3E','axes.edgecolor':'#243447',
    'axes.labelcolor':'#CDD5E0','text.color':'#CDD5E0','xtick.color':'#8B9DB0',
    'ytick.color':'#8B9DB0','grid.color':'#243447','grid.linewidth':0.5,
    'font.family':'DejaVu Sans',
}

def sc(s):
    if s>=8: return RED
    if s>=6: return AMBER
    if s>=4: return TEAL
    return GREEN

def run_visualizations():
    header()
    section_rule("STEP 4 — VISUALIZATIONS")
    if not os.path.exists(STATE["csv_path"]):
        err("Master CSV not found. Run previous steps first."); pause(); return

    vis_dir = os.path.join(STATE["output_dir"], "visualizations")
    os.makedirs(vis_dir, exist_ok=True)
    df = pd.read_csv(STATE["csv_path"])
    df['sample'] = df['apk_file'].str.replace('.apk','',regex=False)
    plt.rcParams.update(PLOT_THEME)

    charts = [
        ("Stealth Score Bar Chart",        "01_stealth_scores.png"),
        ("Dangerous Permissions Heatmap",  "02_permissions_heatmap.png"),
        ("Semgrep Hits Heatmap",           "03_semgrep_heatmap.png"),
        ("Threat Profile Radar Chart",     "04_radar_chart.png"),
        ("Obfuscation vs Stealth Scatter", "05_obfuscation_scatter.png"),
    ]

    with Progress(
        SpinnerColumn(style="#00B4D8"),
        TextColumn("[bold #00B4D8]{task.description}"),
        BarColumn(bar_width=35, style="#0077A8", complete_style="#00B4D8"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating charts...", total=len(charts))

        # Chart 1
        progress.update(task, description=f"[bold]{charts[0][0]}[/]...")
        fig, ax = plt.subplots(figsize=(12,6)); fig.patch.set_facecolor(NAVY); ax.set_facecolor('#1B2A3E')
        sdf = df.sort_values('stealth_score', ascending=True)
        bars = ax.barh(sdf['sample'].tolist(), sdf['stealth_score'].tolist(),
                       color=[sc(s) for s in sdf['stealth_score'].tolist()], height=0.6, zorder=3)
        for bar, score in zip(bars, sdf['stealth_score'].tolist()):
            ax.text(bar.get_width()+0.1, bar.get_y()+bar.get_height()/2,
                    f'{score}/10', va='center', ha='left', color=WHITE_C, fontsize=12, fontweight='bold')
        ax.set_xlim(0,12); ax.set_xlabel('Stealth Score',fontsize=12,color=GRAY_C,labelpad=10)
        ax.set_title('Stealth Score by Sample (0–10)',fontsize=16,fontweight='bold',color=WHITE_C,pad=20)
        ax.axvline(x=7,color=RED,linestyle='--',alpha=0.4,linewidth=1)
        ax.axvline(x=5,color=AMBER,linestyle='--',alpha=0.4,linewidth=1)
        ax.grid(axis='x',zorder=0); ax.set_axisbelow(True)
        patches=[mpatches.Patch(color=RED,label='Critical(8-10)'),mpatches.Patch(color=AMBER,label='High(6-7)'),mpatches.Patch(color=TEAL,label='Medium(4-5)')]
        ax.legend(handles=patches,loc='lower right',facecolor='#243447',edgecolor='#243447',labelcolor=WHITE_C,fontsize=10)
        plt.tight_layout(); plt.savefig(os.path.join(vis_dir,charts[0][1]),dpi=150,bbox_inches='tight'); plt.close()
        progress.advance(task)

        # Chart 2
        progress.update(task, description=f"[bold]{charts[1][0]}[/]...")
        DPERMS=['READ_SMS','SEND_SMS','RECEIVE_SMS','READ_CONTACTS','READ_CALL_LOG',
                'RECORD_AUDIO','CAMERA','ACCESS_FINE_LOCATION','ACCESS_BACKGROUND_LOCATION',
                'READ_PHONE_STATE','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE',
                'MANAGE_EXTERNAL_STORAGE','QUERY_ALL_PACKAGES','PACKAGE_USAGE_STATS',
                'BIND_NOTIFICATION_LISTENER_SERVICE','SYSTEM_ALERT_WINDOW','CALL_PHONE','WRITE_CONTACTS']
        perm_matrix = []
        for _, row in df.iterrows():
            try:
                perms = ast.literal_eval(str(row['permissions']))
                short = [p.split('.')[-1] for p in perms]
                perm_matrix.append([1 if p in short else 0 for p in DPERMS])
            except: perm_matrix.append([0]*len(DPERMS))
        fig, ax = plt.subplots(figsize=(18,6)); fig.patch.set_facecolor(NAVY); ax.set_facecolor(NAVY)
        cmap = LinearSegmentedColormap.from_list('custom',['#1B2A3E',TEAL],N=2)
        ax.imshow(perm_matrix,cmap=cmap,aspect='auto',vmin=0,vmax=1)
        ax.set_xticks(range(len(DPERMS))); ax.set_xticklabels(DPERMS,rotation=45,ha='right',fontsize=8,color=GRAY_C)
        ax.set_yticks(range(len(df))); ax.set_yticklabels(df['sample'].tolist(),fontsize=11,color=WHITE_C)
        for i in range(len(df)):
            for j in range(len(DPERMS)):
                if perm_matrix[i][j]: ax.text(j,i,'✓',ha='center',va='center',color=WHITE_C,fontsize=10,fontweight='bold')
        ax.set_title('Dangerous Permission Usage Across Samples',fontsize=15,fontweight='bold',color=WHITE_C,pad=15)
        for x in range(len(DPERMS)+1): ax.axvline(x-0.5,color='#243447',linewidth=0.5)
        for y in range(len(df)+1): ax.axhline(y-0.5,color='#243447',linewidth=0.5)
        plt.tight_layout(); plt.savefig(os.path.join(vis_dir,charts[1][1]),dpi=150,bbox_inches='tight'); plt.close()
        progress.advance(task)

        # Chart 3
        progress.update(task, description=f"[bold]{charts[2][0]}[/]...")
        SCOLS=['camera-capture','call-log-access','gps-location-request','http-post-data',
               'socket-connection','audio-record','emulator-detection','contacts-read','clipboard-access']
        SLABELS=['Camera','Call Log','GPS','HTTP POST','Socket','Audio Rec','Emulator','Contacts','Clipboard']
        s_matrix=[]
        for _, row in df.iterrows():
            s_matrix.append([int(row.get(c,0)) if pd.notna(row.get(c,0)) else 0 for c in SCOLS])
        max_val=max(max(r) for r in s_matrix) if s_matrix else 1
        fig, ax = plt.subplots(figsize=(14,6)); fig.patch.set_facecolor(NAVY); ax.set_facecolor(NAVY)
        cmap2=LinearSegmentedColormap.from_list('hits',['#1B2A3E','#0077A8',TEAL],N=256)
        im=ax.imshow(s_matrix,cmap=cmap2,aspect='auto',vmin=0,vmax=max_val)
        ax.set_xticks(range(len(SLABELS))); ax.set_xticklabels(SLABELS,rotation=30,ha='right',fontsize=10,color=GRAY_C)
        ax.set_yticks(range(len(df))); ax.set_yticklabels(df['sample'].tolist(),fontsize=11,color=WHITE_C)
        for i in range(len(df)):
            for j in range(len(SCOLS)):
                val=s_matrix[i][j]
                if val>0: ax.text(j,i,str(val),ha='center',va='center',color=WHITE_C,fontsize=11,fontweight='bold')
        ax.set_title('Semgrep Rule Hits by Behavior Category',fontsize=15,fontweight='bold',color=WHITE_C,pad=15)
        plt.colorbar(im,ax=ax,shrink=0.8).set_label('Hit Count',color=GRAY_C,fontsize=10)
        for x in range(len(SCOLS)+1): ax.axvline(x-0.5,color='#243447',linewidth=0.5)
        for y in range(len(df)+1): ax.axhline(y-0.5,color='#243447',linewidth=0.5)
        plt.tight_layout(); plt.savefig(os.path.join(vis_dir,charts[2][1]),dpi=150,bbox_inches='tight'); plt.close()
        progress.advance(task)

        # Chart 4
        progress.update(task, description=f"[bold]{charts[3][0]}[/]...")
        categories=['Dangerous\nPerms','Obfuscation\n(÷50)','Semgrep\nHits(÷5)','Services\nCount','Unusual\nEntries(÷60)','Stealth\nScore']
        def norm(v,mx): return min((v/mx)*10,10)
        radar_data=[]
        for _, row in df.iterrows():
            radar_data.append([norm(row.get('dangerous_permissions_count',0),15),norm(row.get('obfuscated_res_files_count',0),500),
                               norm(row.get('semgrep_total_hits',0),55),norm(row.get('services_count',0),10),
                               norm(row.get('unusual_entry_count',0),610),row.get('stealth_score',0)])
        N=len(categories); angles=[n/float(N)*2*np.pi for n in range(N)]+[0]
        colors_r=[RED,AMBER,TEAL,GREEN,'#A78BFA','#F472B6','#34D399']
        fig,ax=plt.subplots(figsize=(10,10),subplot_kw=dict(projection='polar'))
        fig.patch.set_facecolor(NAVY); ax.set_facecolor('#1B2A3E')
        for i,(rd,sample) in enumerate(zip(radar_data,df['sample'].tolist())):
            vals=rd+rd[:1]; color=colors_r[i%len(colors_r)]
            ax.plot(angles,vals,'o-',linewidth=2,color=color,label=sample); ax.fill(angles,vals,alpha=0.08,color=color)
        ax.set_xticks(angles[:-1]); ax.set_xticklabels(categories,size=11,color=WHITE_C)
        ax.set_ylim(0,10); ax.set_yticks([2,4,6,8,10]); ax.set_yticklabels(['2','4','6','8','10'],size=8,color=GRAY_C)
        ax.grid(color='#243447',linewidth=0.8); ax.spines['polar'].set_color('#243447')
        ax.set_title('APK Threat Profile — Radar Chart\n(All metrics normalized to 0-10)',size=14,fontweight='bold',color=WHITE_C,pad=30)
        ax.legend(loc='upper right',bbox_to_anchor=(1.35,1.15),facecolor='#243447',edgecolor='#243447',labelcolor=WHITE_C,fontsize=10)
        plt.tight_layout(); plt.savefig(os.path.join(vis_dir,charts[3][1]),dpi=150,bbox_inches='tight'); plt.close()
        progress.advance(task)

        # Chart 5
        progress.update(task, description=f"[bold]{charts[4][0]}[/]...")
        fig,ax=plt.subplots(figsize=(11,7)); fig.patch.set_facecolor(NAVY); ax.set_facecolor('#1B2A3E')
        offsets={'antidot':(10,-18),'brata':(-55,8),'clayrat':(-65,-18),'selfspy':(-55,25),'spymax':(-65,8),'spynote':(10,-18),'truthspy':(10,12)}
        for _,row in df.iterrows():
            obf=row.get('obfuscated_res_files_count',0); score=row.get('stealth_score',0)
            hits=row.get('semgrep_total_hits',0); name=row['sample']
            ax.scatter(obf,score,s=hits*15+80,color=sc(score),alpha=0.85,zorder=5,edgecolors=WHITE_C,linewidths=0.8)
            ox,oy=offsets.get(name,(10,8))
            ax.annotate(name,(obf,score),textcoords='offset points',xytext=(ox,oy),fontsize=10,color=WHITE_C,fontweight='bold',
                        arrowprops=dict(arrowstyle='-',color=GRAY_C,lw=0.8,alpha=0.5))
        ax.set_xlabel('Obfuscated Resource Files Count',fontsize=12,color=GRAY_C,labelpad=10)
        ax.set_ylabel('Stealth Score (0–10)',fontsize=12,color=GRAY_C,labelpad=10)
        ax.set_title('Obfuscation Level vs Stealth Score\n(Bubble size = Semgrep hits)',fontsize=14,fontweight='bold',color=WHITE_C,pad=15)
        ax.grid(True,zorder=0); ax.set_axisbelow(True)
        patches=[mpatches.Patch(color=RED,label='Critical(8-10)'),mpatches.Patch(color=AMBER,label='High(6-7)'),mpatches.Patch(color=TEAL,label='Medium(4-5)')]
        ax.legend(handles=patches,facecolor='#243447',edgecolor='#243447',labelcolor=WHITE_C,fontsize=10)
        plt.tight_layout(); plt.savefig(os.path.join(vis_dir,charts[4][1]),dpi=150,bbox_inches='tight'); plt.close()
        progress.advance(task)

    console.print()
    t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
              show_lines=False, padding=(0,1))
    t.add_column("#",     style="bold #A78BFA", width=4,  justify="center")
    t.add_column("Chart", style="bold white",   width=32)
    t.add_column("File",  style="dim #8B9DB0",  width=30)
    for i,(name,fname) in enumerate(charts):
        t.add_row(str(i+1), name, fname)
    console.print(t)
    STATE["steps_done"].add(4)
    done_panel(f"All 5 charts saved to {vis_dir}")
    pause()

# ─────────────────────────────────────────────────────────
# STEP 5 — DETECTION RULES
# ─────────────────────────────────────────────────────────
def run_detection_rules():
    header()
    section_rule("STEP 5 — DETECTION RULES GENERATOR")
    rules_dir = os.path.join(STATE["output_dir"], "detection_rules")
    os.makedirs(rules_dir, exist_ok=True)

    with Progress(SpinnerColumn(style="#00B4D8"),
                  TextColumn("[bold #00B4D8]{task.description}"),
                  BarColumn(bar_width=30, style="#0077A8", complete_style="#00B4D8"),
                  TextColumn("[bold white]{task.completed}/{task.total}"),
                  console=console) as progress:
        task = progress.add_task("Generating detection rules...", total=3)

        progress.update(task, description="Writing YARA rules...")
        yara_rules = '''/*
    Android Spyware Detection Rules
    Project: Hybrid Static-Dynamic Forensic Analysis
    Author: Yaswanth | NFSU | April 2026
    Rules: 6 (5 sample-specific + 1 generic heuristic)
*/

rule Antidot_Banking_Trojan {
    meta:
        description   = "Detects Antidot banking trojan"
        severity      = "CRITICAL"
        sha256        = "506033F7A6EA5C9E4D89F9EDCC998ED1F33FB74E4A2A4F32AF8CEC2EC009A906"
    strings:
        $pkg      = "com.wetpacd1d.psyd1d" ascii wide
        $c2_1     = "ping.ynrkone.top" ascii wide
        $c2_2     = "pip.uiimoss.top" ascii wide
        $overlay1 = "setupSamsungWindowLayout" ascii
        $overlay2 = "setupHuaWeiWindowLayout" ascii
        $overlay3 = "setupOPPOWindowLayout" ascii
        $vm       = "com/nmmedit/protect/NativeUtil" ascii
        $hide     = "hideEnable" ascii
    condition:
        uint32(0) == 0x04034b50 and
        ($pkg or any of ($c2_*) or (2 of ($overlay*)) or ($vm and $hide))
}

rule BraTA_Banking_Trojan_PhishingKit {
    meta:
        description = "Detects BraTA with embedded Mellat Bank phishing kit"
        severity    = "CRITICAL"
        sha256      = "C496DBB5813E2805F330AB487C66B6BBD3771C5267F9AA05366D576FDA0DCEFB"
    strings:
        $kit   = "Mellat.zip" ascii wide
        $token = "5339581065:AAEI3MvGuNmc2io57pk8vIQjIVN4PPIUiao" ascii
        $relay = "codex-team.tk" ascii wide
        $php1  = "connect.mellat.php" ascii
        $php2  = "sendotp.php" ascii
        $pkg   = "sh.abc.shabd" ascii wide
    condition:
        uint32(0) == 0x04034b50 and
        ($kit or $token or $relay or (2 of ($php*)) or $pkg)
}

rule ClayRAT_RAT {
    meta:
        description = "Detects ClayRAT via confirmed C2 domain"
        severity    = "HIGH"
        sha256      = "93893EBA96702F963B6E005E8B9AB046DAE883046C9673E8AC0CAA73194BFA74"
    strings:
        $c2    = "losthed.clay.rest" ascii wide
        $c2_ip = "64.188.83.172" ascii wide
    condition:
        uint32(0) == 0x04034b50 and ($c2 or $c2_ip)
}

rule SpyNote_RAT {
    meta:
        description = "Detects SpyNote RAT via package name and accessibility patterns"
        severity    = "HIGH"
        sha256      = "0A7337027340DED82BCD507ED6406B25C6F44CC58C646AF4EB332209F805B366"
    strings:
        $pkg = "com.appd.mercantil" ascii wide
        $acc = "android.accessibilityservice.AccessibilityService" ascii wide
    condition:
        uint32(0) == 0x04034b50 and ($pkg or $acc)
}

rule TruthSpy_Stalkerware {
    meta:
        description = "Detects TruthSpy via weaponized LAME MP3 encoder"
        severity    = "HIGH"
        sha256      = "41752E7B3D8374EC74B94EBC258A0FEFD3D41A44BB07A43D85546701AFB50E36"
    strings:
        $lame1 = "Java_com_naman14_androidlame_AndroidLame_lameEncode" ascii
        $lame2 = "Java_com_naman14_androidlame_AndroidLame_lameFlush" ascii
        $lame3 = "com/naman14/androidlame/AndroidLame" ascii wide
    condition:
        uint32(0) == 0x04034b50 and (2 of ($lame*))
}

rule Generic_Android_Spyware_Heuristic {
    meta:
        description    = "Heuristic detection for Android spyware"
        severity       = "MEDIUM"
        false_positive = "Legitimate accessibility apps, parental control software"
    strings:
        $boot    = "android.intent.action.BOOT_COMPLETED" ascii wide
        $sms     = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $acc     = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $tg_api  = "api.telegram.org/bot" ascii wide
        $su1     = "/system/bin/su" ascii
    condition:
        uint32(0) == 0x04034b50 and
        (($boot and ($sms or $overlay or $acc)) or
         $tg_api or (any of ($su*) and $overlay))
}
'''
        with open(os.path.join(rules_dir,"android_spyware_rules.yar"),'w',encoding='utf-8') as f:
            f.write(yara_rules)
        progress.advance(task)

        progress.update(task, description="Writing IOC master list...")
        ioc_list = """# Android Spyware IOC Master List
# Project: Hybrid Static-Dynamic Forensic Analysis | NFSU | April 2026

## MALICIOUS DOMAINS
ping.ynrkone.top                # Antidot C2 — confirmed malicious by ANY.RUN
pip.uiimoss.top                 # Antidot secondary C2
log-service-*.aliyuncs.com      # Antidot C2 logging (Alibaba Cloud)
losthed.clay.rest               # ClayRAT live C2 — Python Werkzeug
codex-team.tk                   # BraTA card relay API

## MALICIOUS IPs
147.139.146.211                 # Antidot C2 — Alibaba Cloud CN
147.139.146.209                 # Antidot C2 — Alibaba Cloud CN
147.139.146.144                 # Antidot C2 — Alibaba Cloud CN
64.188.83.172                   # ClayRAT C2

## PACKAGE NAMES
com.wetpacd1d.psyd1d            # Antidot — random-string disguise
com.appd.mercantil              # SpyNote — merchant app disguise
sh.abc.shabd                    # BraTA

## TELEGRAM BOT TOKEN
5339581065:AAEI3MvGuNmc2io57pk8vIQjIVN4PPIUiao  # BraTA phishing kit C2

## SERVER PATH (leaked via PHP error_log)
/home/icmmhitg/public_html/text1/Mellat/

## SHA256 HASHES
506033F7A6EA5C9E4D89F9EDCC998ED1F33FB74E4A2A4F32AF8CEC2EC009A906  # antidot.apk
C496DBB5813E2805F330AB487C66B6BBD3771C5267F9AA05366D576FDA0DCEFB  # brata.apk
93893EBA96702F963B6E005E8B9AB046DAE883046C9673E8AC0CAA73194BFA74  # clayrat.apk
0A7337027340DED82BCD507ED6406B25C6F44CC58C646AF4EB332209F805B366  # spynote.apk
41752E7B3D8374EC74B94EBC258A0FEFD3D41A44BB07A43D85546701AFB50E36  # truthspy.apk
"""
        with open(os.path.join(rules_dir,"ioc_master_list.txt"),'w',encoding='utf-8') as f:
            f.write(ioc_list)
        progress.advance(task)

        progress.update(task, description="Finalizing...")
        time.sleep(0.5)
        progress.advance(task)

    console.print()
    t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
              show_lines=False, padding=(0,1))
    t.add_column("File",        style="bold #00B4D8", width=35)
    t.add_column("Contents",   style="white",         width=42)
    t.add_column("Status",     style="bold",           width=10, justify="center")
    t.add_row("android_spyware_rules.yar", "6 YARA rules (5 specific + 1 heuristic)", "[#2DC653]Saved[/]")
    t.add_row("ioc_master_list.txt",       "5 domains, 4 IPs, 5 hashes, 1 token",    "[#2DC653]Saved[/]")
    console.print(t)
    STATE["steps_done"].add(5)
    done_panel(f"Detection rules saved to {rules_dir}")
    pause()

# ─────────────────────────────────────────────────────────
# STEP 6 — SUMMARY REPORT
# ─────────────────────────────────────────────────────────
def run_summary_report():
    header()
    section_rule("STEP 6 — ANALYSIS SUMMARY REPORT")
    if not os.path.exists(STATE["csv_path"]):
        err("Master CSV not found. Run previous steps first."); pause(); return

    df = pd.read_csv(STATE["csv_path"])

    # Overview panel
    total = len(df)
    avg_score = df['stealth_score'].mean() if 'stealth_score' in df.columns else 0
    critical  = len(df[df.get('stealth_score',pd.Series([0]*len(df)))>=8]) if 'stealth_score' in df.columns else 0
    total_hits = df['semgrep_total_hits'].sum() if 'semgrep_total_hits' in df.columns else 0

    stats = Table(box=box.ROUNDED, border_style="#0077A8", show_header=False, padding=(0,2))
    stats.add_column(style="bold #8B9DB0", width=22)
    stats.add_column(style="bold white",   width=15)
    stats.add_column(style="bold #8B9DB0", width=22)
    stats.add_column(style="bold white",   width=15)
    stats.add_row("Samples Analyzed",   f"[#00B4D8]{total}[/]",
                  "Avg Stealth Score",  f"[#F4A261]{avg_score:.1f}/10[/]")
    stats.add_row("Critical (≥8/10)",   f"[#E63946]{critical}[/]",
                  "Total Semgrep Hits", f"[#2DC653]{int(total_hits)}[/]")
    console.print(Panel(stats, title="[bold #00B4D8]Overview[/]",
                        border_style="#0077A8", padding=(0,1)))
    console.print()

    # Per-sample table
    t = Table(box=box.ROUNDED, border_style="#0077A8", header_style="bold #00B4D8",
              show_lines=True, title="[bold white]Per-Sample Findings[/]", padding=(0,1))
    t.add_column("Sample",      style="bold white",  width=16)
    t.add_column("Stealth",     width=26)
    t.add_column("Dang.Perms",  justify="center",   width=11)
    t.add_column("Obfusc",      justify="center",   width=8)
    t.add_column("Semgrep",     justify="center",   width=9)
    t.add_column("Dex",         justify="center",   width=5)
    t.add_column("Native",      justify="center",   width=8)
    t.add_column("Signing",     width=16)

    sort_col = 'stealth_score' if 'stealth_score' in df.columns else 'apk_file'
    for _, row in df.sort_values(sort_col, ascending=False).iterrows():
        score = row.get('stealth_score',0)
        dp    = row.get('dangerous_permissions_count',0)
        obf   = row.get('obfuscated_res_files_count',0)
        hits  = row.get('semgrep_total_hits',0)
        dex   = row.get('dex_count',1)
        nat   = row.get('has_native_libs',False)
        sign  = str(row.get('signing_scheme','?'))
        t.add_row(
            row['apk_file'],
            score_bar(score),
            f"[{'#E63946' if dp>=10 else '#F4A261' if dp>=5 else 'white'}]{dp}[/]",
            f"[{'#E63946' if obf>=20 else '#F4A261' if obf>=8 else 'white'}]{obf}[/]",
            f"[{'#E63946' if hits>=40 else '#F4A261' if hits>=20 else 'white'}]{int(hits) if pd.notna(hits) else 0}[/]",
            f"[{'#F4A261' if dex>1 else 'white'}]{dex}[/]",
            "[#2DC653]Yes[/]" if str(nat).lower() in ['true','yes'] else "[dim]No[/]",
            f"[{'#F4A261' if 'v1 only' in sign else 'white'}]{sign}[/]",
        )
    console.print(t)

    # Steps completed
    console.print()
    steps_t = Table(box=None, show_header=False, padding=(0,2))
    steps_t.add_column(width=6,  justify="center")
    steps_t.add_column(width=30)
    steps_t.add_column(width=12)
    for i, name in enumerate(["Static Analysis","Semgrep Parser","Stealth Scoring",
                               "Visualizations","Detection Rules"],1):
        done = i in STATE["steps_done"]
        steps_t.add_row(
            "[#2DC653]✔[/]" if done else "[dim]○[/]",
            name,
            "[#2DC653]Complete[/]" if done else "[dim]Pending[/]"
        )
    console.print(Panel(steps_t, title="[bold #00B4D8]Pipeline Status[/]",
                        border_style="#0077A8", padding=(0,1)))
    STATE["steps_done"].add(6)
    console.print()
    done_panel("Summary report complete")
    pause()

# ─────────────────────────────────────────────────────────
# RUN ALL
# ─────────────────────────────────────────────────────────
def run_all():
    header()
    section_rule("RUNNING COMPLETE PIPELINE")
    issues = validate_setup()
    if issues:
        for i in issues: err(i)
        pause(); return
    info("Running all steps sequentially...\n")
    for fn in [run_static_analysis, run_semgrep_parser, run_stealth_scoring,
               run_visualizations, run_detection_rules, run_summary_report]:
        fn()

# ─────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────
def main_menu():
    # First run setup prompt
    if not STATE["output_dir"]:
        header()
        section_rule("FIRST TIME SETUP")
        info("Welcome! Let's set up your output directory first.")
        console.print()
        path = Prompt.ask("  [bold]Output directory[/]",
                          default=r"D:\Major_Project\outputs").strip().strip('"')
        STATE["output_dir"] = path
        STATE["csv_path"] = os.path.join(path, "forensic_analysis_master.csv")
        os.makedirs(path, exist_ok=True)
        os.makedirs(os.path.join(path, "visualizations"), exist_ok=True)
        os.makedirs(os.path.join(path, "detection_rules"), exist_ok=True)
        ok(f"Output directory set: {path}")
        time.sleep(0.8)

    while True:
        header()

        # Status bar
        n_samples = len(STATE["samples"])
        n_ready   = sum(1 for s in STATE["samples"]
                        if os.path.exists(s["apk"]) and os.path.exists(s["decompiled"]))
        steps_done = len(STATE["steps_done"])

        status = Table(box=None, show_header=False, padding=(0,3))
        status.add_column(style="dim #8B9DB0", width=16)
        status.add_column(style="bold white",  width=12)
        status.add_column(style="dim #8B9DB0", width=16)
        status.add_column(style="bold white",  width=12)
        status.add_column(style="dim #8B9DB0", width=16)
        status.add_column(style="bold white",  width=12)
        status.add_row(
            "Samples loaded:",  f"[#00B4D8]{n_samples}[/]",
            "Ready to analyze:",f"[#2DC653]{n_ready}[/]",
            "Steps complete:",  f"[#A78BFA]{steps_done}/6[/]",
        )
        console.print(Panel(status, border_style="#243447", padding=(0,1)))
        console.print()

        # Menu
        t = Table(box=None, show_header=False, padding=(0,2))
        t.add_column(style="bold #00B4D8", width=6)
        t.add_column(style="bold white",   width=30)
        t.add_column(style="dim #8B9DB0",  width=48)

        menu_items = [
            ("S",  "Sample Manager",           "Add/remove samples · set paths · configure output"),
            None,
            ("1",  "Static Analysis",          "Permissions · IOC scanning · obfuscation · APK structure"),
            ("2",  "Semgrep Parser",            "Parse semgrep_results.json → merge into CSV"),
            ("3",  "Stealth Scoring",           "8-indicator scoring system (0–10 scale)"),
            ("4",  "Visualizations",            "Generate 5 publication-quality charts"),
            ("5",  "Detection Rules",           "Generate YARA rules + IOC master list"),
            ("6",  "Summary Report",            "Print full color-coded findings summary"),
            None,
            ("A",  "Run ALL Steps (1→6)",       "Execute complete pipeline from start to finish"),
            None,
            ("Q",  "Quit",                      ""),
        ]

        for item in menu_items:
            if item is None:
                t.add_row("", "", "")
                continue
            num, name, desc = item
            done_marker = " [#2DC653]✔[/]" if (num.isdigit() and int(num) in STATE["steps_done"]) else ""
            color = "#E63946" if num=="Q" else "#2DC653" if num=="A" else "#A78BFA" if num=="S" else "#00B4D8"
            t.add_row(f"[{color}][{num}][/]", f"{name}{done_marker}", desc)

        console.print(t)
        console.print()

        choice = Prompt.ask("  [bold #00B4D8]Enter choice[/]").strip().upper()

        if   choice == "S": sample_manager()
        elif choice == "1": run_static_analysis()
        elif choice == "2": run_semgrep_parser()
        elif choice == "3": run_stealth_scoring()
        elif choice == "4": run_visualizations()
        elif choice == "5": run_detection_rules()
        elif choice == "6": run_summary_report()
        elif choice == "A": run_all()
        elif choice == "Q":
            header()
            console.print(Panel(
                Align.center(
                    Text.from_markup(
                        "[bold #2DC653]Analysis session complete![/]\n\n"
                        f"[dim]Output directory: {STATE['output_dir']}[/]\n"
                        f"[dim]Steps completed:  {len(STATE['steps_done'])}/6[/]\n"
                        f"[dim]Samples analyzed: {len(STATE['samples'])}[/]"
                    )
                ),
                border_style="#2DC653",
                padding=(1,4),
            ))
            console.print()
            sys.exit(0)
        else:
            warn("Invalid choice.")
            time.sleep(0.8)

# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    main_menu()