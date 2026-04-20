import json
import pandas as pd
from collections import defaultdict
import os

# ── Load Semgrep results ──────────────────────────────────
with open(r"D:\Major_Project\semgrep_results.json", "r",encoding="utf-8") as f:
    semgrep_data = json.load(f)

# ── Group hits by sample and rule ────────────────────────
sample_hits = defaultdict(lambda: defaultdict(int))

for result in semgrep_data.get("results", []):
    # Extract sample name from file path
    path = result["path"]
    parts = path.replace("\\", "/").split("/")
    
    # Sample folder is the parent of "sources/"
    if "sources" in parts:
        sample_name = parts[parts.index("sources") - 1]
    else:
        sample_name = parts[-2]  # fallback
    
    rule_id = result["check_id"].split(".")[-1]  # short rule name
    sample_hits[sample_name][rule_id] += 1

# ── Build a DataFrame from hits ───────────────────────────
hits_df = pd.DataFrame(sample_hits).T.fillna(0).astype(int)
hits_df.index.name = "sample_name"
hits_df.reset_index(inplace=True)

# Add a total hit count column
rule_cols = [c for c in hits_df.columns if c != "sample_name"]
hits_df["semgrep_total_hits"] = hits_df[rule_cols].sum(axis=1)

print("Semgrep hits per sample:")
print(hits_df.to_string(index=False))

# ── Merge with your existing Phase 1 CSV ─────────────────
phase1_df = pd.read_csv(r"D:\Major_Project\initial_forensic_analysis_readable.csv")

# Normalize sample name to match — strip extension
phase1_df["sample_name"] = phase1_df["apk_file"].apply(
    lambda x: os.path.splitext(x)[0]
)

merged_df = phase1_df.merge(hits_df, on="sample_name", how="left")
merged_df.drop(columns=["sample_name"], inplace=True)

# ── Save updated CSV ──────────────────────────────────────
output_path = r"D:\Major_Project\forensic_analysis_with_semgrep.csv"
merged_df.to_csv(output_path, index=False)
print(f"\nMerged CSV saved to: {output_path}")