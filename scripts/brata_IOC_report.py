# ── Brata IOC Documentation ───────────────────────────────
# Run this once to generate a structured IOC summary
# for inclusion in your final report
import os
ioc_report = {
    "sample": "brata.apk",
    "threat_type": "Banking Trojan + Phishing Kit",
    "target": "Mellat Bank (Iran) — Behpardakht payment gateway",
    "campaign_date": "2021-06-27 (from error_log timestamp)",
    "server_path": "/home/icmmhitg/public_html/text1/Mellat/",
    "server_timezone": "America/New_York",

    "c2_channels": [
        {
            "type": "Telegram Bot",
            "indicator": "5339581065:AAEI3MvGuNmc2io57pk8vIQjIVN4PPIUiao",
            "file": "telegram.php",
            "purpose": "Real-time victim data exfiltration"
        },
        {
            "type": "HTTP API",
            "indicator": "codex-team.tk/api/card2card.php",
            "file": "paymentresult.php, sendotp.php",
            "purpose": "Card data relay and OTP forwarding"
        },
        {
            "type": "HTTP API",
            "indicator": "ipb.parsian-bank.ir/mobileBank/1.0/getCardOwnerWithoutLogin",
            "file": "paymentresult.php, sendotp.php",
            "purpose": "Card owner lookup via legitimate bank API"
        }
    ],

    "data_stolen": [
        "Card number (PAN)",
        "Card PIN",
        "CVV2",
        "Expiry date",
        "OTP / 2FA codes",
        "First name, Last name",
        "Transaction amounts"
    ],

    "attack_chain": [
        "1. Brata APK installed on victim device",
        "2. APK uses SMS permissions to intercept OTP codes",
        "3. Mellat.zip phishing kit deployed to attacker C2 server",
        "4. Victim directed to fake Mellat Bank payment page",
        "5. Card credentials harvested via POST requests",
        "6. OTP intercepted from victim SMS by the APK",
        "7. Full credentials relayed to codex-team.tk",
        "8. Attacker notified in real-time via Telegram bot"
    ],

    "notable_artifacts": [
        "Test card 6666666666998858 found in error_log — kit was live-tested",
        "Server username 'icmmhitg' leaked via PHP error paths",
        "Farsi (Persian) UI confirms Iranian banking target",
        "echarge.ir and rayanertebat.ir referenced — Iranian payment services",
        "v1-only APK signing — consistent with older/rushed malware build"
    ]
}

# ── Print structured report ───────────────────────────────
print("=" * 60)
print(f"  IOC REPORT: {ioc_report['sample']}")
print("=" * 60)
print(f"  Threat type : {ioc_report['threat_type']}")
print(f"  Target      : {ioc_report['target']}")
print(f"  Campaign    : {ioc_report['campaign_date']}")
print(f"  Server path : {ioc_report['server_path']}")
print()

print("── C2 Channels ────────────────────────────────────────")
for c2 in ioc_report['c2_channels']:
    print(f"  [{c2['type']}]")
    print(f"    Indicator : {c2['indicator']}")
    print(f"    Source    : {c2['file']}")
    print(f"    Purpose   : {c2['purpose']}")
    print()

print("── Data Stolen ────────────────────────────────────────")
for item in ioc_report['data_stolen']:
    print(f"  • {item}")
print()

print("── Attack Chain ───────────────────────────────────────")
for step in ioc_report['attack_chain']:
    print(f"  {step}")
print()

print("── Notable Forensic Artifacts ─────────────────────────")
for artifact in ioc_report['notable_artifacts']:
    print(f"  • {artifact}")

# ── Save as JSON for your GitHub repo ────────────────────
import json
with open(r"D:\Major_Project\IOCs\brata_ioc_report.json", "w") as f:
    os.makedirs(r"D:\Major_Project\IOCs", exist_ok=True)
    json.dump(ioc_report, f, indent=2)
print("\n\nIOC report saved to D:\\Major_Project\\IOCs\\brata_ioc_report.json")