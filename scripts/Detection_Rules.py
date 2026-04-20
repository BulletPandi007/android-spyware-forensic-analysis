# Detection_Rules.py
# Generates YARA rules and Semgrep signatures from confirmed findings
# Based on forensic_analysis_correlated.csv + IOC data

import os

output_dir = r"D:\Major_Project\detection_rules"
os.makedirs(output_dir, exist_ok=True)

# ─────────────────────────────────────────────────────────
# PART 1 — YARA RULES
# ─────────────────────────────────────────────────────────

yara_rules = '''
/*
    Android Spyware Detection Rules
    Project: Hybrid Static-Dynamic Forensic Analysis of Android Spyware
    Author: Yaswanth
    Date: April 2026
    Samples: Antidot, BraTA, ClayRAT, Selfspy, SpyMax, SpyNote, TruthSpy
*/

// ── Rule 1: Antidot Banking Trojan ───────────────────────
rule Antidot_Banking_Trojan
{
    meta:
        description    = "Detects Antidot banking trojan based on confirmed IOCs"
        author         = "Yaswanth"
        date           = "2026-04-07"
        severity       = "CRITICAL"
        sample_sha256  = "506033F7A6EA5C9E4D89F9EDCC998ED1F33FB74E4A2A4F32AF8CEC2EC009A906"
        family         = "Antidot"
        threat_type    = "Banking Trojan"
        source         = "Static + Dynamic Analysis (ANY.RUN)"

    strings:
        // Package name IOC — confirmed in sandbox
        $pkg          = "com.wetpacd1d.psyd1d" ascii wide

        // C2 domains confirmed malicious in sandbox
        $c2_1         = "ping.ynrkone.top" ascii wide
        $c2_2         = "pip.uiimoss.top" ascii wide
        $c2_3         = "aliyuncs.com" ascii wide

        // Manufacturer-specific overlay functions from Ghidra
        $overlay_1    = "setupSamsungWindowLayout" ascii
        $overlay_2    = "setupHuaWeiWindowLayout" ascii
        $overlay_3    = "setupOPPOWindowLayout" ascii
        $overlay_4    = "setupVivoWindowLayout" ascii
        $overlay_5    = "setupXiaomiWindowLayout" ascii

        // Native VM protection SDK
        $vm_protect   = "com/nmmedit/protect/NativeUtil" ascii

        // Stealth function from Ghidra
        $hide         = "hideEnable" ascii

        // Overlay utility class
        $float_win    = "com/cx/utils/FloatWindowUtils" ascii

    condition:
        uint32(0) == 0x04034b50  // ZIP magic (APK)
        and (
            $pkg or
            any of ($c2_*) or
            (2 of ($overlay_*)) or
            ($vm_protect and $hide) or
            ($float_win and any of ($overlay_*))
        )
}

// ── Rule 2: BraTA Banking Trojan + Phishing Kit ──────────
rule BraTA_Banking_Trojan_PhishingKit
{
    meta:
        description    = "Detects BraTA banking trojan with embedded Mellat Bank phishing kit"
        author         = "Yaswanth"
        date           = "2026-04-07"
        severity       = "CRITICAL"
        sample_sha256  = "C496DBB5813E2805F330AB487C66B6BBD3771C5267F9AA05366D576FDA0DCEFB"
        family         = "BraTA"
        threat_type    = "Banking Trojan + Phishing Kit"
        source         = "Static Analysis + Manual Kit Extraction"

    strings:
        // Embedded phishing kit filename
        $kit          = "Mellat.zip" ascii wide

        // PHP phishing kit C2
        $telegram_bot = "5339581065:AAEI3MvGuNmc2io57pk8vIQjIVN4PPIUiao" ascii

        // C2 relay endpoint
        $c2_relay     = "codex-team.tk" ascii wide

        // Target bank API used by phishing kit
        $bank_api     = "ipb.parsian-bank.ir" ascii wide

        // PHP kit files
        $php_1        = "connect.mellat.php" ascii
        $php_2        = "payment.mellat.php" ascii
        $php_3        = "sendotp.php" ascii
        $php_4        = "telegram.php" ascii

        // Server path leaked in error_log
        $server_path  = "icmmhitg" ascii

        // Package name confirmed in sandbox
        $pkg          = "sh.abc.shabd" ascii wide

        // v1-only signing indicator (in META-INF)
        $v1_sign      = "META-INF/CERT.SF" ascii

    condition:
        uint32(0) == 0x04034b50
        and (
            $kit or
            $telegram_bot or
            $c2_relay or
            (2 of ($php_*)) or
            ($server_path and $bank_api) or
            $pkg
        )
}

// ── Rule 3: ClayRAT Remote Access Trojan ─────────────────
rule ClayRAT_RAT
{
    meta:
        description    = "Detects ClayRAT based on confirmed C2 domain and behavioral IOCs"
        author         = "Yaswanth"
        date           = "2026-04-07"
        severity       = "HIGH"
        sample_sha256  = "93893EBA96702F963B6E005E8B9AB046DAE883046C9673E8AC0CAA73194BFA74"
        family         = "ClayRAT"
        threat_type    = "Remote Access Trojan"
        source         = "Static + Dynamic Analysis (ANY.RUN)"

    strings:
        // Live C2 domain confirmed in sandbox
        $c2           = "losthed.clay.rest" ascii wide

        // C2 IP confirmed malicious
        $c2_ip        = "64.188.83.172" ascii wide

        // Python Werkzeug C2 server fingerprint
        $werkzeug     = "Werkzeug" ascii wide

        // CRC communication strings found in static analysis
        $crc          = "CRC" ascii wide

    condition:
        uint32(0) == 0x04034b50
        and (
            $c2 or
            $c2_ip or
            ($werkzeug and $crc)
        )
}

// ── Rule 4: SpyNote RAT ───────────────────────────────────
rule SpyNote_RAT
{
    meta:
        description    = "Detects SpyNote RAT based on package name disguise and behavioral patterns"
        author         = "Yaswanth"
        date           = "2026-04-07"
        severity       = "HIGH"
        sample_sha256  = "0A7337027340DED82BCD507ED6406B25C6F44CC58C646AF4EB332209F805B366"
        family         = "SpyNote"
        threat_type    = "Remote Access Trojan"
        source         = "Static + Dynamic Analysis (ANY.RUN)"

    strings:
        // Package name disguised as payment app
        $pkg          = "com.appd.mercantil" ascii wide

        // Unicode filename evasion pattern (Arabic chars in filenames)
        $unicode_1    = { D9 AC DB A4 }   // Arabic Unicode sequence
        $unicode_2    = { DB 9C DB 96 }   // Arabic Unicode sequence

        // Zero declared permissions + accessibility abuse pattern
        $accessibility = "android.accessibilityservice.AccessibilityService" ascii wide

        // Known SpyNote/CypherRat family strings
        $family_1     = "SpyMax" ascii wide
        $family_2     = "CypherRat" ascii wide
        $family_3     = "SpyNote" ascii wide

    condition:
        uint32(0) == 0x04034b50
        and (
            $pkg or
            (any of ($unicode_*) and $accessibility) or
            any of ($family_*)
        )
}

// ── Rule 5: TruthSpy Stalkerware ─────────────────────────
rule TruthSpy_Stalkerware
{
    meta:
        description    = "Detects TruthSpy stalkerware — audio exfil via LAME MP3 encoder"
        author         = "Yaswanth"
        date           = "2026-04-07"
        severity       = "HIGH"
        sample_sha256  = "41752E7B3D8374EC74B94EBC258A0FEFD3D41A44BB07A43D85546701AFB50E36"
        family         = "TruthSpy"
        threat_type    = "Stalkerware / Commercial Spyware"
        source         = "Static + Ghidra Analysis"

    strings:
        // LAME MP3 encoder JNI bridge — weaponized for audio exfil
        $lame_1       = "Java_com_naman14_androidlame_AndroidLame_lameEncode" ascii
        $lame_2       = "Java_com_naman14_androidlame_AndroidLame_lameFlush" ascii
        $lame_3       = "Java_com_naman14_androidlame_AndroidLame_lameClose" ascii
        $lame_4       = "com/naman14/androidlame/AndroidLame" ascii wide

        // Crashlytics SDK used for C2 blending
        $crashlytics  = "com.crashlytics.sdk" ascii wide

        // Fabric analytics used for telemetry blending
        $fabric       = "fabric/com.crashlytics" ascii

    condition:
        uint32(0) == 0x04034b50
        and (
            (2 of ($lame_*)) or
            ($lame_4 and $crashlytics) or
            ($fabric and any of ($lame_*))
        )
}

// ── Rule 6: Generic Android Spyware Heuristic ────────────
rule Generic_Android_Spyware_Heuristic
{
    meta:
        description    = "Heuristic rule detecting common spyware patterns across all samples"
        author         = "Yaswanth"
        date           = "2026-04-07"
        severity       = "MEDIUM"
        threat_type    = "Android Spyware (Generic)"
        false_positive = "Legitimate accessibility apps, parental control software"
        source         = "Cross-sample static analysis patterns"

    strings:
        // Persistence via boot
        $boot         = "android.intent.action.BOOT_COMPLETED" ascii wide

        // SMS interception
        $sms          = "android.provider.Telephony.SMS_RECEIVED" ascii wide

        // Overlay permission
        $overlay      = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide

        // Accessibility abuse
        $accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide

        // Background location
        $bg_location  = "android.permission.ACCESS_BACKGROUND_LOCATION" ascii wide

        // Notification listener
        $notif        = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" ascii wide

        // Telegram C2 pattern
        $telegram_api = "api.telegram.org/bot" ascii wide

        // Root check patterns
        $su_1         = "/system/bin/su" ascii
        $su_2         = "/system/xbin/su" ascii

    condition:
        uint32(0) == 0x04034b50
        and (
            // Boot persistence + dangerous capability
            ($boot and ($sms or $overlay or $accessibility)) or

            // Telegram C2
            $telegram_api or

            // Multiple dangerous permissions
            (3 of ($sms, $overlay, $accessibility, $bg_location, $notif)) or

            // Root with network
            (any of ($su_*) and $overlay)
        )
}
'''

# Save YARA rules
yara_path = os.path.join(output_dir, "android_spyware_rules.yar")
with open(yara_path, 'w', encoding ='utf-8') as f:
    f.write(yara_rules)
print(f"YARA rules saved: {yara_path}")

# ─────────────────────────────────────────────────────────
# PART 2 — SEMGREP EXPORTABLE RULES (Updated + Extended)
# ─────────────────────────────────────────────────────────

semgrep_rules = '''rules:

  # ── Confirmed: Antidot overlay engine pattern ───────────
  - id: antidot-oem-overlay-setup
    patterns:
      - pattern: |
          void $FUNC(JNIEnv* $ENV, jobject $OBJ, jstring $STR, ...) { ... }
    message: "OEM-specific overlay setup function — pattern matches Antidot banking trojan"
    languages: [c]
    severity: ERROR
    metadata:
      confidence: HIGH
      sample: antidot
      confirmed_by: Ghidra native analysis

  # ── Confirmed: TruthSpy audio recording via LAME ────────
  - id: truthspy-lame-audio-exfil
    pattern: |
      $X = new AndroidLame();
    message: "AndroidLame instantiation — open-source MP3 encoder weaponized for audio exfiltration (TruthSpy pattern)"
    languages: [java]
    severity: ERROR
    metadata:
      confidence: HIGH
      sample: truthspy
      confirmed_by: Ghidra + Semgrep

  # ── Confirmed: Telegram bot C2 exfiltration ─────────────
  - id: telegram-bot-c2-exfil
    patterns:
      - pattern: $URL = "https://api.telegram.org/bot$TOKEN/sendMessage..."
    message: "Telegram bot API used for C2 data exfiltration — confirmed in BraTA phishing kit"
    languages: [java, php]
    severity: ERROR
    metadata:
      confidence: HIGH
      sample: brata
      confirmed_by: PHP phishing kit analysis

  # ── Confirmed: Accessibility service abuse ──────────────
  - id: accessibility-service-no-permissions
    pattern: |
      class $C extends AccessibilityService {
        public void onAccessibilityEvent(AccessibilityEvent $E) { ... }
      }
    message: "Accessibility service subclass — SpyNote pattern: zero declared permissions but full device surveillance"
    languages: [java]
    severity: ERROR
    metadata:
      confidence: MEDIUM
      sample: spynote
      false_positive: Legitimate accessibility apps

  # ── Confirmed: Dynamic class loading (VM protection) ────
  - id: dynamic-class-loading-evasion
    patterns:
      - pattern: DexClassLoader $X = new DexClassLoader(...)
      - pattern: $CL.loadClass($NAME)
    message: "Dynamic class loading detected — Antidot VM protection pattern, hides core logic from static analysis"
    languages: [java]
    severity: WARNING
    metadata:
      confidence: MEDIUM
      sample: antidot
      confirmed_by: Ghidra libnmmp.so analysis

  # ── Confirmed: Boot persistence ─────────────────────────
  - id: boot-persistence-receiver
    pattern: |
      class $C extends BroadcastReceiver {
        public void onReceive(Context $CTX, Intent $I) {
          ...
          $I.getAction().equals("android.intent.action.BOOT_COMPLETED")
          ...
        }
      }
    message: "BOOT_COMPLETED receiver — app persists across reboots. Confirmed in Antidot, ClayRAT, BraTA, TruthSpy"
    languages: [java]
    severity: ERROR
    metadata:
      confidence: HIGH
      samples: antidot, clayrat, brata, truthspy

  # ── Confirmed: Screen state check (banking trojan) ──────
  - id: screen-state-surveillance
    patterns:
      - pattern: $PM.isScreenOn()
      - pattern: $DM.isScreenOn()
    message: "Screen state check — banking trojans wait for victim interaction before activating overlay"
    languages: [java]
    severity: WARNING
    metadata:
      confidence: MEDIUM
      sample: antidot
      confirmed_by: ANY.RUN dynamic analysis

  # ── Confirmed: Device admin check ───────────────────────
  - id: device-admin-privilege-check
    pattern: $DPM.isAdminActive($COMPONENT)
    message: "Device admin status check — spyware confirms elevated privileges before acting"
    languages: [java]
    severity: ERROR
    metadata:
      confidence: HIGH
      sample: antidot
      confirmed_by: ANY.RUN behavioral analysis

  # ── Heuristic: Installed app enumeration ─────────────────
  - id: installed-app-enumeration
    pattern: $PM.getInstalledApplications(...)
    message: "Installed app enumeration — banking trojans scan for target banking apps to overlay"
    languages: [java]
    severity: WARNING
    metadata:
      confidence: MEDIUM
      samples: antidot, spynote

  # ── Heuristic: SMS + network = exfil risk ────────────────
  - id: sms-read-with-network
    patterns:
      - pattern: $X.query(Telephony.Sms.CONTENT_URI, ...)
    message: "SMS content provider query — combined with network access indicates exfiltration risk"
    languages: [java]
    severity: ERROR
    metadata:
      confidence: HIGH
      samples: brata, truthspy, spynote
'''

semgrep_path = os.path.join(output_dir, "android_spyware_semgrep.yaml")
with open(semgrep_path, 'w',encoding ='utf-8') as f:
    f.write(semgrep_rules)
print(f"Semgrep rules saved: {semgrep_path}")

# ─────────────────────────────────────────────────────────
# PART 3 — IOC MASTER LIST
# ─────────────────────────────────────────────────────────

ioc_list = """# Android Spyware IOC Master List
# Project: Hybrid Static-Dynamic Forensic Analysis
# Generated: April 2026
# ═══════════════════════════════════════════════════════

## NETWORK IOCs

### Confirmed Malicious Domains
ping.ynrkone.top                  # Antidot C2 — flagged malicious by ANY.RUN
pip.uiimoss.top                   # Antidot secondary C2 — unknown reputation
log-service-*.aliyuncs.com        # Antidot C2 logging — Alibaba Cloud CDN abuse
losthed.clay.rest                 # ClayRAT live C2 — Python Werkzeug server
codex-team.tk                     # BraTA card relay API

### Confirmed Malicious IPs
147.139.146.211                   # Antidot C2 — Alibaba Cloud (CN)
147.139.146.209                   # Antidot C2 — Alibaba Cloud (CN)
147.139.146.144                   # Antidot C2 — Alibaba Cloud (CN)
64.188.83.172                     # ClayRAT C2

### Suspicious Domains (Not Confirmed Malicious)
ipb.parsian-bank.ir               # BraTA phishing kit target API
echarge.ir                        # BraTA phishing kit referenced

## FILE IOCs

### Package Names (Confirmed in Sandbox)
com.wetpacd1d.psyd1d              # Antidot — disguised as random app
com.appd.mercantil                # SpyNote — disguised as merchant/payment app
sh.abc.shabd                      # BraTA — disguised as legitimate app

### File Hashes (SHA256)
506033F7A6EA5C9E4D89F9EDCC998ED1F33FB74E4A2A4F32AF8CEC2EC009A906  # antidot.apk
C496DBB5813E2805F330AB487C66B6BBD3771C5267F9AA05366D576FDA0DCEFB  # brata.apk
93893EBA96702F963B6E005E8B9AB046DAE883046C9673E8AC0CAA73194BFA74  # clayrat.apk
0A7337027340DED82BCD507ED6406B25C6F44CC58C646AF4EB332209F805B366  # spynote.apk
41752E7B3D8374EC74B94EBC258A0FEFD3D41A44BB07A43D85546701AFB50E36  # truthspy.apk

### Embedded Payload
Mellat.zip                        # BraTA embedded PHP phishing kit

## CREDENTIAL / TOKEN IOCs

### Telegram Bot Token (BraTA C2)
5339581065:AAEI3MvGuNmc2io57pk8vIQjIVN4PPIUiao

### Server Path (BraTA — leaked in error_log)
/home/icmmhitg/public_html/text1/Mellat/

## BEHAVIORAL IOCs

### Native Library Signatures
libx2.so + setupSamsungWindowLayout  # Antidot OEM overlay engine
libandroidlame.so + lameEncode       # TruthSpy audio exfil pipeline
libnmmp.so + vmInterpret             # Antidot VM code protection

### Semgrep Pattern Signatures
com/nmmedit/protect/NativeUtil       # Antidot VM protection SDK
com/cx/utils/FloatWindowUtils        # Antidot overlay utility
com/naman14/androidlame/AndroidLame  # TruthSpy audio encoder

### Structural Anomalies
- APK with >400 obfuscated res/*.xml files  → Antidot indicator
- APK with Unicode/Arabic filenames in r/   → SpyNote indicator
- APK containing embedded .zip PHP files    → BraTA indicator
- APK with 6+ dex files                    → Selfspy indicator
- v1-only APK signing                      → BraTA (Janus vulnerability)
"""

ioc_path = os.path.join(output_dir, "ioc_master_list.txt")
with open(ioc_path, 'w',encoding ='utf-8') as f:
    f.write(ioc_list)
print(f"IOC master list saved: {ioc_path}")

print("\n── Detection Rules Summary ─────────────────────────")
print("  YARA rules   : 6 rules (5 sample-specific + 1 generic heuristic)")
print("  Semgrep rules: 10 rules (7 confirmed + 3 heuristic)")
print("  IOC entries  : 5 domains, 4 IPs, 5 SHA256 hashes, 3 package names")
print(f"\nAll files saved to: {output_dir}")