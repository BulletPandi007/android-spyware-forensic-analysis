# ── Deep inspect Brata phishing kit ──────────────────────
from zipfile import ZipFile
import os

mellat_path = r"D:\Major_Project\extracted_payloads\brata\Mellat.zip"
kit_output  = r"D:\Major_Project\extracted_payloads\brata\mellat_kit"
os.makedirs(kit_output, exist_ok=True)

print("=== Brata Phishing Kit Analysis ===\n")

with ZipFile(mellat_path) as mz:
    mz.extractall(kit_output)
    print(f"Extracted all files to: {kit_output}\n")
    
    # ── Scan each PHP file for IOCs ───────────────────────
    ioc_keywords = [
        'telegram', 'bot', 'token', 'chat_id', 'sendmessage',
        'http', 'curl', 'file_get_contents', 'password',
        'otp', 'sms', 'card', 'account', 'mellat',
        '$_POST', '$_GET', 'mysql', 'database'
    ]
    
    php_files = [f for f in mz.namelist() if f.endswith('.php')]

print(f"PHP files found: {len(php_files)}\n")

for php_file in php_files:
    full_path = os.path.join(kit_output, php_file)
    if not os.path.exists(full_path):
        continue
    
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        found_keywords = [kw for kw in ioc_keywords 
                         if kw.lower() in content.lower()]
        
        # Extract any Telegram bot tokens (format: digits:alphanumeric)
        import re
        bot_tokens  = re.findall(r'\d{8,10}:[A-Za-z0-9_-]{35}', content)
        chat_ids    = re.findall(r'chat_id["\s]*[:=]["\s]*(-?\d+)', content)
        urls        = re.findall(r'https?://[^\s\'"<>]+', content)
        
        print(f"── {php_file} {'─'*(45-len(php_file))}")
        print(f"   Keywords : {', '.join(found_keywords) if found_keywords else 'none'}")
        if bot_tokens:
            print(f"   BOT TOKEN: {bot_tokens}")
        if chat_ids:
            print(f"   CHAT ID  : {chat_ids}")
        if urls:
            print(f"   URLs     : {urls[:5]}")
        print()

    except Exception as e:
        print(f"   Error reading {php_file}: {e}\n")

# ── Check error_log for server artifacts ─────────────────
error_log = os.path.join(kit_output, 'error_log')
if os.path.exists(error_log):
    print("── error_log (first 20 lines) ─────────────────────────")
    with open(error_log, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= 20: 
                break
            print(f"   {line.rstrip()}")