import re
import time
import requests
import requests_cache
from urllib.parse import urlparse

# --- Setup a cache for our web requests ---
# This saves results and prevents us from re-scanning the same URL
requests_cache.install_cache('url_scan_cache', backend='sqlite', expire_after=3600) # Cache for 1 hour

# --- PHISHTANK API (Optional) ---
# You can get a key from phishtank.com
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_API_KEY = "YOUR_API_KEY_HERE" # (We will leave this disabled)
USE_PHISHTANK = False # Set to True if you add a key

def check_phishing_patterns(url):
    """
    Checks for common regex patterns seen in phishing URLs.
    Returns a list of strings describing the red flags.
    """
    flags = []
    
    # 1. Typosquatting / Homograph (using numbers for letters)
    if re.search(r"[0-9][a-zA-Z]|[a-zA-Z][0-9]", urlparse(url).netloc.replace("www.", "")):
        if "192.168" not in url: # Ignore local IPs
            flags.append("Typosquatting (letters/numbers mixed)")

    # 2. Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.loan', '.work', '.click', '.link']
    if any(url.endswith(tld) for tld in suspicious_tlds):
        flags.append("Suspicious TLD")
        
    # 3. HTTP on a login page (we assume all saved passes are logins)
    if not url.startswith("https://"):
        flags.append("Insecure (HTTP)")
        
    # 4. IP Address instead of domain
    if re.match(r"^https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", url):
        if "192.168" not in url and "127.0.0.1" not in url:
            flags.append("URL is IP Address")
            
    return flags

def check_phishtank(url):
    """
    Checks a URL against the PhishTank API.
    Returns (True, "Site details") if a phish, (False, "") if not.
    """
    if not USE_PHISHTANK or PHISHTANK_API_KEY == "YOUR_API_KEY_HERE":
        return (False, "PhishTank (Skipped)")

    try:
        response = requests.post(PHISHTANK_API_URL, data={
            'url': url,
            'format': 'json',
            'app_key': PHISHTANK_API_KEY
        })
        
        # Be polite to API
        time.sleep(1.6) 

        if response.status_code == 200:
            data = response.json()
            if data.get('in_database') and data.get('verified') and data['valid']:
                return (True, "PhishTank (Confirmed)")
        
        return (False, "PhishTank (Clean)")

    except requests.RequestException as e:
        print(f"PhishTank Error: {e}")
        return (False, "PhishTank (Error)")

def analyze_url(url):
    """
    Runs all checks on a single URL and returns a risk verdict.
    """
    if not url:
        return "N/A (Empty)"
        
    # 1. Run pattern checks
    pattern_flags = check_phishing_patterns(url)
    
    # 2. Run API checks (if enabled)
    # is_phish, api_flag = check_phishtank(url)
    # if is_phish:
    #    pattern_flags.append(api_flag)
    
    # 3. Get domain age (This is slow, so we'll skip for this sprint)
    # try:
    #    domain = whois.whois(urlparse(url).netloc)
    #    if (datetime.now() - domain.creation_date).days < 180:
    #        pattern_flags.append("New Domain (< 6 months)")
    # except:
    #    pattern_flags.append("WHOIS Check Failed")
    
    # 4. Final Verdict
    if not pattern_flags:
        return "✔️ Safe"
    elif "Insecure (HTTP)" in pattern_flags and len(pattern_flags) == 1:
        return "⚠️ Insecure (HTTP)"
    else:
        # Return the top 2 flags
        return f"❌ Suspicious ({', '.join(pattern_flags[:2])})"

# --- You can run this file directly to test it ---
if __name__ == "__main__":
    test_urls = [
        "https://accounts.google.com/v3/signin/",
        "http://myaccount.goindigo.in/",
        "https://www.g00gle.com/login",
        "http://1.2.3.4/wp-admin/",
        "https://mybank.com.xyz/"
    ]
    
    for u in test_urls:
        print(f"Checking: {u}")
        verdict = analyze_url(u)
        print(f"  Verdict: {verdict}\n")