import requests
import time

# HIBP API v3 URL
HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
# We must send a User-Agent, HIBP requires it.
HEADERS = {
    "User-Agent": "CyberGuard-App",
    "hibp-api-key": "770df4a288e24ee3af3fa67b1929de7d" # <-- IMPORTANT, SEE NOTE BELOW
}
# Rate limit delay to be polite to the API
REQUEST_DELAY_SECONDS = 6.1 # (HIBP public API limit is ~1 request every 1.5s)

def check_email_breaches(email):
    """
    Checks a single email against the HIBP v3 API.
    Returns (breach_count, breach_names_string)
    """
    if not email or "@" not in email:
        return (0, "N/A (Not an email)")

    try:
        url = f"{HIBP_API_URL}{email}"
        response = requests.get(url, headers=HEADERS)
        
        # Add delay *after* the request
        time.sleep(REQUEST_DELAY_SECONDS) 

        if response.status_code == 200:
            # Success! Email was found in breaches.
            breaches = response.json() # This is a list of breach objects
            breach_count = len(breaches)
            # Get the first 3 breach names
            breach_names = ", ".join([b['Name'] for b in breaches[:3]])
            if breach_count > 3:
                breach_names += ", ..."
            return (breach_count, breach_names)
            
        elif response.status_code == 404:
            # Not found - this is a GOOD thing (no breaches)
            return (0, "No Breaches Found")
            
        elif response.status_code == 401:
            # Unauthorized - API key is missing or invalid
            return (-1, "HIBP API Key Error")

        else:
            # Other error (rate limit, server down, etc.)
            print(f"HIBP Error: {response.status_code}")
            return (-1, f"API Error {response.status_code}")

    except requests.RequestException as e:
        print(f"HIBP Request Failed: {e}")
        return (-1, "Request Failed")

# --- You can run this file directly to test it ---
if __name__ == "__main__":
    # Test with a known breached email
    test_email = "piyushrpadhy@gmail.com" # (Replace with your own for a test)
    print(f"Checking: {test_email}")
    count, names = check_email_breaches(test_email)
    print(f"  Count: {count}")
    print(f"  Names: {names}\n")
    
    # Test with a clean email
    test_email_clean = "a_clean_email_that_doesnt_exist@example.com"
    print(f"Checking: {test_email_clean}")
    count, names = check_email_breaches(test_email_clean)
    print(f"  Count: {count}")
    print(f"  Names: {names}\n")