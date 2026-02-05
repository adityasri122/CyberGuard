import math
import re

def analyze_password(password):
    """
    Analyzes a single password and returns its strength, score, and entropy.
    """
    if not password:
        return {
            "password": "",
            "strength_score": 0,
            "strength_verdict": "Empty",
            "entropy": 0.0
        }

    score, verdict = check_strength_heuristic(password)
    entropy = calculate_entropy(password)
    
    return {
        "password": password,
        "strength_score": score,
        "strength_verdict": verdict,
        "entropy": entropy
    }

def check_strength_heuristic(password):
    """
    Calculates a simple heuristic score and returns (score, verdict).
    """
    score = 0
    
    # 1. Length check
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
        
    # 2. Character type checks
    if re.search(r"[a-z]", password):  # Has lowercase
        score += 1
    if re.search(r"[A-Z]", password):  # Has uppercase
        score += 1
    if re.search(r"\d", password):     # Has digits
        score += 1
    if re.search(r"[^a-zA-Z0-9]", password): # Has special characters
        score += 1

    # 3. Determine verdict
    if score <= 2:
        verdict = "Very Weak"
    elif score <= 3:
        verdict = "Weak"
    elif score <= 4:
        verdict = "Moderate"
    elif score == 5:
        verdict = "Strong"
    else: # score == 6
        verdict = "Very Strong"
        
    return score, verdict

def calculate_entropy(password):
    """
    Calculates the Shannon entropy of the password in bits.
    Formula: H = L * log2(N)
    L = password length
    N = size of the character pool
    """
    if not password:
        return 0.0

    pool_size = 0
    
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"\d", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        # This is a common approximation for special chars
        pool_size += 32 
        
    if pool_size == 0:
        # Handle single-character-type passwords (e.g., "11111" or "aaaaa")
        if re.fullmatch(r"[a-z]+", password): pool_size = 26
        elif re.fullmatch(r"[A-Z]+", password): pool_size = 26
        elif re.fullmatch(r"\d+", password): pool_size = 10
        elif re.fullmatch(r"[^a-zA-Z0-9]+", password): pool_size = 32
        else: pool_size = 1 # Should not happen, but as a fallback
        
    # Calculate entropy
    try:
        entropy = len(password) * math.log2(pool_size)
    except ValueError:
        entropy = 0.0 # e.g., if pool_size is 0 or 1
        
    return round(entropy, 2)


# --- You can run this file directly to test it ---
if __name__ == "__main__":
    test_passwords = ["", "12345", "password", "Password123", "S3cureP@ssword!"]
    
    for p in test_passwords:
        report = analyze_password(p)
        print(f"--- Password: '{p}' ---")
        print(f"  Score:   {report['strength_score']}")
        print(f"  Verdict: {report['strength_verdict']}")
        print(f"  Entropy: {report['entropy']} bits\n")