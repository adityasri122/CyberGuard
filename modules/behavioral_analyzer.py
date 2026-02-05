import re
from collections import Counter
import datetime

# --- Pre-compile regex for common sequences ---
REGEX_SEQUENCES = {
    "3+ sequential digits (e.g., 123)": re.compile(r"012|123|234|345|456|567|678|789|890"),
    "3+ sequential letters (e.g., abc)": re.compile(r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz"),
    "3-char keyboard walk (e.g., qwe)": re.compile(r"qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm")
}

def analyze_reuse(password_list):
    """
    Counts how many times each password is used.
    Returns a dictionary: {password: count}
    """
    passwords = [p.get("password", "") for p in password_list if p.get("password")]
    return Counter(passwords)

def load_wordlist_set(wordlist_path):
    """
    Loads the rockyou.txt wordlist into a fast-lookup set.
    """
    print(f"Behavioral Analyzer: Loading wordlist from {wordlist_path}...")
    word_set = set()
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word_set.add(line.strip().lower()) # Store lowercase for easier matching
        print(f"Behavioral Analyzer: Loaded {len(word_set)} common words.")
    except Exception as e:
        print(f"Behavioral Analyzer: FAILED to load wordlist: {e}")
    return word_set

def check_personal_info(password, profile):
    """
    Checks if the password contains parts of the user's personal info.
    """
    patterns_found = []
    pass_lower = password.lower()
    
    # 1. Check for Name
    name = profile.get('name', '').lower()
    if name:
        # Split name into parts (e.g., "Piyush", "Ranjan", "Padhy")
        name_parts = name.split()
        for part in name_parts:
            if len(part) >= 3 and part in pass_lower:
                patterns_found.append("Contains Name")
                break
                
    # 2. Check for Date of Birth
    dob = profile.get('dob', '') # e.g., "2000-01-31"
    if dob:
        try:
            # Try to parse the date to get Y, M, D
            date_obj = datetime.datetime.strptime(dob, "%Y-%m-%d")
            dob_parts = [
                str(date_obj.year),      # 2000
                str(date_obj.month),     # 1
                str(date_obj.day),       # 31
                str(date_obj.year)[-2:], # 00
                f"{date_obj.month:02d}", # 01
                f"{date_obj.day:02d}"    # 31
            ]
            for part in dob_parts:
                if part in password:
                    patterns_found.append("Contains DOB")
                    break
        except ValueError:
            # If DOB is not in YYYY-MM-DD format, just check for the string
            if len(dob) >= 4 and dob in password:
                 patterns_found.append("Contains DOB")
            
    return patterns_found

def check_password_patterns(password, common_words_set, profile):
    """
    Checks a single password for common words, sequences, and patterns.
    """
    patterns_found = []
    pass_lower = password.lower()
    
    # 1. Check if it's a common word
    if pass_lower in common_words_set:
        patterns_found.append("Common Word")
        
    # 2. Check for sequences
    for name, regex in REGEX_SEQUENCES.items():
        if regex.search(pass_lower):
            patterns_found.append("Sequence/Keyboard Walk")
            break
            
    # 3. Check for personal info
    patterns_found.extend(check_personal_info(password, profile))
            
    return patterns_found