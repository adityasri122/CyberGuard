import os
from datetime import datetime

def generate_personal_wordlist(profile, save_path):
    """
    Generates a list of passwords based on user profile
    and saves it to save_path.
    """
    words = set()
    
    # 1. Get name parts
    name = profile.get('name', '').lower()
    if name:
        name_parts = name.split()
        for part in name_parts:
            if len(part) >= 3:
                words.add(part)
                words.add(part.capitalize())

    # 2. Get DOB parts
    dob = profile.get('dob', '') # e.g., "2000-01-31"
    dob_parts = []
    if len(dob) == 10 and dob[4] == '-' and dob[7] == '-':
        try:
            dt = datetime.strptime(dob, "%Y-%m-%d")
            dob_parts = [
                str(dt.year),      # 2000
                str(dt.month),     # 1
                str(dt.day),       # 31
                str(dt.year)[-2:], # 00
                f"{dt.month:02d}", # 01
                f"{dt.day:02d}",   # 31
                f"{dt.day:02d}{dt.month:02d}{str(dt.year)[-2:]}", # 310100
                f"{dt.day:02d}{dt.month:02d}{str(dt.year)}",     # 31012000
            ]
            words.update(dob_parts)
        except Exception as e:
            print(f"Error parsing DOB: {e}")

    # 3. Create combinations
    name_parts = name.split()
    combined_words = set(words) # Start with the base set
    for name_part in name_parts:
        if len(name_part) < 3: continue
        for dob_part in dob_parts:
            combined_words.add(name_part + dob_part)
            combined_words.add(name_part.capitalize() + dob_part)

    words.update(combined_words)
    
    # 4. Save to file
    try:
        with open(save_path, 'w', encoding='utf-8') as f:
            for word in words:
                f.write(word + "\n")
        print(f"Personal wordlist generated with {len(words)} words at {save_path}")
        return True
    except Exception as e:
        print(f"Failed to write personal wordlist: {e}")
        return False