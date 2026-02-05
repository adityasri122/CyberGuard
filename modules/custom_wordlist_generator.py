import os
from datetime import datetime

def _generate_from_profile(profile):
    """Generates password variations from the user's profile."""
    words = set()
    name_parts = []
    dob_parts = []
    
    # --- FIX: strip() all inputs ---
    name = profile.get('name', '').lower().strip()
    if name:
        name_parts = [p.strip() for p in name.split() if len(p.strip()) >= 3]
        for part in name_parts:
            words.add(part)
            words.add(part.capitalize())

    dob = profile.get('dob', '').strip()
    # --- END FIX ---
    
    if len(dob) == 10 and dob[4] == '-' and dob[7] == '-':
        try:
            dt = datetime.strptime(dob, "%Y-%m-%d")
            dob_parts = [
                str(dt.year), str(dt.month), str(dt.day),
                str(dt.year)[-2:], f"{dt.month:02d}", f"{dt.day:02d}",
                f"{dt.day:02d}{dt.month:02d}{str(dt.year)[-2:]}",
                f"{dt.day:02d}{dt.month:02d}{str(dt.year)}",
            ]
            words.update(dob_parts)
        except Exception as e:
            print(f"Error parsing DOB: {e}")
            
    return words, name_parts, dob_parts

def _generate_from_custom(custom_inputs):
    """Generates password variations from the user's custom inputs."""
    words = set()
    
    # --- FIX: strip() all inputs ---
    custom_words = [w.strip() for w in custom_inputs.get('words', '').split(',') if w.strip()]
    custom_nums = [n.strip() for n in custom_inputs.get('nums', '').split(',') if n.strip()]
    custom_syms = [s.strip() for s in custom_inputs.get('syms', '').split(',') if s.strip()]
    # --- END FIX ---

    for word in custom_words:
        words.add(word)
        words.add(word.lower())
        words.add(word.capitalize())
            
    words.update(custom_nums) # Add numbers as standalone
    
    return words, custom_words, custom_nums, custom_syms

def generate_custom_wordlist(profile, custom_inputs, save_path):
    """
    Generates a master wordlist from both profile and custom inputs,
    then saves it to a file.
    """
    
    profile_words_base, name_parts, dob_parts = _generate_from_profile(profile)
    custom_words_base, custom_words, custom_nums, custom_syms = _generate_from_custom(custom_inputs)
    
    final_wordlist = profile_words_base.union(custom_words_base)
    
    all_base_words = name_parts + custom_words
    all_base_nums = dob_parts + custom_nums
    
    # --- FIX: More thorough combinations ---
    for word in all_base_words:
        if len(word) < 3: continue
        
        for num in all_base_nums:
            final_wordlist.add(word + num)
            final_wordlist.add(word.capitalize() + num)
            
            for sym in custom_syms:
                final_wordlist.add(word + num + sym)
                final_wordlist.add(word.capitalize() + num + sym)
        
        for sym in custom_syms:
            final_wordlist.add(word + sym)
            final_wordlist.add(word.capitalize() + sym)
            
            # Add word + sym + num (for cases like "Wildasfuck@24")
            for num in all_base_nums:
                final_wordlist.add(word + sym + num)
                final_wordlist.add(word.capitalize() + sym + num)
    # --- END FIX ---

    try:
        with open(save_path, 'w', encoding='utf-8') as f:
            for w in final_wordlist:
                f.write(w + "\n")
        print(f"Custom wordlist generated with {len(final_wordlist)} words at {save_path}")
        return True
    except Exception as e:
        print(f"Failed to write custom wordlist: {e}")
        return False