import random
import re

# A simple map for 'leet-speak' replacements
LEET_MAP = {
    'a': '@', 'A': '@',
    'e': '3', 'E': '3',
    'i': '1', 'I': '1',
    'o': '0', 'O': '0',
    's': '$', 'S': '$',
    't': '7', 'T': '7',
}
SPECIAL_CHARS = "!@#$%^&*_+-="

def mutate_password(password):
    """
    Takes a weak password and applies mutations to suggest a stronger one.
    """
    if not password:
        return "NewPass!123" # Return a default strong password

    mutated = list(password) # Convert string to list of characters
    
    # 1. Apply Leet-Speak
    has_leeted = False
    for i, char in enumerate(mutated):
        if char in LEET_MAP and random.random() < 0.5: # 50% chance to replace
            mutated[i] = LEET_MAP[char]
            has_leeted = True

    # 2. Ensure it has at least one of each character type
    has_upper = any(c.isupper() for c in mutated)
    has_lower = any(c.islower() for c in mutated)
    has_digit = any(c.isdigit() for c in mutated)
    has_special = any(c in SPECIAL_CHARS or (c in LEET_MAP.values()) for c in mutated)

    if not has_upper and has_lower:
        # If no uppercase, capitalize a random lowercase letter
        idx = random.choice([i for i, c in enumerate(mutated) if c.islower()])
        mutated[idx] = mutated[idx].upper()
    elif not has_upper and not has_lower and not has_leeted:
        # No letters at all (e.g., "12345") - add one
        mutated.append(random.choice("Ab"))
        
    if not has_digit:
        mutated.append(random.choice("123"))
        
    if not has_special:
        mutated.append(random.choice(SPECIAL_CHARS))

    # 3. Ensure Minimum Length
    if len(mutated) < 10:
        padding_needed = 10 - len(mutated)
        for _ in range(padding_needed):
            mutated.append(random.choice("1a!")) # Add simple padding
            
    # Convert list back to string
    return "".join(mutated)


# --- You can run this file directly to test it ---
if __name__ == "__main__":
    test_passwords = ["password", "123456", "admin", "MyWeakPass123"]
    
    for p in test_passwords:
        suggestion = mutate_password(p)
        print(f"Original:  '{p}'")
        print(f"Suggested: '{suggestion}'\n")