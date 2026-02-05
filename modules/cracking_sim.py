import hashlib
import subprocess
import time
import os
from pathlib import Path
import shutil 

def run_hashcat_simulation(password, hashcat_path, wordlist_paths, temp_dir, attack_mode="dictionary"):
    """
    Runs a hashcat dictionary attack.
    FIXED: Accepts a LIST of wordlists and uses relative paths.
    """
    if not password:
        return "N/A (Empty)"

    try:
        hash_str = hashlib.md5(password.encode()).hexdigest()
        hashcat_dir = hashcat_path.parent
        
        job_dir = hashcat_dir / f"temp_job_{hash_str}"
        os.makedirs(job_dir, exist_ok=True)

        hash_file_rel = f"temp_job_{hash_str}/hash.txt"
        potfile_rel = f"temp_job_{hash_str}/result.pot"
        
        with open(hashcat_dir / hash_file_rel, 'w') as f:
            f.write(hash_str + "\n")

        # --- Build the hashcat command ---
        cmd = [
            f".\\{hashcat_path.name}", 
            "-m", "0",
            "-a", "0",
            hash_file_rel,
            "--potfile-path", potfile_rel,
            "--quiet",
        ]
        
        # --- NEW: Add all wordlists from the list ---
        for wlist_path in wordlist_paths:
            cmd.append(f'"{wlist_path.resolve()}"')
            
        attack_desc = "(Dictionary Attack)"
        
        rule_file_path = Path("rules") / "best66.rule"
        
        if attack_mode == "hybrid" and (hashcat_dir / rule_file_path).exists():
            cmd.extend(["-r", str(rule_file_path)]) 
            attack_desc = "(Hybrid Attack)"
        elif attack_mode == "hybrid":
            print(f"HYBRID ATTACK FAILED: {rule_file_path} not found.")

        cmd_string = " ".join(cmd)
        
        print(f"DEBUG: Running command: {cmd_string}")
        print(f"DEBUG: Setting CWD to: {hashcat_dir}")

        start_time = time.time()
        result = subprocess.run(
            cmd_string, 
            capture_output=True, 
            text=True, 
            timeout=120, 
            cwd=hashcat_dir,
            shell=True # <-- This is the stable fix for [WinError 2]
        )
        duration = time.time() - start_time

        if result.stderr:
            print(f"DEBUG: hashcat stderr: {result.stderr.strip()}")

        cracked = False
        if (hashcat_dir / potfile_rel).exists():
            try:
                with open(hashcat_dir / potfile_rel, 'r') as f:
                    if hash_str in f.read():
                        cracked = True
            except Exception as e:
                print(f"Error reading potfile: {e}")

        try:
            shutil.rmtree(job_dir)
        except Exception as e:
            print(f"Warning: Could not clean up {job_dir}. Error: {e}")
        
        if cracked:
            return f"Cracked in {duration:.2f}s {attack_desc}"
        elif result.stderr and "No hashes loaded" not in result.stderr:
            return "Error (See console)"
        else:
            return f"Not Cracked {attack_desc}"

    except subprocess.TimeoutExpired:
        if 'job_dir' in locals() and os.path.exists(job_dir):
            shutil.rmtree(job_dir, ignore_errors=True)
        return "Not Cracked (Timeout)"
    except Exception as e:
        if 'job_dir' in locals() and os.path.exists(job_dir):
            shutil.rmtree(job_dir, ignore_errors=True)
        print(f"Python Error in hashcat: {e}")
        return f"Error (Python: {e})"