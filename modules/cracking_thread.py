from PySide6.QtCore import QThread, Signal
from modules.cracking_sim import run_hashcat_simulation
from modules.password_analyzer import analyze_password

class CrackingThread(QThread):
    """
    A worker thread for running hashcat simulations in the background.
    """
    result_ready = Signal(int, str)

    def __init__(self, passwords, hashcat_path, wordlist_paths, temp_dir, force_crack=False):
        """
        --- UPDATED: Accepts a LIST of wordlist_paths ---
        """
        super().__init__()
        self.passwords = passwords
        self.hashcat_path = hashcat_path
        self.wordlist_paths = wordlist_paths # <-- This is now a list
        self.temp_dir = temp_dir
        self.force_crack = force_crack
        self.is_running = True

    def run(self):
        """
        This is the function that runs on the new thread.
        It now passes the list of wordlists to the simulation.
        """
        for i, login_data in enumerate(self.passwords):
            if not self.is_running:
                break

            password = login_data.get("password", "")
            
            if not password:
                result_message = "N/A (Empty)"
            else:
                report = analyze_password(password)
                verdict = report["strength_verdict"]
                
                if (not self.force_crack) and (verdict in ["Strong", "Very Strong"]):
                    result_message = "N/A (Skipped Strong)"
                else:
                    # --- UPDATED: Pass the list of paths ---
                    result_message = run_hashcat_simulation(
                        password,
                        self.hashcat_path,
                        self.wordlist_paths, # Pass the list
                        self.temp_dir,
                        attack_mode="hybrid"
                    )
            
            self.result_ready.emit(i, result_message)

    def stop(self):
        """Stops the thread."""
        self.is_running = False