from PySide6.QtCore import QThread, Signal
from modules.cracking_sim import run_hashcat_simulation

class CustomAttackThread(QThread):
    """
    A worker thread for running the targeted custom attack.
    """
    result_ready = Signal(int, str)

    def __init__(self, passwords, hashcat_path, wordlist_paths, temp_dir, attack_mode="dictionary"):
        """
        --- THIS IS THE FIX ---
        We now accept the 'attack_mode' argument
        --- END OF FIX ---
        """
        super().__init__()
        self.passwords = passwords
        self.hashcat_path = hashcat_path
        self.wordlist_paths = wordlist_paths
        self.temp_dir = temp_dir
        self.attack_mode = attack_mode # <-- And we store it
        self.is_running = True

    def run(self):
        """
        Runs a dictionary attack on ALL passwords
        using the provided wordlist_paths.
        """
        for i, login_data in enumerate(self.passwords):
            if not self.is_running:
                break

            password = login_data.get("password", "")
            
            if not password:
                result_message = "N/A (Empty)"
            else:
                # --- THIS IS THE SECOND FIX ---
                # We now pass the 'self.attack_mode' to the simulation
                result_message = run_hashcat_simulation(
                    password,
                    self.hashcat_path,
                    self.wordlist_paths, # Pass the list
                    self.temp_dir,
                    self.attack_mode # <-- Pass the correct attack mode
                )
                # --- END OF FIX ---
            
            self.result_ready.emit(i, result_message)

    def stop(self):
        """Stops the thread."""
        self.is_running = False