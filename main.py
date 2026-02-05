import sys
import os
from pathlib import Path

# --- NEW: Suppress pyqtgraph debug message ---
import pyqtgraph as pg
pg.setConfigOption('crashWarning', False)
# --- END NEW ---

from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow

# --- CRITICAL: Path Configuration ---
def get_project_root():
    """Get the correct root path for both development and bundled .exe."""
    if getattr(sys, 'frozen', False):
        # We are running in a PyInstaller bundle
        return Path(sys._MEIPASS)
    else:
        # We are running as a normal script
        return Path(__file__).parent.resolve()

# --- Global Paths Object (UPDATED) ---
PATHS = {
    "PROJECT_ROOT": get_project_root(),
    "TOOLS_DIR": get_project_root() / "tools",
    "HASHCAT_DIR": get_project_root() / "tools" / "hashcat",
    "HASHCAT_PATH": get_project_root() / "tools" / "hashcat" / "hashcat.exe",
    # "NMAP_DIR": ... <--- REMOVED, as Nmap is a system dependency
    "WORDLIST_PATH": get_project_root() / "tools" / "wordlists" / "rockyou.txt",
    "DICTIONARY_PATH": get_project_root() / "tools" / "wordlists" / "words_alpha.txt"
}

# --- Application Entry Point ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Check if all our required files exist before launching
    if not PATHS["HASHCAT_PATH"].exists():
        print(f"FATAL ERROR: hashcat.exe not found at {PATHS['HASHCAT_PATH']}")
        # You could show a QMessageBox here
        sys.exit(1)
    if not PATHS["WORDLIST_PATH"].exists():
        print(f"FATAL ERROR: {PATHS['WORDLIST_PATH'].name} not found.")
        # You could show a QMessageBox here
        sys.exit(1)
    if not PATHS["DICTIONARY_PATH"].exists():
        print(f"FATAL ERROR: {PATHS['DICTIONARY_PATH'].name} not found.")
        # You could show a QMessageBox here
        sys.exit(1)

    window = MainWindow(paths=PATHS)
    window.show()
    
    sys.exit(app.exec())