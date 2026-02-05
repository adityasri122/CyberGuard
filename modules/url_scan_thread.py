from PySide6.QtCore import QThread, Signal
from modules.url_scanner import analyze_url

class UrlScanThread(QThread):
    """
    A worker thread for running URL safety scans in the background.
    """
    # Signal: (int, str) -> (row_index, verdict_string)
    result_ready = Signal(int, str)

    def __init__(self, logins):
        super().__init__()
        self.logins = logins
        self.is_running = True
        
    def run(self):
        """
        This is the function that runs on the new thread.
        It checks every URL.
        """
        print(f"URL Scan Thread: Starting scan on {len(self.logins)} URLs.")
        
        for i, login_data in enumerate(self.logins):
            if not self.is_running:
                break # Stop if the user closes the app

            url = login_data.get("url", "")
            
            # Run the (potentially slow) analysis
            verdict = analyze_url(url)
            
            # Emit the result back to the main GUI thread
            self.result_ready.emit(i, verdict)
        
        print("URL Scan Thread: Scan complete.")

    def stop(self):
        """Stops the thread."""
        self.is_running = False