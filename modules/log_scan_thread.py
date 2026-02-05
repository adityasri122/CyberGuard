from PySide6.QtCore import QThread, Signal
from modules.log_analyzer import analyze_security_logs

class LogScanThread(QThread):
    """
    A worker thread for running the Windows Event Log scan.
    """
    # Signal: (list or str) -> (list_of_events or error_message)
    scan_complete = Signal(object) 

    def __init__(self):
        super().__init__()
        self.is_running = True
        
    def run(self):
        """
        This is the function that runs on the new thread.
        """
        if not self.is_running:
            return
            
        results = analyze_security_logs()
        
        if self.is_running:
            self.scan_complete.emit(results)
        
    def stop(self):
        """Stops the thread."""
        self.is_running = False