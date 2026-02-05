from PySide6.QtCore import QThread, Signal
from modules.network_scanner import scan_local_network

class NetworkScanThread(QThread):
    """
    A worker thread for running the Nmap network scan.
    """
    # Signal: (list) -> (list_of_device_dicts)
    scan_complete = Signal(list)

    def __init__(self):
        super().__init__()
        self.is_running = True
        
    def run(self):
        """
        This is the function that runs on the new thread.
        """
        if not self.is_running:
            return
            
        results = scan_local_network()
        
        if self.is_running:
            self.scan_complete.emit(results)
        
    def stop(self):
        """Stops the thread."""
        self.is_running = False
        