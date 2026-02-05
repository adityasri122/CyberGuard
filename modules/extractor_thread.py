from PySide6.QtCore import QThread, Signal
from modules.browser_extractor import extract_all_passwords

class ExtractorThread(QThread):
    """
    A worker thread for running the browser password
    extraction in the background.
    """
    # Signal: (list) -> (list_of_password_dicts)
    extraction_complete = Signal(list)

    def __init__(self):
        super().__init__()
        self.is_running = True

    def run(self):
        """
        This is the function that runs on the new thread.
        """
        try:
            # Run the slow extraction function
            all_logins = extract_all_passwords()
            
            # Emit the result back to the main GUI thread
            self.extraction_complete.emit(all_logins)
            
        except Exception as e:
            print(f"Error in extraction thread: {e}")
            self.extraction_complete.emit([]) # Emit empty list on error

    def stop(self):
        """Stops the thread."""
        self.is_running = False