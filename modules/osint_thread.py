from PySide6.QtCore import QThread, Signal
from modules.osint_scanner import check_email_breaches

class OsintThread(QThread):
    """
    A worker thread for running HIBP scans in the background.
    """
    # Signal: (int, int, str) -> (row_index, breach_count, breach_names)
    result_ready = Signal(int, int, str)

    def __init__(self, logins):
        super().__init__()
        self.logins = logins
        self.is_running = True
        
        # --- Collect unique emails ---
        self.unique_emails = {} # {email: [list of rows]}
        
        # --- NEW: Keep track of all rows ---
        self.all_row_indices = set(range(len(self.logins)))
        self.email_row_indices = set()
        
        for i, login in enumerate(self.logins):
            email = login.get("username", "")
            if "@" in email: # Only check if it looks like an email
                if email not in self.unique_emails:
                    self.unique_emails[email] = []
                self.unique_emails[email].append(i) # Store the row index
                self.email_row_indices.add(i) # Mark this row as an email
        
    def run(self):
        """
        This is the function that runs on the new thread.
        It only checks each unique email *once*.
        """
        print(f"OSINT Thread: Starting scan on {len(self.unique_emails)} unique emails.")
        
        for email, rows in self.unique_emails.items():
            if not self.is_running:
                break 

            # Run the slow API call
            count, names = check_email_breaches(email)
            
            # Emit the same result for all rows that use this email
            for row_index in rows:
                if not self.is_running:
                    break
                self.result_ready.emit(row_index, count, names)
        
        # --- THIS IS THE FIX ---
        # Now, go back and update all the rows that were NOT emails
        non_email_rows = self.all_row_indices - self.email_row_indices
        print(f"OSINT Thread: Updating {len(non_email_rows)} non-email rows...")
        
        for row_index in non_email_rows:
            if not self.is_running:
                break
            # Emit a "Not Applicable" result
            self.result_ready.emit(row_index, 0, "N/A (Not an email)")
        # --- END OF FIX ---
        
        print("OSINT Thread: Scan complete.")

    def stop(self):
        """Stops the thread."""
        self.is_running = False