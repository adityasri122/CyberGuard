import os
import shutil  # <-- ADDED
import webbrowser  # <-- ADDED
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit,
    QHeaderView, QFileDialog, QApplication, QTabWidget, QLabel,
    QLineEdit, QCheckBox, QComboBox, QFrame,
    QMessageBox  # <-- ADDED
)
from PySide6.QtCore import Slot, Qt
from PySide6.QtGui import QFont

# --- Import all our modules ---
from modules.password_analyzer import analyze_password
from modules.password_mutation import mutate_password
from modules.cracking_thread import CrackingThread
from modules.cleanup import secure_delete_folder
from modules.extractor_thread import ExtractorThread
from modules.osint_thread import OsintThread
from modules.url_scan_thread import UrlScanThread
from modules.network_scan_thread import NetworkScanThread
from modules.risk_scorer import calculate_overall_score
from modules.log_scan_thread import LogScanThread
from modules.report_generator import create_pdf_report
from modules.behavioral_analyzer import analyze_reuse, load_wordlist_set, check_password_patterns
from modules.visualizer import PasswordBarChart
from modules.educational_content import TOPICS
from modules.custom_wordlist_generator import generate_custom_wordlist
from modules.custom_attack_thread import CustomAttackThread

# --- NEW HELPER FUNCTION ---
def check_nmap_and_prompt(parent_widget):
    """
    Checks if Nmap is installed and in the system's PATH.
    
    If Nmap is found, returns True.
    If not, it shows a warning dialog to the user and returns False.
    
    :param parent_widget: The parent window (e.g., 'self' from your main window)
                          to attach the dialog box to.
    :return: True if Nmap is installed, False otherwise.
    """
    if shutil.which("nmap") is not None:
        # Nmap is found in the system PATH
        print("Nmap is installed and ready.")
        return True
    else:
        # Nmap is not found
        print("[ERROR] Nmap executable not found in system PATH.")
        
        # Create a warning dialog box
        msg = QMessageBox(parent_widget)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Nmap Not Found")
        msg.setText("<b>Network Scanner requires Nmap to function.</b>")
        msg.setInformativeText(
            "Please download and install Nmap from nmap.org.\n\n"
            "<b>Important:</b> During installation, make sure to check the "
            "option to 'Add nmap to system PATH'.\n\n"
            "The network scanner will not work until Nmap is installed correctly "
            "and you restart this application."
        )
        
        # Add a "Go to Download Page" button and a standard "OK" button
        msg.setStandardButtons(QMessageBox.Ok)
        download_button = msg.addButton("Go to nmap.org", QMessageBox.ActionRole)
        
        msg.exec_()
        
        # If the user clicked the custom download button
        if msg.clickedButton() == download_button:
            webbrowser.open_new_tab("https://nmap.org/download.html")
            
        return False
# --- END OF HELPER FUNCTION ---


class MainWindow(QMainWindow):
    """Main application window class."""

    def __init__(self, paths):
        super().__init__()
        self.setWindowTitle("CyberGuard - Personal Threat Dashboard")
        self.resize(1800, 800)
        self.paths = paths
        
        self.loaded_passwords = []
        self.network_devices = []
        self.log_events = []
        self.current_risk_report = {}
        self.common_words_set = load_wordlist_set(self.paths["DICTIONARY_PATH"])
        
        self.cracking_thread = None
        self.extractor_thread = None
        self.osint_thread = None
        self.url_thread = None
        self.network_thread = None
        self.log_thread = None
        self.custom_attack_thread = None
        
        self.is_password_audit_running = False
        self.is_hashcat_running = False
        self.is_custom_attack_running = False

        self.temp_dir = self.paths["PROJECT_ROOT"] / "temp"
        os.makedirs(self.temp_dir, exist_ok=True)
        self.custom_wordlist_path = self.temp_dir / "custom.txt"

        self.init_ui()
        self.create_connections()
        
        self.log(f"CyberGuard Initialized. Ready.")
        self.log(f"Hashcat path: {self.paths['HASHCAT_PATH']}")

    def init_ui(self):
        """Creates all the visual components (widgets) and layouts."""
        
        self.tabs = QTabWidget()
        
        # --- Tab 1: Dashboard ---
        # (This section is UNCHANGED)
        dashboard_widget = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_widget)
        title_label = QLabel("Overall Security Score")
        title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.score_label = QLabel("0")
        self.score_label.setFont(QFont("Arial", 72, QFont.Weight.Bold))
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verdict_label = QLabel("Run audits to see your score")
        self.verdict_label.setFont(QFont("Arial", 18))
        self.verdict_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.issues_label_title = QLabel("Top Issues:")
        self.issues_label_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.issues_list_label = QLabel("-")
        self.issues_list_label.setFont(QFont("Arial", 12))
        dash_button_layout = QHBoxLayout()
        self.refresh_score_button = QPushButton("Refresh Score")
        self.export_report_button = QPushButton("Export Full Report (PDF)")
        dash_button_layout.addWidget(self.refresh_score_button)
        dash_button_layout.addWidget(self.export_report_button)
        dashboard_layout.addWidget(title_label)
        dashboard_layout.addWidget(self.score_label)
        dashboard_layout.addWidget(self.verdict_label)
        dashboard_layout.addStretch()
        dashboard_layout.addWidget(self.issues_label_title)
        dashboard_layout.addWidget(self.issues_list_label)
        dashboard_layout.addStretch()
        dashboard_layout.addLayout(dash_button_layout)
        
        # --- Tab 2: Password Audit ---
        # (This section is UNCHANGED)
        password_widget = QWidget()
        password_layout = QVBoxLayout(password_widget)
        password_top_layout = QHBoxLayout()
        self.load_data_button = QPushButton("1. Extract Browser Data")
        self.start_analysis_button = QPushButton("2. Start Full Audit")
        self.stop_analysis_button = QPushButton("Stop Audit 🛑")
        self.stop_analysis_button.hide()
        self.stop_analysis_button.setStyleSheet("background-color: #E74C3C; color: white;")
        self.start_analysis_button.setEnabled(False)
        self.force_crack_checkbox = QCheckBox("Force Crack (Scan Strong Passwords)")
        self.force_crack_checkbox.setToolTip("If checked, the cracking simulation will run on ALL passwords...")
        password_top_layout.addWidget(self.load_data_button)
        password_top_layout.addWidget(self.start_analysis_button)
        password_top_layout.addWidget(self.stop_analysis_button)
        password_top_layout.addStretch()
        password_top_layout.addWidget(self.force_crack_checkbox)
        self.password_results_table = QTableWidget()
        self.password_results_table.setColumnCount(10)
        self.password_results_table.setHorizontalHeaderLabels([
            "URL", "URL Status", "Username/Email", "Password (Masked)",
            "Breach Count", "Strength", "Entropy (bits)", "Patterns / Reuse",
            "Suggested Password", "Est. Crack Time"
        ])
        header = self.password_results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 10): header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        password_layout.addLayout(password_top_layout)
        password_layout.addWidget(self.password_results_table)

        # --- Tab 3: Network Security ---
        # (This section is UNCHANGED)
        network_widget = QWidget()
        network_layout = QVBoxLayout(network_widget)
        self.start_network_scan_button = QPushButton("Start Network Scan")
        self.network_results_table = QTableWidget()
        self.network_results_table.setColumnCount(5)
        self.network_results_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Device Vendor", "Detected OS", "Open Ports"
        ])
        header_net = self.network_results_table.horizontalHeader()
        for i in range(5): header_net.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        header_net.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header_net.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        network_layout.addWidget(self.start_network_scan_button)
        network_layout.addWidget(self.network_results_table)
        
        # --- Tab 4: Log Audit ---
        # (This section is UNCHANGED)
        log_audit_widget = QWidget()
        log_audit_layout = QVBoxLayout(log_audit_widget)
        self.start_log_scan_button = QPushButton("Start Security Log Scan (Needs Admin)")
        self.log_results_table = QTableWidget()
        self.log_results_table.setColumnCount(3)
        self.log_results_table.setHorizontalHeaderLabels(["Date / Time", "Event ID", "Username"])
        header_log = self.log_results_table.horizontalHeader()
        header_log.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_log.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_log.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        log_audit_layout.addWidget(self.start_log_scan_button)
        log_audit_layout.addWidget(self.log_results_table)
        
        # --- Tab 5: Visualizations ---
        # (This section is UNCHANGED)
        visuals_widget = QWidget()
        visuals_layout = QVBoxLayout(visuals_widget)
        self.password_bar_chart = PasswordBarChart()
        visuals_layout.addWidget(self.password_bar_chart)
        
        # --- Tab 6: Profile ---
        # (This section is UNCHANGED)
        profile_widget = QWidget()
        profile_layout = QVBoxLayout(profile_widget)
        profile_title = QLabel("Personal Info (for Deeper Analysis)")
        profile_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        profile_info = QLabel(
            "This information is used for the 'Patterns / Reuse' check and the 'Attack Simulation' tab.\n"
            "This data is never saved and never leaves your computer."
        )
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter your full name (e.g., Piyush Ranjan Padhy)")
        self.dob_input = QLineEdit()
        self.dob_input.setPlaceholderText("Enter your DOB (e.g., 2000-01-31)")
        profile_layout.addWidget(profile_title)
        profile_layout.addWidget(profile_info)
        profile_layout.addSpacing(20)
        profile_layout.addWidget(QLabel("Name:"))
        profile_layout.addWidget(self.name_input)
        profile_layout.addWidget(QLabel("Date of Birth:"))
        profile_layout.addWidget(self.dob_input)
        profile_layout.addStretch()
        
        # --- Tab 7: Custom Attack Simulation (UPDATED) ---
        # (This section is UNCHANGED from your provided code)
        attack_sim_widget = QWidget()
        attack_sim_layout = QVBoxLayout(attack_sim_widget)
        sim_title = QLabel("Custom Attack Simulation")
        sim_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        sim_info = QLabel(
            "Enter your common patterns (comma-separated) to build a custom wordlist.\n"
            "This will also automatically include info from your 'Profile' tab.\n"
            "The attack will use your custom list + rockyou.txt + the full English dictionary."
        )
        self.custom_words_input = QLineEdit()
        self.custom_words_input.setPlaceholderText("Common words (e.g., dog, football, admin)")
        self.custom_nums_input = QLineEdit()
        self.custom_nums_input.setPlaceholderText("Common numbers (e.g., 123, 1999, 07)")
        self.custom_syms_input = QLineEdit()
        self.custom_syms_input.setPlaceholderText("Common symbols (e.g., !, @, #)")
        attack_button_layout = QHBoxLayout()
        self.start_custom_attack_button = QPushButton("Run Custom Attack Simulation")
        self.stop_custom_attack_button = QPushButton("Stop Attack 🛑")
        self.stop_custom_attack_button.hide()
        self.stop_custom_attack_button.setStyleSheet("background-color: #E74C3C; color: white;")
        self.view_wordlist_button = QPushButton("View Generated Wordlist")
        attack_button_layout.addWidget(self.start_custom_attack_button)
        attack_button_layout.addWidget(self.stop_custom_attack_button)
        attack_button_layout.addStretch()
        attack_button_layout.addWidget(self.view_wordlist_button)
        self.custom_attack_table = QTableWidget()
        self.custom_attack_table.setColumnCount(3)
        self.custom_attack_table.setHorizontalHeaderLabels(["URL", "Username", "Crack Result (Custom Attack)"])
        header_cust = self.custom_attack_table.horizontalHeader()
        header_cust.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header_cust.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_cust.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        attack_sim_layout.addWidget(sim_title)
        attack_sim_layout.addWidget(sim_info)
        attack_sim_layout.addWidget(QLabel("Common Words:"))
        attack_sim_layout.addWidget(self.custom_words_input)
        attack_sim_layout.addWidget(QLabel("Common Numbers:"))
        attack_sim_layout.addWidget(self.custom_nums_input)
        attack_sim_layout.addWidget(QLabel("Common Symbols:"))
        attack_sim_layout.addWidget(self.custom_syms_input)
        attack_sim_layout.addLayout(attack_button_layout)
        attack_sim_layout.addWidget(self.custom_attack_table)
        
        # --- Tab 8: Educational Mode ---
        # (This section is UNCHANGED)
        edu_widget = QWidget()
        edu_layout = QVBoxLayout(edu_widget)
        edu_title = QLabel("Learn About Cybersecurity")
        edu_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.edu_topic_selector = QComboBox()
        self.edu_topic_selector.addItems(TOPICS.keys())
        self.edu_content_display = QTextEdit()
        self.edu_content_display.setReadOnly(True)
        self.edu_content_display.setHtml(TOPICS["What is a Strong Password?"])
        edu_layout.addWidget(edu_title)
        edu_layout.addWidget(QLabel("Select a topic to learn more:"))
        edu_layout.addWidget(self.edu_topic_selector)
        edu_layout.addWidget(self.edu_content_display)
        
        # --- Add Tabs to Main Widget ---
        self.tabs.addTab(dashboard_widget, "📊 Dashboard")
        self.tabs.addTab(password_widget, "🔑 Password Audit")
        self.tabs.addTab(network_widget, "🌐 Network Security")
        self.tabs.addTab(log_audit_widget, "📜 Log Audit")
        self.tabs.addTab(visuals_widget, "📈 Visuals")
        self.tabs.addTab(profile_widget, "👤 Profile")
        self.tabs.addTab(attack_sim_widget, "💥 Attack Simulation")
        self.tabs.addTab(edu_widget, "🎓 Educational Mode")

        # --- Log Console (Common to all tabs) ---
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setFixedHeight(150)
        
        # --- Final Main Layout ---
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        main_layout.addWidget(self.log_console)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def create_connections(self):
        # (This function is UNCHANGED)
        self.refresh_score_button.clicked.connect(self.update_dashboard_ui)
        self.export_report_button.clicked.connect(self.export_report)
        self.load_data_button.clicked.connect(self.start_extraction)
        self.start_analysis_button.clicked.connect(self.run_analysis)
        self.stop_analysis_button.clicked.connect(self.stop_password_audit)
        self.start_network_scan_button.clicked.connect(self.start_network_scan)
        self.start_log_scan_button.clicked.connect(self.start_log_scan)
        self.start_custom_attack_button.clicked.connect(self.start_custom_attack_sim)
        self.stop_custom_attack_button.clicked.connect(self.stop_custom_attack_sim)
        self.view_wordlist_button.clicked.connect(self.view_custom_wordlist)
        self.edu_topic_selector.currentTextChanged.connect(self.update_edu_content)

    def log(self, message):
        """Helper function to add a message to the log console."""
        self.log_console.append(message)
        
    def reset_password_audit_ui(self):
        # (This function is UNCHANGED)
        self.start_analysis_button.show()
        self.stop_analysis_button.hide()
        self.load_data_button.setEnabled(True)
        self.start_analysis_button.setEnabled(True)
        self.log("Password audit UI reset.")

    # --- Dashboard Function ---
    @Slot()
    def update_dashboard_ui(self):
        # (This function is UNCHANGED)
        self.log("Calculating risk score...")
        report = calculate_overall_score(
            self.loaded_passwords,
            self.network_devices,
            self.log_events
        )
        self.current_risk_report = report
        self.score_label.setText(str(report['score']))
        self.verdict_label.setText(report['verdict'])
        if report['top_issues']:
            self.issues_list_label.setText("\n".join(f"- {issue}" for issue in report['top_issues']))
        else:
            self.issues_list_label.setText("- No major issues found!")
        if report['score'] >= 90: self.score_label.setStyleSheet("color: #2ECC71;")
        elif report['score'] >= 70: self.score_label.setStyleSheet("color: #F1C40F;")
        elif report['score'] >= 50: self.score_label.setStyleSheet("color: #E67E22;")
        else: self.score_label.setStyleSheet("color: #E74C3C;")
        self.log("Risk score updated.")
    
    @Slot()
    def export_report(self):
        # (This function is UNCHANGED)
        self.log("Opening PDF save dialog...")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Report As", "CyberGuard_Report.pdf", "PDF Files (*.pdf)")
        if not save_path:
            self.log("Report export cancelled."); return
        self.log(f"Generating PDF report at: {save_path}...")
        success = create_pdf_report(
            save_path, self.current_risk_report, self.loaded_passwords,
            self.network_devices, self.log_events)
        if success: self.log("✅ PDF report saved successfully.")
        else: self.log("❌ ERROR: Failed to generate PDF report. See console.")

    # --- Password Audit Functions ---
    def populate_table(self):
        # (This function is UNCHANGED)
        self.log(f"Populating password table with {len(self.loaded_passwords)} items...")
        self.password_results_table.setRowCount(0)
        for i, login in enumerate(self.loaded_passwords):
            self.password_results_table.insertRow(i)
            password_str = login.get("password", "")
            password_masked = ("*" * len(password_str)) if password_str else "<EMPTY>"
            items = [
                QTableWidgetItem(login.get("url", "N/A")),
                QTableWidgetItem("Pending..."), QTableWidgetItem(login.get("username", "N/A")),
                QTableWidgetItem(password_masked), QTableWidgetItem("Pending..."),
                QTableWidgetItem("Pending..."), QTableWidgetItem("Pending..."),
                QTableWidgetItem("Pending..."), QTableWidgetItem("Pending..."),
                QTableWidgetItem("Pending...")
            ]
            for j, item in enumerate(items):
                self.password_results_table.setItem(i, j, item)
            QApplication.processEvents()
        self.log(f"Password table populated with {len(self.loaded_passwords)} entries.")

    @Slot()
    def start_extraction(self):
        # (This function is UNCHANGED)
        if self.extractor_thread and self.extractor_thread.isRunning():
            self.log("Extraction already in progress. Please wait."); return
        self.log("Starting browser data extraction...")
        self.load_data_button.setEnabled(False); self.start_analysis_button.setEnabled(False)
        self.extractor_thread = ExtractorThread()
        self.extractor_thread.extraction_complete.connect(self.on_extraction_complete)
        self.extractor_thread.start()

    @Slot(list)
    def on_extraction_complete(self, all_logins):
        # (This function is UNCHANGED)
        self.log("...Extraction complete.")
        self.log(f"[DEBUG] Thread emitted {len(all_logins)} logins.")
        if not all_logins:
            self.log("❌ ERROR: No logins found or extraction failed.")
            self.load_data_button.setEnabled(True); return
        self.log(f"✅ Successfully extracted {len(all_logins)} logins.")
        self.loaded_passwords = all_logins
        self.log(f"[DEBUG] self.loaded_passwords now contains {len(self.loaded_passwords)} items.")
        self.populate_table()
        self.start_analysis_button.setEnabled(True)
        self.load_data_button.setEnabled(True)
        self.extractor_thread = None

    @Slot()
    def run_analysis(self):
        # (This function is UNCHANGED)
        self.log("="*30)
        if self.is_hashcat_running:
            self.log("❌ ERROR: Another hashcat scan is already in progress (e.g., Custom Attack). Please wait.")
            return
        if len(self.loaded_passwords) == 0:
            self.log("❌ ERROR: No passwords loaded to analyze. Please extract data first."); return
        self.log(f"Starting FAST analysis (Strength, Patterns, Reuse)...")
        self.is_password_audit_running = True
        self.start_analysis_button.hide()
        self.stop_analysis_button.show()
        self.load_data_button.setEnabled(False)
        profile = { "name": self.name_input.text(), "dob": self.dob_input.text() }
        self.log(f"Analyzing with profile: Name={profile['name']}, DOB={profile['dob']}")
        self.log("Analyzing password reuse patterns...")
        reuse_counts = analyze_reuse(self.loaded_passwords)
        for i, login_data in enumerate(self.loaded_passwords):
            if not self.is_password_audit_running:
                self.log("Fast analysis stopped by user.")
                self.reset_password_audit_ui()
                return
            password = login_data.get("password", ""); report = analyze_password(password)
            verdict = report["strength_verdict"]; suggestion = mutate_password(password)
            patterns_found = check_password_patterns(password, self.common_words_set, profile)
            reuse_count = reuse_counts.get(password, 0)
            if reuse_count > 1: patterns_found.append(f"Reused {reuse_count}x")
            self.loaded_passwords[i]['strength_verdict'] = report["strength_verdict"]
            self.loaded_passwords[i]['entropy'] = report["entropy"]
            self.loaded_passwords[i]['suggestion'] = suggestion
            self.loaded_passwords[i]['patterns'] = patterns_found
            pattern_str = ", ".join(patterns_found) if patterns_found else "N/A"
            self.password_results_table.setItem(i, 5, QTableWidgetItem(verdict))
            self.password_results_table.setItem(i, 6, QTableWidgetItem(str(report["entropy"])))
            self.password_results_table.setItem(i, 7, QTableWidgetItem(pattern_str))
            self.password_results_table.setItem(i, 8, QTableWidgetItem(suggestion))
            self.password_results_table.setItem(i, 9, QTableWidgetItem("Pending..."))
            QApplication.processEvents()
        QApplication.processEvents(); self.log("✅ FAST analysis complete.")
        if not self.is_password_audit_running:
            self.log("Fast analysis stopped by user.")
            self.reset_password_audit_ui()
            return
        self.log("Starting SLOW analysis (URL Phishing Scan)...")
        self.url_thread = UrlScanThread(self.loaded_passwords)
        self.url_thread.result_ready.connect(self.update_url_scan_result)
        self.url_thread.finished.connect(self.on_url_scan_finished)
        self.url_thread.start()
        self.log("Starting SLOW analysis (OSINT Breaches)... This will take time.")
        self.osint_thread = OsintThread(self.loaded_passwords)
        self.osint_thread.result_ready.connect(self.update_osint_result)
        self.osint_thread.finished.connect(self.on_osint_finished)
        self.osint_thread.start()
        self.log("Starting SLOW analysis (Hybrid Cracking)...")
        self.start_cracking_simulation()
        
    @Slot()
    def stop_password_audit(self):
        # (This function is UNCHANGED)
        self.log("🛑 Stop requested for password audit...")
        self.is_password_audit_running = False
        if self.url_thread and self.url_thread.isRunning():
            self.url_thread.stop()
            self.log("URL scan thread signaled to stop.")
        if self.osint_thread and self.osint_thread.isRunning():
            self.osint_thread.stop()
            self.log("OSINT scan thread signaled to stop.")
        if self.cracking_thread and self.cracking_thread.isRunning():
            self.cracking_thread.stop()
            self.log("Cracking thread signaled to stop.")
        self.reset_password_audit_ui()
        self.log("All password audit scans stopped.")

    def start_cracking_simulation(self):
        """
        --- UPDATED: Passes a LIST of wordlists to the thread ---
        (This function is UNCHANGED from your provided code)
        """
        self.is_hashcat_running = True
        force = self.force_crack_checkbox.isChecked()
        if force: self.log("FORCE CRACK enabled: Will scan all passwords.")
        
        # --- Pass both wordlists as a list ---
        wordlists_to_use = [
            self.paths["WORDLIST_PATH"],    # rockyou.txt
            self.paths["DICTIONARY_PATH"] # words_alpha.txt
        ]
        
        self.cracking_thread = CrackingThread(
            passwords=self.loaded_passwords,
            hashcat_path=self.paths["HASHCAT_PATH"],
            wordlist_paths=wordlists_to_use, # <-- Pass the list
            temp_dir=self.temp_dir,
            force_crack=force
        )
        self.cracking_thread.result_ready.connect(self.update_crack_result)
        self.cracking_thread.finished.connect(self.on_cracking_finished)
        self.cracking_thread.start()

    # --- Network Scan Functions ---
    @Slot()
    def start_network_scan(self):
        # (This function is ***MODIFIED***)
        
        # --- ADDED NMAP CHECK ---
        if not check_nmap_and_prompt(self):
            self.log("Network scan aborted. Nmap is not installed or not in PATH.")
            return
        # --- END OF CHECK ---
        
        if self.network_thread and self.network_thread.isRunning():
            self.log("Network scan already in progress. Please wait."); return
            
        self.log("Starting network scan... This may take 1-5 minutes.")
        self.start_network_scan_button.setEnabled(False)
        self.network_results_table.setRowCount(0)
        self.network_thread = NetworkScanThread()
        self.network_thread.scan_complete.connect(self.on_network_scan_complete)
        self.network_thread.start()
        
    @Slot(list)
    def on_network_scan_complete(self, devices):
        # (This function is UNCHANGED from your provided code)
        self.log(f"✅ Network scan complete. Found {len(devices)} devices.")
        if devices is None:
             self.log("❌ ERROR: Nmap not found. Please install Nmap and add it to your system PATH.")
             self.start_network_scan_button.setEnabled(True); return
        self.network_devices = devices
        self.network_results_table.setRowCount(0)
        for i, device in enumerate(devices):
            self.network_results_table.insertRow(i)
            items = [
                QTableWidgetItem(device.get('ip', 'N/A')), QTableWidgetItem(device.get('mac', 'N/A')),
                QTableWidgetItem(device.get('vendor', 'N/A')), QTableWidgetItem(device.get('os', 'N/A')),
                QTableWidgetItem(device.get('ports', 'None'))]
            for j, item in enumerate(items):
                self.network_results_table.setItem(i, j, item)
        self.network_thread = None
        self.start_network_scan_button.setEnabled(True)
        self.log("Network scan complete. Updating dashboard...")
        self.update_dashboard_ui()

    # --- Log Scan Functions ---
    @Slot()
    def start_log_scan(self):
        # (This function is UNCHANGED)
        if self.log_thread and self.log_thread.isRunning():
            self.log("Log scan already in progress. Please wait."); return
        self.log("Starting security log scan... (Needs Admin rights). This may take a moment.")
        self.start_log_scan_button.setEnabled(False)
        self.log_results_table.setRowCount(0)
        self.log_thread = LogScanThread()
        self.log_thread.scan_complete.connect(self.on_log_scan_complete)
        self.log_thread.start()
    @Slot(object)
    def on_log_scan_complete(self, events):
        # (This function is UNCHANGED)
        self.start_log_scan_button.setEnabled(True); self.log_thread = None
        if isinstance(events, str) and events == "Access Denied":
            self.log("❌ ERROR: Access Denied. Please restart CyberGuard with 'Run as Administrator'."); return
        elif events is None:
            self.log("❌ ERROR: Log scan failed. See console for details."); return
        self.log(f"✅ Log scan complete. Found {len(events)} failed logon attempts (last 7 days).")
        self.log_events = events
        self.log_results_table.setRowCount(0)
        for i, event in enumerate(events):
            self.log_results_table.insertRow(i)
            items = [
                QTableWidgetItem(event.get('time', 'N/A')),
                QTableWidgetItem(str(event.get('event_id', 'N/A'))),
                QTableWidgetItem(event.get('username', 'N/A'))]
            for j, item in enumerate(items):
                self.log_results_table.setItem(i, j, item)
        self.log("Log scan complete. Updating dashboard...")
        self.update_dashboard_ui()
        
    # --- Educational Tab Function ---
    @Slot(str)
    def update_edu_content(self, topic_name):
        # (This function is UNCHANGED)
        content = TOPICS.get(topic_name, "<p>Error: Topic not found.</p>")
        self.edu_content_display.setHtml(content)
        
    # --- Custom Attack Sim Functions (UPDATED) ---
    @Slot()
    def start_custom_attack_sim(self):
        """
        --- UPDATED: Now runs HYBRID attack with ALL wordlists ---
        (This function is UNCHANGED from your provided code)
        """
        if self.is_custom_attack_running:
            self.log("Custom attack simulation already running.")
            return
        if self.is_hashcat_running:
            self.log("❌ ERROR: Another hashcat scan is already in progress (e.g., Full Audit). Please wait.")
            return

        profile = { "name": self.name_input.text(), "dob": self.dob_input.text() }
        custom_inputs = {
            "words": self.custom_words_input.text(),
            "nums": self.custom_nums_input.text(),
            "syms": self.custom_syms_input.text()
        }
        
        if not profile["name"] and not profile["dob"] and \
           not custom_inputs["words"] and not custom_inputs["nums"] and not custom_inputs["syms"]:
            self.log("❌ ERROR: Please enter info in the 'Profile' tab or this tab to run an attack.")
            return
            
        if not self.loaded_passwords:
            self.log("❌ ERROR: Please extract browser data first (in 'Password Audit' tab).")
            return

        self.log("Starting custom attack simulation (HYBRID)...")
        self.is_custom_attack_running = True
        self.start_custom_attack_button.hide()
        self.stop_custom_attack_button.show()
        
        success = generate_custom_wordlist(profile, custom_inputs, self.custom_wordlist_path)
        if not success:
            self.log("❌ ERROR: Could not generate custom wordlist.")
            self.start_custom_attack_button.show()
            self.stop_custom_attack_button.hide()
            self.is_custom_attack_running = False
            return

        self.custom_attack_table.setRowCount(0)
        for i, login in enumerate(self.loaded_passwords):
            self.custom_attack_table.insertRow(i)
            self.custom_attack_table.setItem(i, 0, QTableWidgetItem(login.get("url", "N/A")))
            self.custom_attack_table.setItem(i, 1, QTableWidgetItem(login.get("username", "N/A")))
            self.custom_attack_table.setItem(i, 2, QTableWidgetItem("Pending..."))

        self.is_hashcat_running = True
        
        # --- NEW: Pass ALL THREE wordlists as a list ---
        wordlists_to_use = [
            self.custom_wordlist_path,   # 1. Custom list
            self.paths["WORDLIST_PATH"],   # 2. rockyou.txt
            self.paths["DICTIONARY_PATH"] # 3. words_alpha.txt
        ]
        
        self.custom_attack_thread = CustomAttackThread(
            passwords=self.loaded_passwords,
            hashcat_path=self.paths["HASHCAT_PATH"],
            wordlist_paths=wordlists_to_use, # <-- Pass the full list
            temp_dir=self.temp_dir,
            attack_mode="hybrid" # <-- Run as HYBRID attack
        )
        self.custom_attack_thread.result_ready.connect(self.update_custom_attack_result)
        self.custom_attack_thread.finished.connect(self.on_custom_attack_finished)
        self.custom_attack_thread.start()

    @Slot(int, str)
    def update_custom_attack_result(self, row, message):
        # (This function is UNCHANGED)
        self.custom_attack_table.setItem(row, 2, QTableWidgetItem(message))

    @Slot()
    def on_custom_attack_finished(self):
        # (This function is UNCHANGED)
        self.log("✅ Custom attack simulation complete.")
        self.start_custom_attack_button.show()
        self.stop_custom_attack_button.hide()
        self.custom_attack_thread = None
        self.is_hashcat_running = False
        self.is_custom_attack_running = False
        
    @Slot()
    def stop_custom_attack_sim(self):
        # (This function is UNCHANGED)
        self.log("🛑 Stop requested for custom attack...")
        self.is_custom_attack_running = False
        if self.custom_attack_thread and self.custom_attack_thread.isRunning():
            self.custom_attack_thread.stop()
            self.log("Custom attack thread signaled to stop.")
        
        self.start_custom_attack_button.show()
        self.stop_custom_attack_button.hide()
        self.is_hashcat_running = False
        
    @Slot()
    def view_custom_wordlist(self):
        # (This function is UNCHANGED)
        if not self.custom_wordlist_path.exists():
            self.log("❌ ERROR: No custom wordlist found. Please run a custom attack first to generate it.")
            return
        try:
            self.log(f"Opening {self.custom_wordlist_path} in default editor...")
            os.startfile(self.custom_wordlist_path)
        except Exception as e:
            self.log(f"❌ ERROR: Could not open file: {e}")

    # --- Thread Management Functions ---
    @Slot(int, str)
    def update_url_scan_result(self, row, verdict):
        self.password_results_table.setItem(row, 1, QTableWidgetItem(verdict))
        if row < len(self.loaded_passwords): self.loaded_passwords[row]['url_verdict'] = verdict
    @Slot()
    def on_url_scan_finished(self):
        self.log("✅ URL Phishing scan complete."); self.url_thread = None
        self.check_all_threads_finished()
    @Slot(int, int, str)
    def update_osint_result(self, row, count, names):
        count_str = str(count);
        if count == -1: count_str = "API Key Error"
        self.password_results_table.setItem(row, 4, QTableWidgetItem(count_str))
        if row < len(self.loaded_passwords):
            self.loaded_passwords[row]['breach_count'] = count
            self.loaded_passwords[row]['breach_names'] = names
    @Slot()
    def on_osint_finished(self):
        self.log("✅ OSINT Breach scan complete."); self.osint_thread = None
        self.check_all_threads_finished()
    @Slot(int, str)
    def update_crack_result(self, row, message):
        self.password_results_table.setItem(row, 9, QTableWidgetItem(message))
        if row < len(self.loaded_passwords): self.loaded_passwords[row]['crack_result'] = message
    @Slot()
    def on_cracking_finished(self):
        self.log("✅ Cracking simulation complete."); self.cracking_thread = None
        self.is_hashcat_running = False
        self.check_all_threads_finished()
        
    def check_all_threads_finished(self):
        # (This function is UNCHANGED)
        if self.cracking_thread is None and self.osint_thread is None and self.url_thread is None:
            if not self.is_password_audit_running:
                self.log("Password audit scans confirmed stopped.")
                return
            self.log("="*30)
            self.log("✅ All password analysis complete.")
            self.log("Updating dashboard and visuals...")
            self.update_dashboard_ui()
            self.password_bar_chart.update_chart(self.loaded_passwords) # <-- FIXED
            self.log("Cleaning up temporary files...")
            secure_delete_folder(self.temp_dir)
            os.makedirs(self.temp_dir, exist_ok=True)
            self.is_password_audit_running = False
            self.reset_password_audit_ui()
            
    def closeEvent(self, event):
        # (This function is UNCHANGED)
        self.log("Close event triggered. Shutting down...")
        self.is_password_audit_running = False
        threads = [
            ("Extraction", self.extractor_thread), ("URL Scan", self.url_thread),
            ("OSINT", self.osint_thread), ("Cracking",self.cracking_thread),
            ("Network Scan", self.network_thread), ("Log Scan", self.log_thread),
            ("Custom Attack", self.custom_attack_thread)
        ]
        for name, thread in threads:
            if thread and thread.isRunning():
                self.log(f"Stopping {name} thread...")
                thread.stop(); thread.wait(); self.log(f"{name} thread stopped.")
        self.log("Cleaning up temporary files...")
        secure_delete_folder(self.temp_dir)
        self.log("Shutdown complete.")
        event.accept()