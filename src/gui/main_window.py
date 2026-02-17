"""
Main GUI window for VulnScanr Desktop App
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from src.scanner import VulnScanr
from src.utils.logger import setup_logger

class VulnScanrGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VulnScanr - Web Vulnerability Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Scan state
        self.scanning = False
        self.current_scanner = None
        
        # Setup GUI
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the main GUI components"""
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame, 
            text="🔍 VulnScanr - Web Vulnerability Scanner", 
            font=('Arial', 16, 'bold'),
            fg='white',
            bg='#2c3e50'
        )
        title_label.pack(pady=20)
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel - Controls
        self.setup_controls_panel(main_frame)
        
        # Right panel - Results
        self.setup_results_panel(main_frame)
        
    def setup_controls_panel(self, parent):
        """Setup the controls panel"""
        controls_frame = tk.LabelFrame(
            parent, 
            text="Scan Configuration", 
            font=('Arial', 12, 'bold'),
            bg='#f0f0f0',
            padx=10,
            pady=10
        )
        controls_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Target URL
        tk.Label(controls_frame, text="Target URL:", bg='#f0f0f0').pack(anchor='w', pady=(10, 5))
        self.url_entry = tk.Entry(controls_frame, width=30, font=('Arial', 10))
        self.url_entry.insert(0, "http://localhost:8080")
        self.url_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Scan types
        tk.Label(controls_frame, text="Scan Types:", bg='#f0f0f0').pack(anchor='w', pady=(10, 5))
        
        self.scan_vars = {}
        scan_types = [
            ("SQL Injection", "sql"),
            ("Cross-Site Scripting (XSS)", "xss"),
            ("Full Security Scan", "full")
        ]
        
        for display_name, scan_id in scan_types:
            var = tk.BooleanVar(value=(scan_id in ['sql', 'xss', 'full']))
            self.scan_vars[scan_id] = var
            cb = tk.Checkbutton(
                controls_frame, 
                text=display_name, 
                variable=var,
                bg='#f0f0f0',
                anchor='w'
            )
            cb.pack(fill=tk.X, pady=2)
        
        # Buttons
        button_frame = tk.Frame(controls_frame, bg='#f0f0f0')
        button_frame.pack(fill=tk.X, pady=20)
        
        self.start_btn = tk.Button(
            button_frame,
            text="🚀 Start Scan",
            command=self.start_scan,
            bg='#27ae60',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15,
            height=2
        )
        self.start_btn.pack(pady=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="⏹️ Stop Scan",
            command=self.stop_scan,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15,
            height=2,
            state=tk.DISABLED
        )
        self.stop_btn.pack(pady=5)
        
        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            controls_frame, 
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        self.status_label = tk.Label(
            controls_frame, 
            text="Ready to scan",
            bg='#f0f0f0',
            fg='#7f8c8d'
        )
        self.status_label.pack()
        
    def setup_results_panel(self, parent):
        """Setup the results display panel"""
        results_frame = tk.LabelFrame(
            parent, 
            text="Scan Results", 
            font=('Arial', 12, 'bold'),
            bg='#f0f0f0',
            padx=10,
            pady=10
        )
        results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Results summary
        summary_frame = tk.Frame(results_frame, bg='#f0f0f0')
        summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.results_label = tk.Label(
            summary_frame,
            text="No scan performed yet",
            font=('Arial', 11),
            bg='#f0f0f0',
            justify=tk.LEFT
        )
        self.results_label.pack(anchor='w')
        
        # Log output
        tk.Label(results_frame, text="Scan Log:", bg='#f0f0f0').pack(anchor='w')
        
        self.log_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            width=60,
            height=20,
            font=('Consolas', 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.log_text.config(state=tk.DISABLED)
        
    def start_scan(self):
        """Start the vulnerability scan"""
        if self.scanning:
            return
            
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        # Get selected scan types
        selected_scans = []
        for scan_id, var in self.scan_vars.items():
            if var.get():
                selected_scans.append(scan_id)
                
        if not selected_scans:
            messagebox.showerror("Error", "Please select at least one scan type")
            return
            
        # Update UI
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.status_label.config(text="Starting scan...")
        
        # Clear previous results
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(
            target=self.run_scan_thread,
            args=(target_url, selected_scans)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning and self.current_scanner:
            self.scanning = False
            self.status_label.config(text="Stopping scan...")
            # Note: We'll need to implement proper scan interruption
            
    def run_scan_thread(self, target_url, scan_types):
        """Run the scan in a separate thread"""
        try:
            # Initialize scanner
            self.current_scanner = VulnScanr(target_url, verbose=True)
            
            # Test connection
            self.update_log("Testing connection to target...\n")
            if not self.current_scanner.test_connection():
                self.update_log("❌ Connection failed!\n")
                self.scan_complete(False)
                return
                
            self.update_log("✅ Successfully connected to target\n\n")
            
            # Run selected scans
            total_scans = len(scan_types)
            current_scan = 0
            
            for scan_type in scan_types:
                if not self.scanning:
                    break
                    
                current_scan += 1
                progress = (current_scan / total_scans) * 100
                self.progress_var.set(progress)
                
                if scan_type == 'sql':
                    self.update_log("🔍 Starting SQL Injection scan...\n")
                    self.current_scanner.run_sql_injection_scan()
                elif scan_type == 'xss':
                    self.update_log("🔍 Starting XSS scan...\n")
                    self.current_scanner.run_xss_scan()
                elif scan_type == 'full':
                    self.update_log("🔍 Starting full security scan...\n")
                    self.current_scanner.run_sql_injection_scan()
                    self.current_scanner.run_xss_scan()
                    
                self.update_log(f"✅ {scan_type.upper()} scan completed\n\n")
            
            if self.scanning:
                # Generate reports
                self.update_log("📄 Generating reports...\n")
                self.current_scanner.generate_reports()
                self.update_log("✅ Scan completed successfully!\n")
                self.scan_complete(True)
                
        except Exception as e:
            self.update_log(f"❌ Scan error: {str(e)}\n")
            self.scan_complete(False)
            
    def update_log(self, message):
        """Update the log text area (thread-safe)"""
        def update():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
            self.root.update_idletasks()
            
        self.root.after(0, update)
        
    def scan_complete(self, success):
        """Handle scan completion"""
        def complete():
            self.scanning = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.progress_var.set(100)
            
            if success:
                self.status_label.config(text="Scan completed successfully!")
                # Update results summary
                total_findings = len(self.current_scanner.reporter.findings)
                self.results_label.config(
                    text=f"Scan completed! Found {total_findings} vulnerabilities.\nCheck reports/ folder for detailed results."
                )
            else:
                self.status_label.config(text="Scan failed!")
                self.results_label.config(text="Scan failed. Check log for details.")
                
        self.root.after(0, complete)
        
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

def main():
    """Main entry point for GUI app"""
    app = VulnScanrGUI()
    app.run()

if __name__ == "__main__":
    main()