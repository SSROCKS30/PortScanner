import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from scanner import network_scan, save_results, scan_device
from visualization import visualize_network
import schedule
import time
import threading
import textwrap

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Port Scanner")
        self.geometry("900x650")

        self.style = ttk.Style(self)
        available_themes = self.style.theme_names()
        if 'clam' in available_themes:
            self.style.theme_use('clam')
        elif 'vista' in available_themes:
            self.style.theme_use('vista')

        self.style.configure('TFrame', padding=5)
        self.style.configure('TButton', padding=(8, 5), font=('Helvetica', 10), relief=tk.FLAT)
        self.style.map('TButton',
            foreground=[('disabled', 'grey'), ('active', '#0078D7')],
            background=[('active', 'white')])
        self.style.configure('TLabel', padding=(0, 5), font=('Helvetica', 10))
        self.style.configure('TEntry', padding=5, font=('Helvetica', 10))
        self.style.configure('TCombobox', padding=5, font=('Helvetica', 10))
        self.style.map('TCombobox', fieldbackground=[('readonly','white')])
        self.style.configure('Treeview.Heading', font=('Helvetica', 10, 'bold'))
        self.style.configure('Treeview', rowheight=40, font=('Helvetica', 9))
        self.style.configure('TLabelframe', padding=10, relief=tk.RIDGE)
        self.style.configure('TLabelframe.Label', font=('Helvetica', 11, 'bold'), padding=(0,5))
        self.style.configure('Status.TLabel', padding=(5, 5), font=('Helvetica', 9), relief=tk.GROOVE, anchor=tk.W)
        self.style.configure('TCheckbutton', font=('Helvetica', 10), padding=(0,0,5,0))

        main_frame = ttk.Frame(self, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        config_labelframe = ttk.Labelframe(main_frame, text="Scan Configuration")
        config_labelframe.pack(fill=tk.X, padx=5, pady=5)

        self.input_frame = ttk.Frame(config_labelframe, padding="10 10 10 10")
        self.input_frame.pack(fill=tk.X)

        self.ip_range_label = ttk.Label(self.input_frame, text="IP Range:")
        self.ip_range_label.pack(side=tk.LEFT, padx=(0, 5))
        self.ip_range_entry = ttk.Entry(self.input_frame, width=30)
        self.ip_range_entry.pack(side=tk.LEFT, padx=(0, 15), expand=True, fill=tk.X)

        self.scan_type_label = ttk.Label(self.input_frame, text="Scan Type:")
        self.scan_type_label.pack(side=tk.LEFT, padx=(10, 5))
        self.scan_type_var = tk.StringVar(self)
        scan_types = ["SYN Scan", "UDP Scan"]
        self.scan_type_var.set(scan_types[0])
        self.scan_type_menu = ttk.Combobox(self.input_frame, textvariable=self.scan_type_var, values=scan_types, state="readonly", width=12)
        self.scan_type_menu.pack(side=tk.LEFT, padx=(0, 15))

        self.os_detection_var = tk.BooleanVar(value=False)
        self.os_detection_check = ttk.Checkbutton(self.input_frame, text="Enable OS Detection", variable=self.os_detection_var)
        self.os_detection_check.pack(side=tk.LEFT, padx=(5,5))
        
        sep1 = ttk.Separator(main_frame, orient='horizontal')
        sep1.pack(fill='x', padx=5, pady=10)

        self.button_frame = ttk.Frame(main_frame)
        self.button_frame.pack(fill=tk.X, padx=5, pady=5)

        self.scan_button = ttk.Button(self.button_frame, text="▶ Scan Network", command=self.scan_network)
        self.scan_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.save_button = ttk.Button(self.button_frame, text="💾 Save Results", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.visualize_button = ttk.Button(self.button_frame, text="📊 Visualize Network", command=self.visualize_network)
        self.visualize_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.schedule_button = ttk.Button(self.button_frame, text="⏰ Schedule Scan", command=self.schedule_scan)
        self.schedule_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        sep2 = ttk.Separator(main_frame, orient='horizontal')
        sep2.pack(fill='x', padx=5, pady=10)

        results_labelframe = ttk.Labelframe(main_frame, text="Scan Results")
        results_labelframe.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tree_frame = ttk.Frame(results_labelframe, padding="10 10 10 10")
        self.tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("IP", "OS", "Port", "State", "Vulnerability")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        
        vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vsb.set)

        hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        hsb.pack(side='bottom', fill='x')
        self.tree.configure(xscrollcommand=hsb.set)
        self.tree.bind("<Shift-MouseWheel>", self._on_horizontal_scroll)

        for col in columns:
            self.tree.heading(col, text=col, anchor=tk.W)
            if col == "Vulnerability":
                 self.tree.column(col, minwidth=150, width=250, stretch=tk.YES, anchor=tk.W)
            elif col == "OS":
                 self.tree.column(col, minwidth=120, width=200, stretch=tk.YES, anchor=tk.W)
            else:
                 self.tree.column(col, minwidth=80, width=100, stretch=tk.YES, anchor=tk.W)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.devices = []
        self.schedule_thread = None

        self.status_label = ttk.Label(main_frame, text="Ready", style="Status.TLabel")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(5,0))

    def _on_horizontal_scroll(self, event):
        scroll_speed_multiplier = 5 
        if event.num == 5 or event.delta < 0:
            self.tree.xview_scroll(scroll_speed_multiplier, "units")
        elif event.num == 4 or event.delta > 0:
            self.tree.xview_scroll(-scroll_speed_multiplier, "units")

    def log_message(self, message):
        self.status_label.config(text=message)
        logging.info(message)

    def log_device(self, scanned_device):
        wrap_widths = {
            'OS': 30,
            'Vulnerability': 35
        }

        ip = scanned_device.get('ip', 'N/A')
        os_info = scanned_device.get('os', 'N/A')
        os_detection_performed = scanned_device.get('os_detection_performed', False)

        if os_info and os_info not in ["OS Detection Disabled", "N/A", "Unknown", "OS detection attempted, no match."]:
             os_info = textwrap.fill(os_info, width=wrap_widths.get('OS', 30))
        elif not os_detection_performed and os_info == 'N/A': # If os_info is N/A and detection wasn't run
            os_info = "OS Detection Disabled"
        elif os_detection_performed and os_info == 'N/A': # If detection ran but os_info is still N/A (should be 'Unknown' or 'no match' from scanner.py)
             os_info = "OS detection attempted, no match."

        open_ports = scanned_device.get('open_ports', [])

        if not open_ports:
            # Add a row for devices with no open ports found
            self.tree.insert("", "end", values=(
                ip,
                os_info,
                "N/A", # Port
                "No open ports found", # State
                "N/A"  # Vulnerability
            ))
        else:
            for i, port_info in enumerate(open_ports):
                port = port_info.get('port', 'N/A')
                state = port_info.get('state', 'N/A')
                vulnerability = port_info.get('vulnerability', 'No known vulnerabilities (basic check)')
                
                vulnerability = textwrap.fill(vulnerability, width=wrap_widths.get('Vulnerability', 35))

                # For the first port of a device, show IP and OS. For subsequent, clear them for readability.
                current_ip_display = ip if i == 0 else ""
                current_os_display = os_info if i == 0 else ""

                self.tree.insert("", "end", values=(
                    current_ip_display,
                    current_os_display,
                    port,
                    state,
                    vulnerability
                ))

    def scan_network(self):
        ip_range = self.ip_range_entry.get()
        scan_type = self.scan_type_var.get()
        perform_os_detection = self.os_detection_var.get()

        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range")
            return
    
        self.tree.delete(*self.tree.get_children())
        os_status_msg = "with OS Detection" if perform_os_detection else "without OS Detection"
        self.log_message(f"Scanning: {ip_range} ({scan_type} scan, {os_status_msg})...")
        
        self.scan_button.config(state=tk.DISABLED)
        scan_thread = threading.Thread(target=self._execute_scan, args=(ip_range, scan_type, perform_os_detection), daemon=True)
        scan_thread.start()

    def _execute_scan(self, ip_range, scan_type, perform_os_detection):
        try:
            devices_found = network_scan(ip_range)
            self.devices = [] 

            if devices_found:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_device = {executor.submit(scan_device, device, scan_type, perform_os_detection): device for device in devices_found}
                    for future in as_completed(future_to_device):
                        try:
                            scanned_device_result = future.result()
                            if scanned_device_result:
                                self.devices.append(scanned_device_result)
                                self.log_device(scanned_device_result)
                        except Exception as e:
                            logging.error(f"Error processing device scan result: {e}")
                self.log_message(f"Scan completed for {ip_range}. Processed {len(devices_found)} potential host(s).")
            else:
                self.log_message(f"No devices initially found in the range: {ip_range}")

        except Exception as e:
            logging.error(f"An error occurred during network scan execution: {e}")
            self.log_message(f"Scan Error: {e}")

        finally:
            self.scan_button.config(state=tk.NORMAL)
            if not devices_found:
                 self.log_message(f"Scan finished. No devices responded in {ip_range}.")
            elif not self.devices and devices_found:
                 self.log_message(f"Scan finished for {ip_range}. Devices found, but no open ports or specific details gathered based on scan type.")
            elif self.devices:
                 self.log_message(f"Scan finished for {ip_range}. Displaying details for {len(self.devices)} device(s) with open ports/info.")

    def save_results(self):
        if not self.devices:
            messagebox.showerror("Error", "No scan results to save")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if filename:
            save_results(self.devices, filename) 
            messagebox.showinfo("Info", f"Results saved to {filename}")
            self.log_message(f"Results saved to {filename}")

    def visualize_network(self):
        if not self.devices:
            messagebox.showerror("Error", "No scan results to visualize")
            self.log_message("Visualization failed: No scan results available.")
            return
        visualize_network(self.devices, interactive=True) 
        self.log_message("Network visualization generated.")

    def schedule_scan(self):
        ip_range = self.ip_range_entry.get()
        scan_type = self.scan_type_var.get()
        perform_os_detection = self.os_detection_var.get()

        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range")
            return
        
        os_status_msg = "with OS Detection" if perform_os_detection else "without OS Detection"
        if not messagebox.askyesno("Confirm Schedule", f"Schedule a daily '{scan_type}' scan ({os_status_msg}) for {ip_range} at midnight?"):
            return

        schedule.every().day.at("00:00").do(self._execute_scan, ip_range, scan_type, perform_os_detection)
        self.log_message(f"Scheduled daily {scan_type} scan ({os_status_msg}) for {ip_range} at midnight")
        
        if self.schedule_thread is None or not self.schedule_thread.is_alive():
            self.schedule_thread = threading.Thread(target=self.run_schedule, daemon=True)
            self.schedule_thread.start()

    def run_schedule(self):
        while True:
            schedule.run_pending()
            time.sleep(60)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    app = PortScannerApp()
    app.mainloop()