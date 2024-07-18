import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from scanner import network_scan, save_results, scan_device
from visualization import visualize_network
import schedule
import time
import threading

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("1000x600")

        # Frame for IP Range and Scan Type
        self.input_frame = tk.Frame(self)
        self.input_frame.pack(pady=10, padx=10, fill=tk.X)

        self.ip_range_label = tk.Label(self.input_frame, text="IP Range:")
        self.ip_range_label.pack(side=tk.LEFT, padx=(0, 10))
        self.ip_range_entry = tk.Entry(self.input_frame, width=30)
        self.ip_range_entry.pack(side=tk.LEFT, padx=(0, 10))

        self.scan_type_label = tk.Label(self.input_frame, text="Scan Type:")
        self.scan_type_label.pack(side=tk.LEFT, padx=(10, 10))
        self.scan_type_var = tk.StringVar(self)
        self.scan_type_var.set("Default")
        self.scan_type_menu = tk.OptionMenu(self.input_frame, self.scan_type_var, "Default", "SYN", "UDP", "Version", "Comprehensive")
        self.scan_type_menu.pack(side=tk.LEFT, padx=(0, 10))

        # Frame for Buttons
        self.button_frame = tk.Frame(self)
        self.button_frame.pack(pady=10, padx=10, fill=tk.X)

        self.scan_button = tk.Button(self.button_frame, text="Scan Network", command=self.scan_network)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(self.button_frame, text="Save Results", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.visualize_button = tk.Button(self.button_frame, text="Visualize Network", command=self.visualize_network)
        self.visualize_button.pack(side=tk.LEFT, padx=5)

        self.schedule_button = tk.Button(self.button_frame, text="Schedule Scan", command=self.schedule_scan)
        self.schedule_button.pack(side=tk.LEFT, padx=5)

        # Treeview for displaying scan results
        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        columns = ("IP", "Hostname", "Status", "OS", "Port", "Service", "State", "Product", "Vulnerability")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, minwidth=0, width=100, stretch=tk.YES)
        self.tree.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        self.devices = []
        self.schedule_thread = None

    def log_message(self, message):
        self.tree.insert("", "end", values=(message, "", "", "", "", "", "", "", ""))
        logging.info(message)

    def log_device(self, scanned_device):
        for port in scanned_device['open_ports']:
            self.tree.insert("", "end", values=(
                scanned_device['ip'],
                scanned_device.get('hostname', 'N/A'),
                scanned_device.get('status', 'up'),
                scanned_device.get('os', 'Unknown'),
                port['port'],
                port.get('name', 'N/A'),
                port.get('state', 'unknown'),
                port.get('product', 'N/A'),
                port.get('vulnerability', 'No known vulnerabilities')
            ))

    def scan_network(self):
        ip_range = self.ip_range_entry.get()
        scan_type = self.scan_type_var.get()
        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range")
            return
    
        self.tree.delete(*self.tree.get_children())  # Clear previous scan results
        self.log_message(f"Scanning network range: {ip_range} with {scan_type} scan")
        self.devices = network_scan(ip_range)
    
        if self.devices:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(scan_device, device, scan_type): device for device in self.devices}
                for future in as_completed(futures):
                    device = futures[future]
                    try:
                        scanned_device = future.result()
                        self.log_device(scanned_device)
                    except Exception as e:
                        logging.error(f"Error scanning device {device['ip']}: {e}")
            self.log_message("Network scan completed")
        else:
            messagebox.showerror("Error", "No devices found in the specified range")

    def save_results(self):
        if not self.devices:
            messagebox.showerror("Error", "No scan results to save")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            save_results(self.devices, filename)
            messagebox.showinfo("Info", f"Results saved to {filename}")

    def visualize_network(self):
        if not self.devices:
            messagebox.showerror("Error", "No scan results to visualize")
            return
        visualize_network(self.devices)

    def visualize_network_interactive(self):
        if not self.devices:
            messagebox.showerror("Error", "No scan results to visualize")
            return
        visualize_network(self.devices, interactive=True)

    def schedule_scan(self):
        ip_range = self.ip_range_entry.get()
        scan_type = self.scan_type_var.get()
        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range")
            return
        
        schedule.every().day.at("00:00").do(self.scan_network)  # Schedule daily scan at midnight
        self.log_message(f"Scheduled daily {scan_type} scan at midnight")
        
        if self.schedule_thread is None or not self.schedule_thread.is_alive():
            self.schedule_thread = threading.Thread(target=self.run_schedule, daemon=True)
            self.schedule_thread.start()

    def run_schedule(self):
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app = PortScannerApp()
    app.mainloop()