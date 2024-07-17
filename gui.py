import tkinter as tk
from tkinter import filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from scanner import check_vulnerability, network_scan, port_scan, save_results, os_detection, scan_device
from visualization import visualize_network
import schedule
import time
import threading

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("600x400")
        
        self.ip_range_label = tk.Label(self, text="IP Range:")
        self.ip_range_label.pack(pady=10)
        self.ip_range_entry = tk.Entry(self, width=30)
        self.ip_range_entry.pack(pady=10)
        
        self.scan_button = tk.Button(self, text="Scan Network", command=self.scan_network)
        self.scan_button.pack(pady=10)
        
        self.save_button = tk.Button(self, text="Save Results", command=self.save_results)
        self.save_button.pack(pady=10)
        
        self.visualize_button = tk.Button(self, text="Visualize Network", command=self.visualize_network)
        self.visualize_button.pack(pady=10)

        
        self.text_area = tk.Text(self, wrap='word', height=10)
        self.text_area.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self.devices = []

        self.schedule_button = tk.Button(self, text="Schedule Scan", command=self.schedule_scan)
        self.schedule_button.pack(pady=10)
        
        self.schedule_thread = None

    def log_message(self, message):
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)
        logging.info(message)

    def scan_network(self):
        ip_range = self.ip_range_entry.get()
        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range")
            return
    
        self.log_message(f"Scanning network range: {ip_range}")
        self.devices = network_scan(ip_range)
    
        if self.devices:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(scan_device, device): device for device in self.devices}
                for future in as_completed(futures):
                    device = futures[future]
                    try:
                        scanned_device = future.result()
                        # Update this part
                        self.log_message(f"Device: {scanned_device['ip']} ({scanned_device.get('hostname', 'N/A')}) is {scanned_device.get('state', 'unknown')}")
                        self.log_message(f"OS: {scanned_device.get('os', 'Unknown')}")
                        self.log_message("Open ports:")
                        for port in scanned_device['open_ports']:
                            self.log_message(f" - Port {port['port']} ({port.get('name', 'N/A')}): {port.get('state', 'unknown')} ({port.get('product', 'N/A')})")
                            self.log_message(f"   Vulnerability check: {port.get('vulnerability', 'No known vulnerabilities')}")
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
        if not ip_range:
            messagebox.showerror("Error", "Please enter a valid IP range")
            return
        
        schedule.every().day.at("00:00").do(self.scan_network)  # Schedule daily scan at midnight
        self.log_message("Scheduled daily scan at midnight")
        
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
