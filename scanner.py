import nmap
import logging
import json
import os # Added for path joining

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get Nmap path from config or use default
def get_nmap_path():
    config_file = 'config.json'
    default_nmap_path = None # Will mean system PATH
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                nmap_path_from_config = config.get('nmap_path')
                if nmap_path_from_config and nmap_path_from_config != "PASTE_YOUR_NMAP_PATH_HERE_IF_NOT_IN_SYSTEM_PATH":
                    logging.info(f"Using Nmap path from {config_file}: {nmap_path_from_config}")
                    return nmap_path_from_config
                else:
                    logging.info(f"'{config_file}' found, but 'nmap_path' is not set or is placeholder. Trying system PATH.")
        else:
            logging.info(f"'{config_file}' not found. Trying system PATH for Nmap.")
    except Exception as e:
        logging.warning(f"Error reading {config_file}: {e}. Trying system PATH for Nmap.")
    return default_nmap_path

def network_scan(ip_range):
    logging.info(f"Discovering devices in network range: {ip_range}")
    nmap_path = get_nmap_path()
    try:
        if nmap_path:
            scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
        else:
            scanner = nmap.PortScanner() # Try system PATH
    except nmap.PortScannerError as e:
        logging.error(f"Nmap program was not found in configured path or system PATH. Error: {e}")
        logging.error("Please ensure Nmap is installed and its path is correctly specified in 'config.json' or available in the system PATH.")
        return []
    try:
        # -sn: Ping Scan - disables port scanning. Just discovers hosts.
        scanner.scan(ip_range, arguments='-sn')
    except nmap.PortScannerError as e:
        logging.error(f"Network host discovery scan failed: {e}")
        return []
    
    devices = []
    for host in scanner.all_hosts():
        devices.append({
            'ip': host,
            # We are removing hostname and status from GUI, but nmap -sn provides them.
            # Let's keep them internally for now, they might be useful for other features or logging.
            'hostname': scanner[host].hostname() if scanner[host].hostname() else 'N/A',
            'status': scanner[host].state() # e.g. 'up', 'down'
        })
    logging.info(f"Found {len(devices)} live host(s) in range {ip_range}.")
    return devices

def check_vulnerability(ip, port, service_name=None, product_name=None):
    # Vulnerability check is simplified, consider enhancing it in the future.
    # For now, it's kept as a placeholder.
    # A more advanced approach would involve CVE databases and matching service/product versions.
    known_vulnerabilities = {
        # Example: (port, service_keyword, vulnerability_info_url)
        (80, "apache", "CVE-XXXX-XXXX: Apache Example Vulnerability"),
        (22, "openssh", "CVE-YYYY-YYYY: OpenSSH Example Vulnerability"),
    }
    if product_name: # Product name is more specific
        for (p, key, vuln) in known_vulnerabilities:
            if port == p and key.lower() in product_name.lower():
                return vuln
    if service_name: # Fallback to service name
        for (p, key, vuln) in known_vulnerabilities:
            if port == p and key.lower() in service_name.lower():
                return vuln
    return "No known vulnerabilities (basic check)"

# Updated perform_scan to accept perform_os_detection
def perform_scan(ip, scan_type='Default', perform_os_detection=False):
    logging.info(f"Performing {scan_type} scan on {ip} (OS Detection: {'Enabled' if perform_os_detection else 'Disabled'})")
    nmap_path = get_nmap_path()
    try:
        if nmap_path:
            scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
        else:
            scanner = nmap.PortScanner() # Try system PATH
    except nmap.PortScannerError as e:
        logging.error(f"Nmap program was not found in configured path or system PATH. Error: {e}")
        logging.error("Please ensure Nmap is installed and its path is correctly specified in 'config.json' or available in the system PATH.")
        return None

    arguments = ''
    if scan_type == 'SYN Scan':
        arguments = '-sS' # Basic SYN scan for TCP ports
    elif scan_type == 'UDP Scan':
        arguments = '-sU -sV' # UDP Scan with Version Detection (recommended for UDP)
    else:
        # This case should ideally not be reached if GUI is the only source of scan_type
        logging.error(f"Unknown or unsupported scan type received: {scan_type}. Aborting scan for this target.")
        return {'ip': ip, 'state': 'error', 'open_ports': [], 'os': 'Invalid Scan Type', 'os_detection_performed': perform_os_detection}

    if perform_os_detection:
        arguments += ' -O'
    
    logging.debug(f"Nmap arguments for {ip}: {arguments}")

    try:
        scanner.scan(ip, arguments=arguments)
    except Exception as e:
        logging.error(f"Nmap scan command failed for {ip} with args '{arguments}': {e}")
        # If scan itself fails, return minimal info
        return {'ip': ip, 'state': 'down or error', 'open_ports': [], 'os': 'Scan Error', 'os_detection_performed': perform_os_detection}

    if ip not in scanner.all_hosts():
        logging.warning(f"Host {ip} not found in Nmap scan results after scan command. Might be down or filtered.")
        return {'ip': ip, 'state': 'down or filtered', 'open_ports': [], 'os': 'Host Not Found Post-Scan', 'os_detection_performed': perform_os_detection}

    host_info = scanner[ip]
    os_guess = "OS Detection Disabled" # Default if not performed
    if perform_os_detection:
        os_guess = get_os_info(host_info) # Get OS info if detection was performed
        if not os_guess or os_guess == "Unknown": # If detection ran but failed
            os_guess = "OS detection attempted, no match."

    result = {
        'ip': ip,
        'state': host_info.state(), # Simplified: port state, not device status here
        'os': os_guess,
        'os_detection_performed': perform_os_detection, # Flag to help GUI
        'open_ports': []
    }

    for proto in host_info.all_protocols(): # e.g., 'tcp', 'udp'
        ports = host_info[proto].keys()
        for port in ports:
            service_info = host_info[proto][port]
            port_data = {
                'port': port,
                'protocol': proto,
                'state': service_info.get('state', 'N/A'),
                # For vulnerability check, we need service name and product, 
                # even if not displayed directly in main table
                'name': service_info.get('name', ''), 
                'product': service_info.get('product', ''),
                'version': service_info.get('version', '')
            }
            result['open_ports'].append(port_data)
    return result

def get_os_info(host_info):
    if 'osmatch' in host_info and host_info['osmatch']:
        top_match = host_info['osmatch'][0]
        return f"{top_match.get('name', 'Unknown OS')} (Acc: {top_match.get('accuracy', 'N/A')}%)"
    return "Unknown" # OS detection ran, but no match found

# No longer using the separate os_detection function that used subprocess
# def os_detection(ip): ... 

def save_results(devices, filename):
    with open(filename, 'w') as file:
        json.dump(devices, file, indent=4)

def scan_device(device_discovery_info, scan_type='Default', perform_os_detection=False):
    ip = device_discovery_info['ip']
    scanned_info = perform_scan(ip, scan_type, perform_os_detection)

    # Create a new dictionary to ensure all data is present for visualization and saving
    # Start with initial discovery info (IP, hostname, initial status)
    # Then update/override with more detailed info from the port scan
    combined_info = device_discovery_info.copy() # ip, hostname, status (from network_scan)

    if scanned_info: # If perform_scan was successful and returned data
        combined_info.update(scanned_info) # os, os_detection_performed, open_ports, state (nmap host state)
        # Note: scanned_info['state'] (from nmap host status) might be more current than initial device_discovery_info['status']
        
        if 'open_ports' in combined_info: # Ensure open_ports exists
            for port_detail in combined_info['open_ports']:
                port_detail['vulnerability'] = check_vulnerability(
                    combined_info['ip'], 
                    port_detail['port'],
                    service_name=port_detail.get('name'),
                    product_name=port_detail.get('product')
                )
        else:
            combined_info['open_ports'] = [] # Ensure it always has open_ports key
    else: # perform_scan failed or returned None
        logging.error(f"Scan details for {ip} are missing. Visualization might be incomplete for this host.")
        # Ensure basic structure for GUI if scan totally failed after discovery
        combined_info['os'] = combined_info.get('os', 'Scan Failed')
        combined_info['os_detection_performed'] = perform_os_detection
        combined_info['open_ports'] = []
        combined_info['state'] = combined_info.get('state', 'unknown') # Use initial state if available

    return combined_info