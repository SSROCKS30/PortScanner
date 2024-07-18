import nmap
import logging
import json
import requests
import subprocess
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def network_scan(ip_range):
    logging.info(f"Scanning network range: {ip_range}")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip_range, arguments='-sn')  # Changed from -sP to -sn for newer nmap versions
    except nmap.PortScannerError as e:
        logging.error(f"Network scan failed: {e}")
        return []
    
    devices = []

    for host in scanner.all_hosts():
        devices.append({
            'ip': host,
            'hostname': scanner[host].hostname(),
            'status': scanner[host].state()
        })

    return devices

def check_vulnerability(ip, port):
    known_vulnerabilities = {
        80: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",  # Example: Log4j vulnerability
        22: "https://nvd.nist.gov/vuln/detail/CVE-2020-14145",  # Example: OpenSSH vulnerability
    }
    
    if port in known_vulnerabilities:
        try:
            response = requests.get(known_vulnerabilities[port], timeout=5)
            if response.status_code == 200:
                return f"Potential vulnerability: {known_vulnerabilities[port]}"
        except requests.RequestException:
            pass
    return "No known vulnerabilities"

def perform_scan(ip, scan_type='default'):
    logging.info(f"Performing {scan_type} scan on {ip}")
    scanner = nmap.PortScanner()
    try:
        if scan_type == 'SYN':
            scanner.scan(ip, arguments='-sS -O')
        elif scan_type == 'UDP':
            scanner.scan(ip, arguments='-sU -O -sV')
        elif scan_type == 'Version':
            scanner.scan(ip, arguments='-sV -O')
        elif scan_type == 'Comprehensive':
            scanner.scan(ip, arguments='-sS -sU -sV -O -A')
        else:
            scanner.scan(ip, arguments='-sV -O')
        
        logging.debug(f"Full Nmap scan result for {ip}: {scanner[ip]}")
        
        result = {
            'ip': ip,
            'hostname': scanner[ip].hostname(),
            'state': scanner[ip].state(),
            'os': get_os_info(scanner[ip]),
            'open_ports': get_open_ports(scanner[ip])
        }
        return result
    except Exception as e:
        logging.error(f"Scan failed for {ip}: {e}")
        return None

def get_os_info(host_info):
    if 'osmatch' in host_info:
        os_matches = host_info['osmatch']
        if os_matches:
            top_match = os_matches[0]
            return f"{top_match['name']} (Accuracy: {top_match['accuracy']}%)"
    return "Unknown"

def get_open_ports(host_info):
    open_ports = []
    for proto in host_info.all_protocols():
        ports = host_info[proto].keys()
        for port in ports:
            service = host_info[proto][port]
            open_ports.append({
                'port': port,
                'protocol': proto,
                'state': service['state'],
                'name': service.get('name', 'N/A'),
                'product': service.get('product', 'N/A')
            })
    return open_ports

def os_detection(ip):
    try:
        result = subprocess.run(['nmap', '-O', ip], capture_output=True, text=True)
        output = result.stdout
        logging.debug(f"Raw nmap output: {output}")
        
        pattern = r"OS details: (.+)"  # Adjust as per your nmap output format
        
        match = re.search(pattern, output, re.IGNORECASE)
        
        if match:
            os_details = match.group(1).strip()
            return os_details
        else:
            logging.warning("No OS details found in nmap output.")
            return "Unknown"
        
    except Exception as e:
        logging.error(f"Error running nmap: {e}")
        return "Unknown"

def save_results(devices, filename):
    with open(filename, 'w') as file:
        json.dump(devices, file, indent=4)

def scan_device(device, scan_type='default'):
    scanned_info = perform_scan(device['ip'], scan_type)
    if scanned_info:
        for port in scanned_info['open_ports']:
            port['vulnerability'] = check_vulnerability(device['ip'], port['port'])
        device.update(scanned_info)
    return device