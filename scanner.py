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
        scanner.scan(ip_range, arguments='-sP')
    except nmap.PortScannerError as e:
        logging.error(f"Network scan failed: {e}")
        return []
    
    devices = []

    for host in scanner.all_hosts():
        devices.append({
            'ip': host,
            'hostname': scanner[host].hostname(),
            'state': scanner[host].state()
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

def port_scan(ip):
    logging.info(f"Scanning ports for IP: {ip}")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, arguments='-sV')
    except nmap.PortScannerError as e:
        logging.error(f"Port scan failed for {ip}: {e}")
        return []

    open_ports = []

    for proto in scanner[ip].all_protocols():
        ports = scanner[ip][proto].keys()
        for port in ports:
            open_ports.append({
                'port': port,
                'state': scanner[ip][proto][port]['state'],
                'name': scanner[ip][proto][port]['name'],
                'product': scanner[ip][proto][port]['product']
            })

    return open_ports

def save_results(devices, filename):
    with open(filename, 'w') as file:
        json.dump(devices, file, indent=4)

def os_detection(ip):
    try:
        result = subprocess.run(['nmap', '-O', ip], capture_output=True, text=True)
        output = result.stdout
        logging.debug(f"Raw nmap output: {output}")
        
        # Example pattern to match OS detection section in nmap output
        pattern = r"OS details: (.+)"  # Adjust as per your nmap output format
        
        # Search for the pattern in the output
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

def scan_device(device):
    open_ports = port_scan(device['ip'])
    device['open_ports'] = open_ports
    device['os'] = os_detection(device['ip'])
    for port in device['open_ports']:
        port['vulnerability'] = check_vulnerability(device['ip'], port['port'])
    return device