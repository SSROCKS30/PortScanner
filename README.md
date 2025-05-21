# Network Port Scanner and Visualization Tool

## Description
This project is a Python-based network scanning tool with a graphical user interface (GUI) built using Tkinter. It allows users to discover live hosts on a network, perform various types of port scans (SYN, UDP) on target IPs, optionally detect operating systems, and visualize the network topology. Scan results can be saved to a file.

## Features
- **Network Discovery**: Identifies live hosts within a specified IP range.
- **Port Scanning**:
    - SYN Scan: Fast scan for TCP ports.
    - UDP Scan: Scans for open UDP ports (can be slower).
- **OS Detection**: Optionally attempts to identify the operating system of target hosts (requires appropriate permissions).
- **Graphical User Interface**: User-friendly GUI for easy interaction.
- **Results Display**: Shows scan results in a clear, sortable table, including IP address, port, protocol, port state, and OS (if detected).
- **Interactive Network Visualization**: Generates an interactive HTML graph of the scanned network, showing hosts and their open ports. Nodes are styled based on device/port status.
- **Static Network Visualization**: Option for a static plot of the network map using Matplotlib.
- **Save Scan Results**: Allows saving detailed scan results in JSON format.
- **Status Bar**: Displays informative messages and progress updates.
- **Horizontal Scroll in Table**: Supports Shift + MouseWheel for easier horizontal scrolling in the results table.
- **Text Wrapping**: Wraps long text in the results table for better readability.

## Technologies Used
- **Python 3**: Core programming language.
- **Nmap**: The underlying network scanning engine. The `python-nmap` library is used as a Python wrapper.
- **Tkinter (ttkthemed)**: For creating the graphical user interface.
- **NetworkX**: For creating and manipulating network graphs.
- **Matplotlib**: For generating static network visualizations.
- **Pyvis**: For generating interactive HTML network visualizations.

## Prerequisites
1.  **Python 3**: Ensure Python 3.x is installed. You can download it from [python.org](https://www.python.org/).
2.  **Nmap**: Nmap must be installed on your system and preferably added to your system's PATH.
    - Download Nmap from [nmap.org](https://nmap.org/download.html).
    - During installation, ensure you allow it to be added to the PATH or note its installation directory.

## Setup and Installation
1.  **Clone the repository (or download the files):**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv myenv
    source myenv/bin/activate  # On Windows: myenv\Scripts\activate
    ```
3.  **Configure Nmap Path (Important):**
    -   Copy `config.example.json` to `config.json`.
    -   Edit `config.json` and update the `"nmap_path"` value to the full path of your `nmap.exe` if it's not already in your system's PATH or if you want to specify a particular Nmap installation. For example:
        ```json
        {
          "nmap_path": "C:\\Program Files (x86)\\Nmap\\nmap.exe"
        }
        ```
    -   If Nmap is in your system PATH and you don't need to specify it, you can leave the default placeholder value or an empty string, and the application will attempt to use the system PATH.
4.  **Install the required Python libraries:**
    ```bash
    pip install -r requirements.txt
    ```
    The `requirements.txt` file should include:
    ```
    python-nmap
    networkx
    matplotlib
    pyvis
    ttkthemes
    ```

## How to Run
Execute the `main.py` script from the project's root directory:
```bash
python main.py
```
This will launch the Port Scanner GUI.

## Using the Application

### Entering Targets
-   In the "Target IP(s) / Range(s)" field, enter the IP address(es) or network range(s) you want to scan.
-   Nmap supports various formats:
    -   Single IP: `192.168.1.1`
    -   Hyphenated range: `192.168.1.1-100`
    -   CIDR notation: `192.168.1.0/24`
    -   Comma-separated list: `192.168.1.1,192.168.1.5,192.168.1.10-15`

### Selecting Scan Type
-   Choose the desired scan type from the dropdown menu:
    -   **SYN Scan**: A quick TCP scan that is often less detectable than a full TCP connect scan. It determines port status (open, closed, filtered) by analyzing SYN-ACK and RST packets.
    -   **UDP Scan**: Scans for open UDP ports. UDP scanning is generally slower and more difficult than TCP scanning because UDP is connectionless. Open ports might not send a response, while closed ports often send an ICMP "Port Unreachable" message.

### OS Detection
-   Check the "Enable OS Detection" checkbox if you want Nmap to attempt to identify the operating system of the target hosts.
-   **Note**: OS detection typically requires raw packet privileges (run as administrator/root) and adds to the scan time. It sends a series of probes to the target and analyzes the responses to make an educated guess about the OS.

### Viewing Results
-   Live hosts and scan results will be displayed in the table.
-   Columns include: IP Address, Port, Protocol, State (of the port), and OS (if OS detection was enabled and successful).
-   If a host is scanned and no open ports are found, it will be indicated in the table.
-   Log messages and status updates appear in the status bar at the bottom of the window.

### Network Visualization
-   After a scan completes, click the "Visualize Network (Interactive)" button to generate an interactive HTML map (`network_map.html`) which will open in your default web browser.
    -   Hosts are typically represented as larger nodes, and open ports as smaller nodes connected to their respective hosts.
    -   Node colors and shapes can indicate status (e.g., host up/down, port open/closed).
-   Click "Visualize Network (Static)" for a static Matplotlib-based plot of the network.

### Saving Scan Results
-   Click the "Save Results" button to save the detailed scan information (including all discovered devices and their port details) to a JSON file. You will be prompted to choose a location and filename.

## Project Structure
```
PortScanner/
├── .gitignore
├── main.py               # Main entry point, launches the GUI
├── gui.py                # Handles the Tkinter GUI, user interactions, and calls scanner/visualization
├── scanner.py            # Core scanning logic using python-nmap
├── visualization.py      # Generates network graphs using NetworkX, Matplotlib, and Pyvis
├── requirements.txt      # Lists Python dependencies
└── README.md             # This file
```

## Important Note on Nmap
-   **Nmap Installation**: This tool relies on Nmap being installed on your system.
-   **Nmap Path Configuration**:
    -   The application will first attempt to read the Nmap executable path from a `config.json` file in the root directory.
    -   To specify a path, copy `config.example.json` to `config.json` and edit the `nmap_path` value.
    -   If `config.json` is not found, or if the `nmap_path` in it is not set or invalid, the application will attempt to find Nmap in your system's PATH.
    -   **It is highly recommended to either ensure Nmap is in your system's PATH or to correctly configure its path in `config.json` for reliable operation.**
-   **Permissions**: Some Nmap scan types (like SYN scans and OS detection) require raw packet privileges. You may need to run the application with administrator or root privileges for these scans to work correctly. If not, Nmap might fall back to other scan types or fail.

## Future Enhancements
(Potential ideas based on previous discussions)
-   More granular scan control (e.g., specific port ranges, Nmap script selection).
-   Enhanced vulnerability scanning (e.g., integrating with CVE databases via APIs, using Nmap Scripting Engine more extensively).
-   Different report formats (e.g., CSV, XML, PDF).
-   Historical scan data comparison.
-   Improved GUI progress indication and scan cancellation.
-   More sophisticated scheduled scan management.
-   Configuration file for Nmap path and other settings.
-   Unit tests and more robust error handling. 