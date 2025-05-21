# Network Port Scanner and Visualization Tool

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Prerequisites](#prerequisites)
- [Setup and Installation](#setup-and-installation)
- [How to Run](#how-to-run)
- [Using the Application](#using-the-application)
- [Important Nmap Details](#important-nmap-details)
- [Project Structure](#project-structure)

## Description
A Python-based network scanner with a Tkinter GUI. It discovers hosts, performs SYN and UDP port scans, optionally detects OS, and visualizes network topology. Scan results can be saved.

## Features
- **Network Discovery**: Finds live hosts in an IP range.
- **Port Scanning**: SYN (TCP) and UDP scans.
- **OS Detection**: Optional operating system identification.
- **GUI**: User-friendly Tkinter interface.
- **Results Table**: Displays IP, port, protocol, state, and OS.
- **Network Visualization**: Interactive (HTML/Pyvis) and static (Matplotlib) network graphs.
- **Save Results**: Exports scan data to JSON.
- **Status Bar**: Shows logs and progress.

## Technologies Used
- Python 3
- Nmap (`python-nmap` wrapper)
- Tkinter (with `ttkthemes`)
- NetworkX, Matplotlib, Pyvis (for visualizations)

## Prerequisites
1.  **Python 3**: Install from [python.org](https://www.python.org/).
2.  **Nmap**: Install from [nmap.org](https://nmap.org/download.html). Ensure it's added to your system PATH or configure its location as described below.

## Setup and Installation
1.  **Get the Code**: Clone the repository or download the project files.
2.  **Configure Nmap Path (If Necessary)**:
    *   The application attempts to find Nmap in your system's PATH by default.
    *   If Nmap is not in your PATH, or you need to use a specific Nmap installation:
        1.  Copy `config.example.json` to `config.json` in the project's root directory.
        2.  Edit `config.json` and set the `nmap_path` to the full path of your `nmap.exe` (or Nmap executable).
            *Example for Windows (note the double backslashes `\\` which are required in JSON strings for literal backslashes):*
            ```json
            {
              "nmap_path": "C:\\Program Files (x86)\\Nmap\\nmap.exe"
            }
            ```
            *For Linux/macOS, a typical path might be `"/usr/bin/nmap"` or `"/usr/local/bin/nmap"` (single slashes are fine).*
        3.  If `nmap_path` in `config.json` is empty or set to the placeholder, the system PATH will be tried.
3.  **Set Up Python Environment & Install Dependencies**:
    ```bash
    # Navigate to the project directory
    cd <your_project_directory>

    # Create and activate a virtual environment (recommended)
    python -m venv myenv
    # On Windows:
    myenv\Scripts\activate
    # On macOS/Linux:
    # source myenv/bin/activate

    # Install required libraries
    pip install -r requirements.txt
    ```
    (`requirements.txt` includes: `python-nmap`, `networkx`, `matplotlib`, `pyvis`, `ttkthemes`)

## How to Run
Execute `main.py` from the project's root directory:
```bash
python main.py
```
This will launch the Port Scanner GUI.

## Using the Application
-   **Target IP(s)**: Enter IP addresses or ranges (e.g., `192.168.1.1`, `192.168.1.1-100`, `192.168.1.0/24`).
-   **Scan Type**: Choose "SYN Scan" (TCP) or "UDP Scan".
-   **OS Detection**: Check the box to enable OS detection (may require admin/root privileges).
-   **Results**: View scan output in the table. Hosts without open ports are also listed.
-   **Visualize**: Click buttons to generate interactive (HTML) or static network maps.
-   **Save**: Save detailed results to a JSON file.

## Important Nmap Details
-   **Path Priority**: The application checks for Nmap in this order:
    1.  Path specified in `config.json`.
    2.  System PATH.
    For reliable operation, ensure Nmap is accessible via one of these methods.
-   **Permissions**: SYN scans and OS detection often require administrator/root privileges. If these scans fail or behave unexpectedly, try running the application with elevated permissions.

## Project Structure
```
PortScanner/
├── .gitignore
├── main.py               # Main entry point
├── gui.py                # Tkinter GUI and user interactions
├── scanner.py            # Core scanning logic (uses python-nmap)
├── visualization.py      # Network graph generation
├── requirements.txt      # Python dependencies
├── config.example.json   # Example Nmap path configuration
├── README.md             # This file
``` 