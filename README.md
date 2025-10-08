# ⚡ PyScan: Multi-threaded Port Scanner

PyScan is a command-line tool written in Python designed for basic network reconnaissance. It uses multi-threading to efficiently scan a target IP or range for open TCP ports, performs banner grabbing to identify running services, and generates detailed reports in multiple formats.

✨ Features
Multi-threaded Scanning: Uses concurrent threads (default 50) to rapidly check multiple ports simultaneously.

Menu-Driven Interface: Easy-to-use CLI for configuring targets, ports, and threads without complex command-line arguments.

Service & Banner Grabbing: Identifies open ports and retrieves the service banner (e.g., SSH version) for reconnaissance.

Flexible Reporting: Exports detailed scan results to CSV, JSON, and professional PDF formats.

Educational Focus: Provides a transparent, socket-level implementation of core scanning techniques.

🛠️ Installation & Dependencies
PyScan requires Python 3 and the fpdf2 library for PDF generation.

Clone the Repository:

git clone [https://github.com/YourUsername/PyScan.git](https://github.com/YourUsername/PyScan.git)
cd PyScan

Install Dependencies:
You may need to use --break-system-packages if installing globally on a system like Kali Linux, or preferably, use a virtual environment (recommended):

# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install fpdf2

🚀 Usage
Execute the tool using Python 3 and follow the interactive menu.

python3 port_scanner.py

Example Workflow
Main Menu: Select 1: Configure Scan Parameters.

Target Configuration: Enter a single IP (192.168.1.1) or an IP range (192.168.1.1-10).

Port Configuration: Use default ports or input a custom range (e.g., 1-1000) or list (21,80,443).

Run Scan: Select 2: Run Scan from the main menu.

View/Save Results: Select 3: View Results or 4: Save Report to export the findings.

💡 Inspiration: The Nmap Foundation
This project is directly inspired by the functionality of Nmap (Network Mapper), the industry standard for network reconnaissance. PyScan implements the fundamental TCP Connect Scan to demonstrate how low-level socket connections are used to determine port status.

While Nmap employs sophisticated techniques (like stealth SYN scans and extensive service fingerprinting), PyScan offers an accessible, Python-native implementation focused on the educational understanding of multi-threaded scanning and banner grabbing principles.
