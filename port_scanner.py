import socket
import argparse
import ipaddress
import csv
import json
import time
import textwrap
import sys
import threading
from queue import Queue
from fpdf import FPDF

# --- Configuration ---
# Set the default ports to scan (e.g., common services)
DEFAULT_PORTS = "21,22,23,25,80,110,139,443,445,3389,8080"
TOP_1024_PORTS_RAW = "1-1024" # Ports 1 through 1024
FULL_PORTS_RAW = "1-65535" # All possible TCP ports
TIMEOUT = 1.0  # seconds
DEFAULT_THREADS = 50 # Default number of concurrent threads for scanning

# Thread-safe structures
print_lock = threading.Lock()
result_lock = threading.Lock()
# Initialize Queue globally to hold ports or tasks

# --- Utility Functions ---

def get_ip_list(target):
    """
    Parses the target string (single IP, CIDR range, or Hostname) and returns a list of IP addresses.
    Returns None on error.
    """
    ip_list = []
    try:
        # 1. Check if it's a CIDR network (e.g., 192.168.1.0/24)
        network = ipaddress.ip_network(target, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        
        # 2. Handle single IP or /32 network cases
        if not ip_list and '/' not in target:
            ipaddress.ip_address(target) # Validate if it's a single valid IP
            ip_list = [target]
        elif not ip_list and '/' in target:
            # Handle cases like /32 which resolve to a single host that hosts() excludes
            if network.prefixlen == 32 and network.version == 4:
                 ip_list = [str(network.network_address)]
            elif network.prefixlen == 128 and network.version == 6:
                 ip_list = [str(network.network_address)]
                 
    except ValueError:
        # 3. If ipaddress fails, attempt to resolve it as a hostname
        try:
            resolved_ip = socket.gethostbyname(target)
            ip_list = [resolved_ip]
            print(f"Note: Resolved hostname '{target}' to IP '{resolved_ip}'.")
        except socket.gaierror:
            # This handles failed DNS lookups
            print(f"Error: Could not resolve hostname or invalid IP/CIDR: '{target}'.")
            return None
        except Exception:
            # General catch-all for other hostname resolution failures
            print(f"Error: Invalid target format. Please provide a single IP, CIDR range, or hostname.")
            return None

    if not ip_list:
        print("Error: The provided target resulted in no scannable hosts.")
        return None
        
    return ip_list

def parse_ports(port_string):
    """
    Parses a string of ports (e.g., "1-100,8080,8443") into a list of integers.
    Returns None on error.
    """
    ports = set()
    try:
        if not port_string:
            raise ValueError("Port string is empty.")
            
        for part in port_string.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end: start, end = end, start # Handle inverted ranges
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        
        # Filter for valid TCP ports
        ports = [p for p in ports if 1 <= p <= 65535]
        if not ports:
             raise ValueError("No valid ports specified.")
             
        return sorted(list(ports))
        
    except ValueError as e:
        print(f"Error parsing ports: {e}. Please use a format like '21,22,80-100'.")
        return None


# --- Scanning Logic ---

def banner_grab(ip, port):
    """
    Connects to an open port and attempts to retrieve a service banner.
    Returns the banner string or a descriptive error message.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))

        # Attempt to send a small request (e.g., HTTP newline)
        if port in [80, 443, 8080]:
            # Simple HTTP request for better results on web servers
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        
        # Receive up to 4096 bytes of data
        banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
        
        # Clean up the banner for display/reporting
        if len(banner) > 200:
            banner = banner[:200] + "..."
            
        # Replace newlines with spaces for clean single-line display
        return ' '.join(banner.split())
        
    except socket.timeout:
        return f"Service timeout after {TIMEOUT}s. No banner received."
    except ConnectionResetError:
        return "Connection reset by peer."
    except Exception as e:
        return f"Banner Grab Failed: {e}"
    finally:
        if 'sock' in locals():
            sock.close()


def port_scan_worker(q, all_results):
    """
    Worker thread function: pulls (ip, port) tasks from the queue and executes the scan.
    """
    while not q.empty():
        try:
            ip, port = q.get_nowait()
        except Queue.Empty:
            break # Queue is empty, exit worker
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        
        is_open = False
        try:
            # Returns 0 on success, non-zero on failure
            result = sock.connect_ex((ip, port))
            if result == 0:
                is_open = True
        except socket.error:
            pass # Ignore socket errors in workers
        finally:
            sock.close()
            
        if is_open:
            # Acquire print lock to prevent messy console output
            with print_lock:
                print(f"  [OPEN] TCP/{port} found on {ip}.")
                
            banner = banner_grab(ip, port)
            
            # Simple service detection
            service = "Unknown"
            if port == 21: service = "FTP"
            elif port == 22: service = "SSH"
            elif port == 23: service = "Telnet"
            elif port == 25: service = "SMTP"
            elif port == 80: service = "HTTP"
            elif port == 443: service = "HTTPS"
            elif port == 3389: service = "RDP"
            
            if "ssh" in banner.lower() and service == "Unknown": service = "SSH"
            if "http" in banner.lower() and service == "Unknown": service = "HTTP/HTTPS"
            
            result_data = {
                'IP Address': ip,
                'Port': port,
                'Status': 'OPEN',
                'Service': service,
                'Banner/Version': banner
            }
            
            # Acquire result lock to safely update the shared list
            with result_lock:
                all_results.append(result_data)

        # Signal that the task is done
        q.task_done()


def run_scan(target_ip_list, ports_to_scan, num_threads):
    """
    Main function to orchestrate the multithreaded scan.
    """
    all_results = []
    
    total_ips = len(target_ip_list)
    total_ports = len(ports_to_scan)
    scan_start_time = time.time()
    
    print(f"\n--- Starting Scan of {total_ips} Host(s) on {total_ports} Port(s) with {num_threads} Threads ---")
    
    # 1. Create a queue of (ip, port) tasks
    q = Queue()
    for ip in target_ip_list:
        # For multithreading simplicity, we add all (IP, Port) combinations as tasks
        for port in ports_to_scan:
            q.put((ip, port))

    # 2. Create and start the worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=port_scan_worker, args=(q, all_results))
        t.daemon = True # Allows the main program to exit even if threads are still running
        t.start()
        threads.append(t)

    # 3. Wait for the queue to be empty
    try:
        q.join()
    except KeyboardInterrupt:
        print("\nScan interrupted by user (Ctrl+C). Generating report for current results.")
        # If interrupted, we don't wait for threads, just proceed to reporting
        
    scan_end_time = time.time()
    elapsed_time = scan_end_time - scan_start_time
    
    print(f"\n--- Scan Complete ---")
    print(f"Total time elapsed: {elapsed_time:.2f} seconds.")
    print(f"Found {len(all_results)} open port(s).")
    
    return all_results

# --- Reporting Functions ---

def export_csv(results, filename):
    """Exports scan results to a CSV file."""
    if not results:
        print("No open ports found to export to CSV.")
        return
        
    fieldnames = list(results[0].keys())
    try:
        with open(f"{filename}.csv", 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"Successfully exported results to {filename}.csv")
    except Exception as e:
        print(f"Error exporting CSV: {e}")

def export_json(results, filename):
    """Exports scan results to a JSON file."""
    try:
        with open(f"{filename}.json", 'w', encoding='utf-8') as jsonfile:
            json.dump(results, jsonfile, indent=4)
        print(f"Successfully exported results to {filename}.json")
    except Exception as e:
        print(f"Error exporting JSON: {e}")

def export_pdf(results, filename):
    """Exports scan results to a PDF file using FPDF."""
    class PDF(FPDF):
        def header(self):
            self.set_font('Arial', 'B', 15)
            self.cell(0, 10, 'Network Security Scanner Report', 0, 1, 'C')
            self.set_font('Arial', '', 10)
            self.cell(0, 5, time.strftime("%Y-%m-%d %H:%M:%S"), 0, 1, 'C')
            self.ln(5)

        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

        def chapter_title(self, title):
            self.set_font('Arial', 'B', 12)
            self.cell(0, 6, title, 0, 1, 'L')
            self.ln(2)

        def chapter_body(self, data, col_widths):
            self.set_fill_color(200, 220, 255) # Light blue background for header
            self.set_font('Arial', 'B', 8)
            
            # Table Header
            headers = list(data[0].keys())
            for i, header in enumerate(headers):
                self.cell(col_widths[i], 7, header, 1, 0, 'C', 1)
            self.ln()

            # Table Data
            self.set_font('Arial', '', 8)
            for row in data:
                # Calculate required height for the row (based on banner)
                banner_text = row['Banner/Version']
                
                # Split banner into lines for rendering
                banner_lines = textwrap.wrap(banner_text, width=70) 
                
                # Determine max height for this row based on the wrapped banner
                row_height = max(len(banner_lines) * 4, 7) 

                # Print static columns first
                self.cell(col_widths[0], row_height, str(row['IP Address']), 1, 0, 'L')
                self.cell(col_widths[1], row_height, str(row['Port']), 1, 0, 'C')
                self.cell(col_widths[2], row_height, str(row['Status']), 1, 0, 'C')
                self.cell(col_widths[3], row_height, str(row['Service']), 1, 0, 'L')
                
                # Store starting X and Y position for multi-line banner cell
                x = self.get_x()
                y = self.get_y()
                
                # Draw the cell boundary (must be done before multi-line text)
                self.rect(x, y, col_widths[4], row_height)
                
                # Move inside the cell and print lines
                self.set_xy(x + 1, y) # 1mm padding
                for line in banner_lines:
                    self.cell(col_widths[4] - 2, 4, line, 0, 2, 'L')
                
                # Move cursor to the end of the full row height and start of next row
                self.set_xy(self.l_margin, y + row_height)
                

    if not results:
        print("No open ports found to export to PDF.")
        return

    try:
        pdf = PDF('P', 'mm', 'A4') # Portrait, millimeters, A4 size
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.alias_nb_pages()

        pdf.chapter_title(f"Scan Results Summary ({len(results)} Open Ports)")

        # Define column widths (A4 width is 210mm, margins take up space)
        # Total available width is approx 190mm
        col_widths = [30, 15, 20, 30, 95] # IP, Port, Status, Service, Banner/Version
        
        pdf.chapter_body(results, col_widths)

        pdf.output(f"{filename}.pdf", 'F')
        print(f"Successfully exported results to {filename}.pdf")

    except Exception as e:
        print(f"Error exporting PDF (Is 'fpdf2' installed?): {e}")


def export_report(results, report_format, filename):
    """
    Handles calling the correct export function based on the requested format.
    """
    # Ensure the report filename is set
    if not filename:
        filename = f"scan_report_{int(time.time())}"

    # Handle multiple formats
    formats = [f.strip().lower() for f in report_format.split(',')]
    
    exported = False
    for fmt in formats:
        if fmt == 'csv':
            export_csv(results, filename)
            exported = True
        elif fmt == 'json':
            export_json(results, filename)
            exported = True
        elif fmt == 'pdf':
            export_pdf(results, filename)
            exported = True
        else:
            print(f"Warning: Unknown format '{fmt}' skipped. Supported formats are: csv, json, pdf.")
            
    if not exported:
        print("No valid export formats were selected.")


# --- Interactive Menu Logic ---

def display_results(results):
    """Prints the current scan results in a formatted table."""
    if not results:
        print("\n[INFO] No scan results available yet. Run a scan first.")
        return

    print("\n--- Current Scan Results ---")
    print(f"Found {len(results)} open port(s).")
    print("-" * 80)
    print(f"{'IP Address':<15} {'Port':<6} {'Status':<8} {'Service':<12} {'Banner/Version'}")
    print("-" * 80)
    
    for row in results:
        banner = row['Banner/Version']
        # Truncate and display banner on one line for console
        if len(banner) > 40:
            banner = banner[:37] + "..."
            
        print(
            f"{row['IP Address']:<15} "
            f"{row['Port']:<6} "
            f"{row['Status']:<8} "
            f"{row['Service']:<12} "
            f"{banner}"
        )
    print("-" * 80)

def configure_target(config):
    """Handles interactive input for setting the target IP/range."""
    print("\n--- Configure Target ---")
    print(f"Current Target: {config['target']} ({len(config.get('target_ip_list', []))} hosts)")
    print("1: Scan Localhost (127.0.0.1) - Scan your own machine.")
    print("2: Scan Common Local Network (192.168.1.0/24) - Scan devices on your home network.")
    print("3: Manual Target Input (IP, CIDR, or hostname)")
    print("4: Back to Main Configuration Menu")
    
    choice = input("Enter target choice (1-4): ").strip()
    target_input = None

    if choice == '1':
        target_input = '127.0.0.1'
        print("[INFO] Target set to Localhost.")
    elif choice == '2':
        # Note: In a real environment, you might need to adjust this based on the user's actual subnet (e.g., 10.0.0.0/24 or 192.168.0.0/24)
        target_input = '192.168.1.0/24'
        print("[INFO] Target set to 192.168.1.0/24. Remember to adjust the IP range if your network uses a different subnet.")
    elif choice == '3':
        target_input = input("Enter Manual Target (IP, CIDR, or hostname): ").strip()
        if not target_input:
            print("[ERROR] Manual target cannot be empty. Returning to configuration menu.")
            return config
    elif choice == '4':
        return config
    else:
        print("[ERROR] Invalid choice. Returning to configuration menu.")
        return config

    if target_input:
        ip_list = get_ip_list(target_input)
        if ip_list is not None:
            config['target'] = target_input
            config['target_ip_list'] = ip_list
            print(f"[SUCCESS] Target set to {config['target']} ({len(ip_list)} hosts).")
        else:
            print("[ERROR] Failed to set target. Target was invalid.")
            config['target'] = None # Clear potentially bad target
            config['target_ip_list'] = []

    return config

def configure_ports(config):
    """Handles interactive input for setting the ports to scan."""
    print("\n--- Configure Ports ---")
    print(f"Current Ports: {config['ports_raw']} ({len(config['ports'])} total)")
    print(f"1: Common Services ({DEFAULT_PORTS}) - Fastest, best for quick checks.")
    print(f"2: Top 1024 Ports ({TOP_1024_PORTS_RAW}) - Standard range for well-known services.")
    print(f"3: Full Range (1-65535) - WARNING: Slow, use only if necessary.")
    print("4: Manual Port Input (e.g., 80,443,8080-8088)")
    print("5: Back to Main Configuration Menu")

    choice = input("Enter port choice (1-5): ").strip()
    ports_raw_input = None

    if choice == '1':
        ports_raw_input = DEFAULT_PORTS
        print("[INFO] Ports set to Common Services.")
    elif choice == '2':
        ports_raw_input = TOP_1024_PORTS_RAW
        print("[INFO] Ports set to Top 1024 Ports.")
    elif choice == '3':
        ports_raw_input = FULL_PORTS_RAW
        print("[WARNING] Full port scan selected. This may take a long time!")
    elif choice == '4':
        ports_raw_input = input("Enter Manual Ports (e.g., 1-100,443): ").strip()
        if not ports_raw_input:
            print("[ERROR] Port list cannot be empty. Returning to configuration menu.")
            return config
    elif choice == '5':
        return config
    else:
        print("[ERROR] Invalid choice. Returning to configuration menu.")
        return config
    
    if ports_raw_input:
        ports_to_scan = parse_ports(ports_raw_input)
        if ports_to_scan is not None:
            config['ports_raw'] = ports_raw_input
            config['ports'] = ports_to_scan
            print(f"[SUCCESS] {len(ports_to_scan)} ports selected.")
        # parse_ports prints the error if parsing fails

    return config

def configure_threads(config):
    """Handles interactive input for setting thread count."""
    print("\n--- Configure Thread Count ---")
    print("Threads determine how many scans run concurrently (higher = faster, but uses more resources).")
    while True:
        threads_raw = input(f"Enter threads (max concurrency, 1-200) [{config['threads']}]: ").strip() or str(config['threads'])
        try:
            num_threads = int(threads_raw)
            if 1 <= num_threads <= 200:
                config['threads'] = num_threads
                print(f"[SUCCESS] Threads set to {num_threads}.")
                break
            else:
                print("[ERROR] Threads must be between 1 and 200. Defaulting to 50 is usually safe.")
        except ValueError:
            print("[ERROR] Invalid thread count. Please enter a number.")
    return config

def configure_scan(config):
    """Handles interactive input for setting scan parameters."""
    while True:
        print("\n--- Main Configuration Menu ---")
        print(f"A. Target: {config['target']} ({len(config.get('target_ip_list', []))} hosts)")
        print(f"B. Ports: {config['ports_raw']} ({len(config['ports'])} total)")
        print(f"C. Threads: {config['threads']}")
        print("-" * 30)
        print("1: Configure Target (A)")
        print("2: Configure Ports (B)")
        print("3: Configure Threads (C)")
        print("4: Back to Main Menu")
        
        choice = input("Enter your choice (1-4): ").strip()

        if choice == '1':
            config = configure_target(config)
        elif choice == '2':
            config = configure_ports(config)
        elif choice == '3':
            config = configure_threads(config)
        elif choice == '4':
            print("[INFO] Returning to Main Menu.")
            break
        else:
            print("[ERROR] Invalid choice.")
            
    return config


def handle_export(results):
    """Handles the interactive flow for saving the report."""
    if not results:
        print("\n[INFO] Cannot export: No scan results available.")
        return

    print("\n--- Export Results ---")
    
    # Filename
    filename = input(f"Enter base filename (e.g., my_scan_report): ").strip()
    if not filename:
        filename = f"scan_report_{int(time.time())}"
        print(f"Using default filename: {filename}")
        
    # Format selection
    formats = input("Select formats to export (comma-separated: csv, json, pdf) [csv,json]: ").strip().lower() or "csv,json"
    
    export_report(results, formats, filename)


def interactive_scan_tool():
    """Main function for the interactive port scanning tool."""
    # Initial state
    config = {
        'target': '127.0.0.1', # Default to localhost for quick start
        'target_ip_list': ['127.0.0.1'],
        'ports': parse_ports(DEFAULT_PORTS),
        'ports_raw': DEFAULT_PORTS,
        'threads': DEFAULT_THREADS
    }
    current_results = []
    
    print("="*50)
    print("  Welcome to the Interactive Port Scanner Tool")
    print("  (Type '5' to exit at any time)")
    print("="*50)

    while True:
        # Display current configuration
        print("\n--- Current Configuration ---")
        print(f"Target: {config['target']} ({len(config.get('target_ip_list', []))} hosts)")
        print(f"Ports: {config['ports_raw']} ({len(config['ports'])} total)")
        print(f"Threads: {config['threads']}")
        print(f"Last Scan Found: {len(current_results)} open port(s)")
        print("-" * 30)

        # Display menu
        print("1: Configure Scan Parameters")
        print("2: Run Scan")
        print("3: View Results")
        print("4: Save Report (CSV, JSON, PDF)")
        print("5: Exit")
        
        choice = input("Enter your choice (1-5): ").strip()

        if choice == '1':
            config = configure_scan(config)
            
        elif choice == '2':
            if not config['target'] or not config['ports']:
                print("[ERROR] Please configure the target and ports first (Option 1).")
                continue
                
            current_results = run_scan(
                config['target_ip_list'], 
                config['ports'], 
                config['threads']
            )

        elif choice == '3':
            display_results(current_results)
            
        elif choice == '4':
            handle_export(current_results)

        elif choice == '5':
            print("\nThank you for using the Port Scanner By Ronit Rai. Goodbye!")
            break
        
        else:
            print("[ERROR] Invalid choice. Please enter a number between 1 and 5.")


if __name__ == '__main__':
    # Set a custom global socket timeout before execution starts
    socket.setdefaulttimeout(TIMEOUT) 
    # Start the interactive tool instead of running a one-off scan
    interactive_scan_tool()
