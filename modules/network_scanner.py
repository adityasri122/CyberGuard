import nmap
import socket

def get_local_network_target():
    """
    Finds the user's local IP and assumes a /24 subnet.
    e.g., 192.168.1.5 -> 192.168.1.0/24
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to a public DNS to find our local IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Create the subnet target
        ip_parts = local_ip.split('.')
        ip_parts[-1] = '0/24'
        target = ".".join(ip_parts)
        return target
        
    except Exception as e:
        print(f"Could not get local IP: {e}")
        # Fallback to a common default
        return "192.168.1.0/24"

def scan_local_network():
    """
    Performs an Nmap scan on the local network to find devices.
    Returns a list of dictionaries, one for each device found.
    """
    target = get_local_network_target()
    print(f"Network Scanner: Starting scan on {target}...")
    
    nm = nmap.PortScanner()
    
    # -sn: Ping scan (finds hosts)
    # -T4: Aggressive timing (faster)
    # --min-parallelism 100: Speeds up scan on local networks
    # We also scan common ports to identify services
    try:
        nm.scan(hosts=target, arguments='-p 22,23,80,443,8080 -T4 --min-parallelism 50')
    except nmap.nmap.PortScannerError:
        print("Nmap not found. Please install it and add to PATH.")
        return None # Return None to signal Nmap is missing
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        return []

    hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            device_info = {
                'ip': host,
                'mac': nm[host]['addresses'].get('mac', 'N/A'),
                'vendor': 'N/A',
                'ports': [],
                'os': nm[host].get('osmatch', [{}])[0].get('name', 'Unknown')
            }
            
            # Get vendor info from MAC address
            if device_info['mac'] != 'N/A' and 'vendor' in nm[host]['vendor']:
                 device_info['vendor'] = nm[host]['vendor'].get(device_info['mac'], 'N/A')

            # Get open ports
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        device_info['ports'].append(f"{port}/{proto}")
                        
            device_info['ports'] = ", ".join(device_info['ports'])
            hosts.append(device_info)
            
    print(f"Network Scanner: Scan complete. Found {len(hosts)} devices.")
    return hosts

# --- You can run this file directly to test it ---
if __name__ == "__main__":
    results = scan_local_network()
    if results:
        for device in results:
            print(f"\n--- Device ---")
            print(f"  IP:     {device['ip']}")
            print(f"  MAC:    {device['mac']}")
            print(f"  Vendor: {device['vendor']}")
            print(f"  OS:     {device['os']}")
            print(f"  Ports:  {device['ports']}")