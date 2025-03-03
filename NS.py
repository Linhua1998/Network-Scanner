import nmap
import scapy.all as scapy
import socket
import os

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"Error resolving {target}. Please check the input.")
        return None

def scan_network(ip_range):
    print("[*] Scanning network...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices

def scan_ports(target_ip):
    print(f"[*] Scanning ports on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-sV --script vuln")
    
    results = {}
    for proto in nm[target_ip].all_protocols():
        results[proto] = []
        for port in nm[target_ip][proto]:
            port_info = nm[target_ip][proto][port]
            results[proto].append({
                "port": port,
                "state": port_info["state"],
                "service": port_info.get("name", "Unknown"),
                "vulnerabilities": port_info.get("script", {})
            })
    return results

def test_network_connection(target_ip):
    print(f"[*] Testing network connection to {target_ip}...")
    response = os.system(f"ping -c 2 {target_ip}" if os.name != "nt" else f"ping -n 2 {target_ip}")
    if response == 0:
        print(f"[+] {target_ip} is reachable.")
    else:
        print(f"[-] {target_ip} is unreachable.")

if __name__ == "__main__":
    target = input("Enter network range, IP address, or URL: ")
    target_ip = resolve_target(target)
    
    if target_ip:
        test_network_connection(target_ip)
        devices = scan_network(target_ip + "/24")
        
        if not devices:
            print("No devices found on the network.")
        else:
            print("\nDiscovered devices:")
            for device in devices:
                print(f"IP: {device['ip']}, MAC: {device['mac']}")
        
            for device in devices:
                print(f"\nScanning {device['ip']} for open ports and vulnerabilities...")
                scan_results = scan_ports(device['ip'])
                for proto, ports in scan_results.items():
                    for port in ports:
                        print(f"Port {port['port']} ({port['service']}) - {port['state']}")
                        if port['vulnerabilities']:
                            print("Potential vulnerabilities:")
                            for vuln, details in port['vulnerabilities'].items():
                                print(f" - {vuln}: {details}")


