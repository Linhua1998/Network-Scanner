# Network-Scanner

Network Scanner — a network analysis tool

Project Description: This Python tool allows you to scan the network for active devices, open ports, running services, and possible vulnerabilities. The program supports the input of both IP addresses and URLs, automatically detecting their IP.

Project functionality:

✅ Network Scan (ARP scan) — detects active devices in a given IP range.
✅ Port Scan (Nmap) — checks for open ports and running services.
✅ Vulnerability detection — vulnerability analysis using embedded Nmap scripts.
✅ Domain name support — the ability to enter a URL that is automatically converted to IP.
✅ Connection Testing (Ping) — checking the availability of the device before scanning.

Technologies used:

Python (the main language)
Scapy (ARP scanning)
Nmap (python-nmap) (search for open ports and vulnerabilities)
Socket (determining the IP address by domain name)
OS (using ping to check the availability of devices)

How to launch a project:

Install dependencies: pip install scapy python-nmap
Run the script: python network_scanner.py

Additional opportunities for future development:

Adding export of results to JSON/CSV.
Integration with databases for storing scan history.
Improved vulnerability analysis using external APIs (Shodan, VirusTotal).
