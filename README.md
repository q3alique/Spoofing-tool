# Spoofing-tool

## Description
This script is designed to simulate an attack by spoofing IPs and sending crafted network packets using various protocols. It bypasses firewall packet inspection by making the requests appear legitimate, even though the source IPs are spoofed. The script supports multiple protocols and simulates TCP handshakes to ensure the traffic mimics real connections.

## Supported Protocols
- **HTTP**: Sends HTTP GET or POST requests.
- **HTTPS**: Sends HTTPS requests with a simulated TLS handshake.
- **SSH**: Sends SSH connection banners.
- **SMB**: Sends SMB session setup requests.
- **ICMP**: Sends ICMP echo requests (pings).

## Characteristics
- **IP Spoofing**: Allows spoofing of source IPs and sending traffic to targets with specified protocols.
- **Simulated Handshake**: Simulates the TCP handshake (SYN, SYN-ACK, ACK) even when using spoofed IPs.
- **Protocol-Specific Payloads**: Supports custom payloads for each protocol type.
- **Custom Port Handling**: Allows specifying custom destination ports for individual IPs.
- **Simulated Attack Mode**: Can use well-known malicious payloads to mimic a realistic attack scenario.
- **Flexible IP Input**: Accepts lists of IPs from comma-separated strings, `.txt` files, or `.xlsx` files.

## Functionalities
- **Send packets using different protocols (HTTP, HTTPS, SSH, SMB, ICMP).**
- **Simulate legitimate connections by completing the TCP handshake.**
- **Display tcpdump command to help capture packets on the target machine.**
- **Parse IP and port lists from various file formats.**
- **Spoof multiple IPs with support for custom ports.**

## Installation
1. **Install Python and Required Libraries**
    - Make sure Python is installed on your system. You can download it from [python.org](https://www.python.org/).
    - Install the required libraries using the following command:
      ```bash
      pip install scapy pandas colorama
      ```

2. **Download the Script**
    - Save the script as `spoof_script.py`.

3. **Verify the Dependencies**
    - Make sure the following libraries are installed and available in your Python environment: `scapy`, `pandas`, and `colorama`.

## IP List Creation
- **Comma-Separated List:** You can provide IPs directly as a comma-separated list in the command line (e.g., `192.168.1.100,10.10.15.5`).
- **Text File (.txt):** Each line in the file can contain an IP or an IP with a port (e.g., `192.168.1.100:8080`).
- **Excel File (.xlsx):** The first column can contain IPs or IP-port pairs (e.g., `192.168.1.100:8080`).

## Parameters and Values (`-h`)
- **`--source-ip`**: Comma-separated list of source IPs or a file (.txt or .xlsx) containing them.
- **`--dst-ip`**: Comma-separated list of destination IPs with optional custom ports or a file (.txt or .xlsx) containing them.
- **`--protocol`**: The protocol to use (choices: `http`, `https`, `smb`, `ssh`).
- **`--dst-port`**: Custom default destination port for all IPs. If not specified, the default port for the chosen protocol will be used.
- **`--type`**: The type of payload to send. Options include:
  - `http_get`: A typical HTTP GET request.
  - `http_post`: A simulated HTTP POST request.
  - `ssh_banner`: An SSH connection banner.
  - `smb_session`: An SMB session setup request.
  - `icmp_ping`: An ICMP echo request (ping).
- **`--simulate-attack`**: Use well-known malicious payloads to simulate an attack.

## Usage Examples
1. **Basic HTTP GET Request**
   ```bash
   python3 spoof_script.py --source-ip 192.168.1.100 --dst-ip 192.168.1.86 --protocol http --type http_get
   ```

2. **HTTPS Request with a Custom Destination Port**
   ```bash
   python3 spoof_script.py --source-ip 192.168.1.100,192.168.1.200 --dst-ip 192.168.1.86:8080 --protocol https --type http_post --dst-port 8080
   ```

3. **Simulated SSH Attack**
   ```bash
   python3 spoof_script.py --source-ip source_ips.txt --dst-ip 192.168.1.86 --protocol ssh --type ssh_banner --simulate-attack
   ```

4. **Using an IP List from an Excel File**
   ```bash
   python3 spoof_script.py --source-ip source_ips.xlsx --dst-ip target_ips.xlsx --protocol smb --type smb_session
   ```

5. **ICMP Ping Simulation**
   ```bash
   python3 spoof_script.py --source-ip 10.0.0.1,10.0.0.2 --dst-ip 192.168.1.86 --protocol icmp --type icmp_ping
   ```

## Notes
- The script requires root privileges to send raw packets. Use `sudo` to execute the script if necessary.
- The provided IPs must be in a valid format, and ports must be numeric.
- The `--simulate-attack` option adds realistic attack scenarios to the payloads.
