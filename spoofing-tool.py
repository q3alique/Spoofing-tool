import argparse
import random
import pandas as pd
from scapy.all import *
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
from colorama import Fore, Style, init
import socket

# Initialize colorama
init(autoreset=True)

# Function to load IPs from a file or a comma-separated list
def load_ips(ip_input):
    ips = []
    if ip_input.endswith('.txt'):
        try:
            with open(ip_input, 'r') as file:
                ips = [line.strip().split(':')[0] for line in file if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}File {ip_input} not found.{Style.RESET_ALL}")
    elif ip_input.endswith('.xlsx'):
        try:
            df = pd.read_excel(ip_input, header=None)
            ips = df[0].dropna().astype(str).apply(lambda x: x.split(':')[0]).tolist()
        except FileNotFoundError:
            print(f"{Fore.RED}File {ip_input} not found.{Style.RESET_ALL}")
    else:
        ips = [ip.strip().split(':')[0] for ip in ip_input.split(',') if ip.strip()]
    ips = [ip for ip in ips if is_valid_ip(ip)]
    return ips

# Function to validate an IP address
def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        return False

# Function to load IPs and ports from a file or a comma-separated list
def load_ips_with_ports(ip_input, default_port):
    ip_list = []
    if ip_input.endswith('.txt'):
        try:
            with open(ip_input, 'r') as file:
                for line in file:
                    line = line.strip()
                    if ':' in line:
                        ip, port = line.split(':')
                        ip_list.append((ip.strip(), int(port.strip())))
                    elif ' ' in line:
                        ip, port = line.split()
                        ip_list.append((ip.strip(), int(port.strip())))
                    else:
                        ip_list.append((line, default_port))
        except FileNotFoundError:
            print(f"{Fore.RED}File {ip_input} not found.{Style.RESET_ALL}")
    elif ip_input.endswith('.xlsx'):
        try:
            df = pd.read_excel(ip_input, header=None)
            for entry in df[0].dropna().astype(str).tolist():
                if ':' in entry:
                    ip, port = entry.split(':')
                    ip_list.append((ip.strip(), int(port.strip())))
                elif ' ' in entry:
                    ip, port = entry.split()
                    ip_list.append((ip.strip(), int(port.strip())))
                else:
                    ip_list.append((entry, default_port))
        except FileNotFoundError:
            print(f"{Fore.RED}File {ip_input} not found.{Style.RESET_ALL}")
    else:
        for entry in ip_input.split(','):
            entry = entry.strip()
            if ':' in entry:
                ip, port = entry.split(':')
                ip_list.append((ip.strip(), int(port.strip())))
            elif ' ' in entry:
                ip, port = entry.split()
                ip_list.append((ip.strip(), int(port.strip())))
            else:
                ip_list.append((entry, default_port))
    ip_list = [(ip, port) for ip, port in ip_list if is_valid_ip(ip)]
    return ip_list

# Function to determine the correct port based on the protocol
def get_default_port(protocol):
    if protocol.lower() == "http":
        return 80
    elif protocol.lower() == "https":
        return 443
    elif protocol.lower() == "ssh":
        return 22
    elif protocol.lower() == "smb":
        return 445
    else:
        return None

# Display the tcpdump command for the user to run on the target
def show_tcpdump_command(source_ips, dst_ports):
    if source_ips:
        ip_filter = " or ".join([f"host {ip}" for ip in source_ips])
        port_filter = " or ".join([f"port {port}" for port in dst_ports])
        tcpdump_command = f'sudo tcpdump -i eth0 "({ip_filter}) and ({port_filter})" -n -vv'
    else:
        tcpdump_command = 'sudo tcpdump -i eth0 -n -vv'

    print(f"{Fore.CYAN}\nTo capture the packets on the target, run the following command:")
    print(f"{Fore.YELLOW}{tcpdump_command}")
    print(f"{Fore.CYAN}\nPress ENTER to continue...{Style.RESET_ALL}")
    input()

# Function to generate payloads
def generate_payload(payload_type, simulate_attack):
    if not simulate_attack:
        if payload_type == "http_get":
            return b"GET /index.html HTTP/1.1\r\nHost: www.target.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
        elif payload_type == "http_post":
            return b"POST /login HTTP/1.1\r\nHost: www.target.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nusername=admin&password=12345"
        elif payload_type == "ssh_banner":
            return b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n"
        elif payload_type == "smb_session":
            return b"\x00\x00\x00\x88\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
        else:
            return b"\x08\x00\x7d\x4b\x00\x01\x00\x01abcdefghijklmnopqrstuvwabcdefghi"
    else:
        if payload_type == "http_get":
            return b"GET /index.php?id=1%20OR%201=1 HTTP/1.1\r\nHost: www.target.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
        elif payload_type == "http_post":
            return b"POST /login HTTP/1.1\r\nHost: www.target.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 51\r\n\r\nusername=admin&password=12345' OR '1'='1"
        elif payload_type == "ssh_banner":
            return b"SSH-2.0-Exploit-SSH_1.0\r\n"
        elif payload_type == "smb_session":
            return b"\x00\x00\x00\x90\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
        else:
            return b"\x08\x00\xf7\xff\x41\x41\x41\x41" + b"\x42" * 40

# Function to simulate TLS connections when using spoofed IPs
def send_https_packets(ip_layer, dport, payload):
    sport = random.randint(1024, 65535)
    initial_seq = random.randint(1000, 9000)

    # Send SYN packet
    tcp_syn = TCP(sport=sport, dport=dport, flags="S", seq=initial_seq)
    send(ip_layer / tcp_syn, verbose=0)

    # Simulate SYN-ACK response
    syn_ack_seq = random.randint(1000, 9000)
    tcp_syn_ack = TCP(sport=dport, dport=sport, flags="SA", seq=syn_ack_seq, ack=initial_seq + 1)
    send(IP(src=ip_layer.dst, dst=ip_layer.src) / tcp_syn_ack, verbose=0)

    # Send ACK to complete the handshake
    tcp_ack = TCP(sport=sport, dport=dport, flags="A", seq=initial_seq + 1, ack=syn_ack_seq + 1)
    send(ip_layer / tcp_ack, verbose=0)

    # Minimal TLS ClientHello
    tls_client_hello = TLS(
        msg=TLSClientHello(
            version=0x0303,  # TLS 1.2
            gmt_unix_time=random.randint(0, 2**32),
            random_bytes=RandString(28),
            ciphers=[0x002F]  # TLS_RSA_WITH_AES_128_CBC_SHA
        )
    )
    tcp_psh_ack = TCP(sport=sport, dport=dport, flags="PA", seq=tcp_ack.seq, ack=syn_ack_seq + 1)
    send(ip_layer / tcp_psh_ack / tls_client_hello, verbose=0)

    # Send application data
    tcp_psh_ack = TCP(sport=sport, dport=dport, flags="PA", seq=tcp_psh_ack.seq + len(tls_client_hello), ack=syn_ack_seq + 1)
    send(ip_layer / tcp_psh_ack / payload, verbose=0)

# Function to send packets based on the protocol
def send_packets(source_ips, dst_ips_ports, protocol, payload_type, simulate_attack):
    payload = generate_payload(payload_type, simulate_attack)
    
    for source_ip in source_ips:
        for dst_ip, dport in dst_ips_ports:
            ip_layer = IP(src=source_ip, dst=dst_ip)

            if protocol.lower() == "https":
                send_https_packets(ip_layer, dport, payload)
            elif protocol.lower() in ["http", "ssh", "smb"]:
                sport = random.randint(1024, 65535)
                initial_seq = random.randint(1000, 9000)
                
                # Send SYN packet
                tcp_syn = TCP(sport=sport, dport=dport, flags="S", seq=initial_seq)
                send(ip_layer / tcp_syn, verbose=0)

                # Simulate SYN-ACK response
                syn_ack_seq = random.randint(1000, 9000)
                tcp_syn_ack = TCP(sport=dport, dport=sport, flags="SA", seq=syn_ack_seq, ack=initial_seq + 1)
                send(IP(src=ip_layer.dst, dst=ip_layer.src) / tcp_syn_ack, verbose=0)

                # Send ACK to complete the handshake
                tcp_ack = TCP(sport=sport, dport=dport, flags="A", seq=initial_seq + 1, ack=syn_ack_seq + 1)
                send(ip_layer / tcp_ack, verbose=0)

                # Send the payload
                tcp_psh_ack = TCP(sport=sport, dport=dport, flags="PA", seq=tcp_ack.seq, ack=syn_ack_seq + 1)
                send(ip_layer / tcp_psh_ack / payload, verbose=0)
            else:
                print(f"{Fore.RED}Protocol {protocol} not supported.{Style.RESET_ALL}")
                continue
            
            print(f"{Fore.GREEN}Sent spoofed {protocol.upper()} packet from {source_ip} to {dst_ip}:{dport} with payload type {payload_type}{' (Simulated Attack)' if simulate_attack else ''}{Style.RESET_ALL}")

# Argument parsing
def main():
    parser = argparse.ArgumentParser(description="Spoof packets to simulate an APT attack and bypass firewall inspection.")
    parser.add_argument("--source-ip", required=True, help="Comma-separated list of source IPs or a file (.txt or .xlsx) containing them.")
    parser.add_argument("--dst-ip", required=True, help="Comma-separated list of destination IPs with optional custom ports, or a file (.txt or .xlsx) containing them.")
    parser.add_argument("--protocol", required=True, choices=["http", "https", "smb", "ssh"], help="The protocol to use.")
    parser.add_argument("--dst-port", type=int, help="Custom default destination port for all IPs.")
    parser.add_argument("--type", required=True, choices=["http_get", "http_post", "ssh_banner", "smb_session", "icmp_ping"], help="""Type of payload:
        - http_get: A typical HTTP GET request.
        - http_post: A simulated HTTP POST request.
        - ssh_banner: An SSH connection banner.
        - smb_session: An SMB session setup request.
        - icmp_ping: An ICMP echo request (ping).
    """)
    parser.add_argument("--simulate-attack", action="store_true", help="Use well-known malicious payloads to simulate an attack.")
    
    args = parser.parse_args()
    
    # Load source and destination IPs
    default_port = args.dst_port if args.dst_port else get_default_port(args.protocol)
    source_ips = load_ips(args.source_ip)
    dst_ips_ports = load_ips_with_ports(args.dst_ip, default_port)
    dst_ports = [port for _, port in dst_ips_ports]
    
    # Display the tcpdump command with the source IPs and destination ports
    show_tcpdump_command(source_ips, dst_ports)

    # Send packets
    send_packets(source_ips, dst_ips_ports, args.protocol, args.type, args.simulate_attack)

if __name__ == "__main__":
    main()
