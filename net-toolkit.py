#!/usr/bin/env python3

import socket
import threading
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP
import sys
import time

# A print lock to prevent threads from printing over each other
print_lock = threading.Lock()

def scan_port(target, port):
    """
    Attempts to connect to a specific port on the target IP.
    Returns True if the port is open, False otherwise.
    """
    try:
        # Create a new socket object for IPv4 and TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout to avoid waiting too long for a response
        socket.setdefaulttimeout(0.5)
        
        # connect_ex returns 0 if the connection is successful (port is open)
        result = s.connect_ex((target, port))
        
        if result == 0:
            with print_lock:
                print(f"✔️ Port {port} is open")
        
        s.close()

    except socket.error:
        with print_lock:
            print(f"❌ Could not connect to server at {target}.")
        return False

def worker(target, q):
    """
    The worker function for threading. It continuously gets a port from the
    queue and scans it.
    """
    while not q.empty():
        port = q.get()
        scan_port(target, port)
        q.task_done()

def perform_scan():
    """
    Manages the port scanning process, including user input and threading.
    """
    try:
        target_host = input("Enter the target IP address to scan: ")
        # Ensure the IP is valid before proceeding
        socket.inet_aton(target_host) 
        
        start_port = int(input("Enter the starting port number: "))
        end_port = int(input("Enter the ending port number: "))
        
        print("\n" + "="*50)
        print(f"Scanning target: {target_host}")
        print(f"Time started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50 + "\n")

        q = Queue()
        for port in range(start_port, end_port + 1):
            q.put(port)

        # Create and start 100 threads for faster scanning
        for _ in range(100):
            t = threading.Thread(target=worker, args=(target_host, q))
            t.daemon = True # a daemon thread will die when the main thread dies
            t.start()
        
        q.join() # Wait for the queue to be empty
        print("\nScan complete.")

    except socket.error:
        print("Invalid IP address format. Please try again.")
    except ValueError:
        print("Invalid port number. Please enter integers only.")


def process_packet(packet):
    """
    This is the callback function for scapy's sniff().
    It's called for every packet that is captured.
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        proto_name = {6: "TCP", 17: "UDP"}.get(protocol, f"Other ({protocol})")
        
        print(f"IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto_name})")

        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"  TCP Segment: Port {tcp_sport} -> {tcp_dport}")

        elif packet.haslayer(UDP):
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"  UDP Datagram: Port {udp_sport} -> {udp_dport}")


def perform_sniffing():
    """
    Manages the packet sniffing process.
    """
    try:
        count = int(input("Enter the number of packets to sniff: "))
        print("\n sniffing packets... Press Ctrl+C to stop early.")
        
        # sniff() is the core function from scapy
        # prn: function to call for each packet
        # count: number of packets to capture
        # store: set to 0 to not store packets in memory, making it efficient
        sniff(prn=process_packet, count=count, store=0)
        
        print("\nSniffing complete.")

    except ValueError:
        print("Invalid number. Please enter an integer.")
    except PermissionError:
        print("\n❌ Permission denied. You must run this script with root/administrator privileges to sniff packets.")
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")


def main():
    """
    The main menu of the application.
    """
    while True:
        print("\n--- Network Toolkit ---")
        print("1. Scan for Open Ports (Nmap-like)")
        print("2. Analyze Network Traffic (Wireshark-like)")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            perform_scan()
        elif choice == '2':
            perform_sniffing()
        elif choice == '3':
            print("Exiting the application. Goodbye!")
            sys.exit()
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()