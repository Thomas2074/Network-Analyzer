#!/usr/bin/env python3
"""Network Toolkit -- command-line interface.

A small interactive toolkit for TCP port scanning and packet sniffing.
The actual logic lives in :mod:`netcore`, which is shared with the GUI
(``gui.py``).

Usage:
    py net-toolkit.py
"""

import sys
import time

import netcore


def _prompt_int(prompt):
    """Read an integer from the user, returning None on invalid input."""
    try:
        return int(input(prompt))
    except ValueError:
        print("Invalid number. Please enter an integer.")
        return None


def perform_scan():
    """Prompt for a target and port range, then run a threaded scan."""
    target = input("Enter the target IP address or hostname to scan: ").strip()
    if not target:
        print("No target provided.")
        return
    try:
        target = netcore.resolve_host(target)
    except OSError:
        print("Could not resolve host.")
        return

    start_port = _prompt_int("Enter the starting port number: ")
    if start_port is None:
        return
    end_port = _prompt_int("Enter the ending port number: ")
    if end_port is None:
        return

    if start_port < netcore.MIN_PORT or end_port > netcore.MAX_PORT or end_port < start_port:
        print(f"Invalid port range. Use {netcore.MIN_PORT}-{netcore.MAX_PORT}.")
        return

    print("\n" + "=" * 50)
    print(f"Scanning target: {target}")
    print(f"Time started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50 + "\n")

    open_ports = netcore.scan_ports(
        target, start_port, end_port,
        on_open=lambda port: print(f"Port {port} is open"),
    )

    print("\nScan complete.")
    if open_ports:
        print("Open ports: " + ", ".join(str(p) for p in open_ports))
    else:
        print("No open ports found in the given range.")


def perform_sniffing():
    """Prompt for capture options, then sniff and summarise traffic."""
    mode = input("Capture by (c)ount or (d)uration? [c/d] (default c): ").strip().lower() or "c"
    count = duration = None
    if mode == "d":
        try:
            duration = float(input("Enter duration in seconds: "))
        except ValueError:
            print("Invalid duration.")
            return
    else:
        count = _prompt_int("Enter the number of packets to sniff: ")
        if count is None:
            return

    proto_filter = input("Protocol filter (tcp/udp/icmp/all) [all]: ").strip().lower() or "all"
    src_filter = input("Source IP filter (or blank): ").strip() or None
    dst_filter = input("Destination IP filter (or blank): ").strip() or None
    port_raw = input("Port filter (single port or blank): ").strip()
    port_filter = int(port_raw) if port_raw.isdigit() else None

    pcap_path = None
    if input("Save to pcap file? (y/N): ").strip().lower() == "y":
        pcap_path = input("PCAP filename (default capture.pcap): ").strip() or "capture.pcap"
        print(f"Saving packets to {pcap_path}")

    print("\nSniffing packets... Press Ctrl+C to stop early.\n")

    def on_packet(info, raw, ts):
        timestr = time.strftime("%H:%M:%S", time.localtime(ts))
        line = f"[{timestr}] {info.get('src')} -> {info.get('dst')} {netcore.proto_name(info.get('proto'))} len={len(raw)}"
        if "sport" in info:
            line += f"  ports {info['sport']} -> {info['dport']}"
        print(line)

    import threading
    stop_event = threading.Event()
    try:
        stats = netcore.sniff_packets(
            count=count, duration=duration, proto_filter=proto_filter,
            src_filter=src_filter, dst_filter=dst_filter, port_filter=port_filter,
            pcap_path=pcap_path, on_packet=on_packet, stop_event=stop_event,
        )
    except netcore.CaptureError as e:
        print(f"\n{e}")
        return
    except KeyboardInterrupt:
        stop_event.set()
        print("\nCapture interrupted by user.")
        return

    print("\nCapture summary:")
    print(f"  Total packets captured: {stats['total']}")
    print("  Protocol counts:")
    for proto, cnt in stats["proto_counts"].most_common():
        print(f"    {proto}: {cnt}")
    print("  Top talkers:")
    for ip, cnt in stats["talkers"].most_common(10):
        print(f"    {ip}: {cnt}")
    if pcap_path:
        print("PCAP file saved.")


def main():
    """Main interactive menu loop."""
    while True:
        print("\n--- Network Toolkit ---")
        print("1. Scan for Open Ports (Nmap-like)")
        print("2. Analyze Network Traffic (light sniff)")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ").strip()
        if choice == "1":
            perform_scan()
        elif choice == "2":
            perform_sniffing()
        elif choice == "3":
            print("Exiting the application. Goodbye!")
            sys.exit()
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
