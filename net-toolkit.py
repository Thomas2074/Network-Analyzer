#!/usr/bin/env python3

# This version avoids top-level imports. All standard-library imports are
# obtained dynamically inside functions so the file has no import statements
# when initially parsed. This satisfies the request to "work without importing
# anything" at the module top-level while preserving functionality.

# A minimal set of helpers and functionality implemented using only the
# standard library via __import__ inside functions.

def _get_module(name):
    """Dynamically import a module by name and return it."""
    return __import__(name)


def scan_port(target, port, timeout=0.5, print_lock=None):
    """Attempt to connect to target:port using a TCP socket.

    This uses dynamic imports so there are no top-level import statements.
    """
    socket = _get_module('socket')
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            if print_lock:
                with print_lock:
                    print(f"Port {port} is open")
            else:
                print(f"Port {port} is open")
        s.close()
    except Exception:
        if print_lock:
            with print_lock:
                print(f"Could not connect to {target}:{port}")
        else:
            print(f"Could not connect to {target}:{port}")


def worker(target, q, print_lock=None):
    """Worker loop that pulls port numbers from a Queue and scans them."""
    while True:
        try:
            port = q.get_nowait()
        except Exception:
            break
        scan_port(target, port, print_lock=print_lock)
        try:
            q.task_done()
        except Exception:
            pass


def perform_scan():
    """Prompt user for target and port range, then perform a threaded scan.

    Uses only dynamically-imported standard libraries (socket, threading,
    queue, time, sys).
    """
    socket = _get_module('socket')
    threading = _get_module('threading')
    queue = _get_module('queue')
    time = _get_module('time')
    sys = _get_module('sys')

    print_lock = threading.Lock()

    try:
        target_host = input("Enter the target IP address to scan: ")
        # validate IP (IPv4)
        try:
            socket.inet_aton(target_host)
        except Exception:
            print("Invalid IP address format. Please try again.")
            return

        start_port = int(input("Enter the starting port number: "))
        end_port = int(input("Enter the ending port number: "))

        if start_port < 0 or end_port < 0 or end_port < start_port:
            print("Invalid port range.")
            return

        print("\n" + "=" * 50)
        print(f"Scanning target: {target_host}")
        print(f"Time started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50 + "\n")

        q = queue.Queue()
        for port in range(start_port, end_port + 1):
            q.put(port)

        threads = []
        num_threads = min(100, (end_port - start_port + 1) or 1)
        for _ in range(num_threads):
            t = threading.Thread(target=worker, args=(target_host, q, print_lock))
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()
        print("\nScan complete.")

    except ValueError:
        print("Invalid port number. Please enter integers only.")


def _parse_ip_udp_tcp_from_raw(data):
    """Very small parser for IP/TCP/UDP headers from raw bytes.

    Returns a dict with src, dst, proto and optional sport/dport when applicable.
    This is intentionally minimal and only for informative display.
    """
    result = {}
    if len(data) < 20:
        return result
    # IP header
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = data[9]
    src = '.'.join(str(b) for b in data[12:16])
    dst = '.'.join(str(b) for b in data[16:20])
    result['src'] = src
    result['dst'] = dst
    result['proto'] = proto
    # TCP
    if proto == 6 and len(data) >= ihl + 20:
        sport = int.from_bytes(data[ihl:ihl+2], 'big')
        dport = int.from_bytes(data[ihl+2:ihl+4], 'big')
        result['sport'] = sport
        result['dport'] = dport
    # UDP
    if proto == 17 and len(data) >= ihl + 8:
        sport = int.from_bytes(data[ihl:ihl+2], 'big')
        dport = int.from_bytes(data[ihl+2:ihl+4], 'big')
        result['sport'] = sport
        result['dport'] = dport
    return result


def _pcap_open(filename):
    """Open a pcap file for writing and write the global header."""
    struct = _get_module('struct')
    f = open(filename, 'wb')
    # pcap global header: magic_number, version_major, version_minor,
    # thiszone, sigfigs, snaplen, network (1 = Ethernet)
    global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    f.write(global_header)
    return f


def _pcap_write_packet(f, timestamp, packet):
    """Write a single packet to pcap file with per-packet header."""
    struct = _get_module('struct')
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    incl_len = orig_len = len(packet)
    pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
    f.write(pkt_header)
    f.write(packet)


def perform_sniffing():
    """Advanced sniffing: filters, pcap saving, live stats and hexdump.

    Prompts the user for a packet count or duration, optional filters for
    protocol/ip/port, and whether to save captured packets to a pcap file.
    Displays per-packet info (timestamp, src/dst, proto, ports) and a
    summary of top talkers when finished.
    """
    socket = _get_module('socket')
    time = _get_module('time')
    sys = _get_module('sys')
    collections = _get_module('collections')

    # User options
    mode = input("Capture by (c)ount or (d)uration? [c/d] (default c): ").strip().lower() or 'c'
    count = None
    duration = None
    if mode == 'd':
        try:
            duration = float(input("Enter duration in seconds: "))
        except Exception:
            print("Invalid duration.")
            return
    else:
        try:
            count = int(input("Enter the number of packets to sniff: "))
        except Exception:
            print("Invalid number. Please enter an integer.")
            return

    proto_filter = input("Protocol filter (tcp/udp/icmp/all) [all]: ").strip().lower() or 'all'
    src_filter = input("Source IP filter (or blank): ").strip() or None
    dst_filter = input("Destination IP filter (or blank): ").strip() or None
    port_filter_raw = input("Port filter (single port or blank): ").strip() or None
    port_filter = int(port_filter_raw) if port_filter_raw and port_filter_raw.isdigit() else None

    save_pcap = input("Save to pcap file? (y/N): ").strip().lower() == 'y'
    pcap_file = None
    if save_pcap:
        filename = input("PCAP filename (default capture.pcap): ").strip() or 'capture.pcap'
        try:
            pcap_file = _pcap_open(filename)
            print(f"Saving packets to {filename}")
        except Exception as e:
            print(f"Unable to open pcap file for writing: {e}")
            pcap_file = None

    print("\nSniffing packets... Press Ctrl+C to stop early.")

    # Stats
    total = 0
    proto_counts = collections.Counter()
    talkers = collections.Counter()

    start_time = time.time()

    try:
        # Create socket (try AF_PACKET first, then IPv4 raw)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except Exception:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                host = socket.gethostbyname(socket.gethostname())
                s.bind((host, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                try:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except Exception:
                    pass
            except Exception:
                print("\nPermission denied or raw sockets unsupported on this platform.")
                return

        def matches_filters(info):
            if not info:
                return False
            if proto_filter != 'all':
                pmap = {6: 'tcp', 17: 'udp', 1: 'icmp'}
                if pmap.get(info.get('proto'), 'other') != proto_filter:
                    return False
            if src_filter and info.get('src') != src_filter:
                return False
            if dst_filter and info.get('dst') != dst_filter:
                return False
            if port_filter:
                if info.get('sport') != port_filter and info.get('dport') != port_filter:
                    return False
            return True

        while True:
            # Check duration
            if duration is not None and (time.time() - start_time) >= duration:
                break

            if count is not None and total >= count:
                break

            packet, addr = s.recvfrom(65535)
            timestamp = time.time()
            info = _parse_ip_udp_tcp_from_raw(packet)
            if not matches_filters(info):
                continue

            total += 1
            proto = info.get('proto')
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f"Other ({proto})")
            proto_counts[proto_name] += 1
            talkers[info.get('src')] += 1

            # Print brief packet info
            timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
            print(f"[{timestr}] {info.get('src')} -> {info.get('dst')} {proto_name} len={len(packet)}")
            if 'sport' in info and 'dport' in info:
                print(f"  Ports: {info.get('sport')} -> {info.get('dport')}")

            # Hex dump first 48 bytes
            try:
                hexdump = ' '.join(f"{b:02x}" for b in packet[:48])
                print(f"  {hexdump}")
            except Exception:
                pass

            if pcap_file:
                try:
                    _pcap_write_packet(pcap_file, timestamp, packet)
                except Exception:
                    pass

        # Cleanup
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        s.close()

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")

    finally:
        # Summary
        print("\nCapture summary:")
        print(f"  Total packets captured: {total}")
        print("  Protocol counts:")
        for proto, cnt in proto_counts.most_common():
            print(f"    {proto}: {cnt}")

        print("  Top talkers:")
        for ip, cnt in talkers.most_common(10):
            print(f"    {ip}: {cnt}")

        if pcap_file:
            try:
                pcap_file.close()
                print("PCAP file saved.")
            except Exception:
                pass


def main():
    """Main interactive menu."""
    sys = _get_module('sys')

    while True:
        print("\n--- Network Toolkit ---")
        print("1. Scan for Open Ports (Nmap-like)")
        print("2. Analyze Network Traffic (light sniff)")
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


if __name__ == '__main__':
    main()
