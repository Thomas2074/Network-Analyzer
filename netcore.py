#!/usr/bin/env python3
"""Core network-analysis logic for the Network Analyzer toolkit.

This module contains the reusable building blocks (port scanning and packet
sniffing) used by both the command-line interface (``net-toolkit.py``) and the
graphical interface (``gui.py``).

All progress and results are reported through optional callbacks and a
``threading.Event`` stop flag, so callers stay in full control of presentation
and lifetime. Nothing here reads from stdin or writes to stdout.
"""

import collections
import socket
import struct
import threading
import time

# Maps IP protocol numbers to human-readable names.
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
PROTO_FILTERS = {"tcp": 6, "udp": 17, "icmp": 1}

MIN_PORT = 1
MAX_PORT = 65535


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def validate_ipv4(host):
    """Return True if *host* is a valid dotted-quad IPv4 address."""
    try:
        socket.inet_aton(host)
    except OSError:
        return False
    # inet_aton accepts shorthand like "1.2"; require four octets.
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def resolve_host(host):
    """Resolve *host* (name or IP) to an IPv4 address string.

    Raises socket.gaierror if the name cannot be resolved.
    """
    return socket.gethostbyname(host)


def primary_outbound_ip():
    """Best-effort detection of this machine's primary outbound IPv4 address.

    Uses a UDP socket "connected" to a public address; no packets are actually
    sent. Falls back to the hostname lookup, then loopback.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------
def scan_port(target, port, timeout=0.5):
    """Return True if a TCP connection to *target*:*port* succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((target, port)) == 0
    except OSError:
        return False


def scan_ports(target, start_port, end_port, *, timeout=0.5, max_threads=100,
               on_open=None, on_progress=None, stop_event=None):
    """Threaded TCP connect-scan over the inclusive range *start_port*..*end_port*.

    Callbacks (all optional):
        on_open(port)            -- called once per open port found
        on_progress(done, total) -- called as each port finishes
    *stop_event* is an optional threading.Event; when set, the scan stops as
    soon as in-flight workers finish their current port.

    Returns a sorted list of open ports.
    """
    start_port = max(MIN_PORT, int(start_port))
    end_port = min(MAX_PORT, int(end_port))
    if end_port < start_port:
        raise ValueError("End port must be >= start port.")

    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    open_ports = []
    lock = threading.Lock()
    progress = {"done": 0}

    import queue as _queue
    q = _queue.Queue()
    for p in ports:
        q.put(p)

    def worker():
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            try:
                port = q.get_nowait()
            except _queue.Empty:
                break
            try:
                if scan_port(target, port, timeout=timeout):
                    with lock:
                        open_ports.append(port)
                    if on_open:
                        on_open(port)
            finally:
                with lock:
                    progress["done"] += 1
                    done = progress["done"]
                if on_progress:
                    on_progress(done, total)
                q.task_done()

    num_threads = max(1, min(max_threads, total))
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return sorted(open_ports)


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------
def parse_ip_packet(data):
    """Parse the IPv4 header (and TCP/UDP ports) from raw bytes.

    Returns a dict with keys src, dst, proto and, when applicable, sport/dport.
    Returns an empty dict if the data is too short to contain an IP header.
    """
    result = {}
    if len(data) < 20:
        return result
    ver_ihl = data[0]
    if (ver_ihl >> 4) != 4:  # only IPv4 is parsed here
        return result
    ihl = (ver_ihl & 0x0F) * 4
    proto = data[9]
    result["src"] = ".".join(str(b) for b in data[12:16])
    result["dst"] = ".".join(str(b) for b in data[16:20])
    result["proto"] = proto
    if proto in (6, 17) and len(data) >= ihl + 4:
        result["sport"] = int.from_bytes(data[ihl:ihl + 2], "big")
        result["dport"] = int.from_bytes(data[ihl + 2:ihl + 4], "big")
    return result


def proto_name(proto):
    """Human-readable name for an IP protocol number."""
    return PROTO_NAMES.get(proto, f"Other ({proto})")


# ---------------------------------------------------------------------------
# PCAP writing
# ---------------------------------------------------------------------------
class PcapWriter:
    """Minimal pcap (libpcap) file writer for link-type Ethernet/raw IP."""

    def __init__(self, filename, linktype=1):
        self._f = open(filename, "wb")
        # Global header: magic, version 2.4, thiszone, sigfigs, snaplen, network
        self._f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))

    def write(self, timestamp, packet):
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        length = len(packet)
        self._f.write(struct.pack("<IIII", ts_sec, ts_usec, length, length))
        self._f.write(packet)

    def close(self):
        if self._f:
            self._f.close()
            self._f = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# Packet sniffing
# ---------------------------------------------------------------------------
class CaptureError(RuntimeError):
    """Raised when a capture socket cannot be created (e.g. no privileges)."""


def open_capture_socket():
    """Create a raw socket suitable for sniffing on this platform.

    Tries AF_PACKET (Linux) first, then a Windows-style AF_INET raw socket with
    SIO_RCVALL promiscuous mode. Raises CaptureError on failure.

    Returns a tuple (socket, includes_ethernet) where *includes_ethernet* is
    True when captured frames start with an Ethernet header (so the IP header
    is offset by 14 bytes).
    """
    # Linux / AF_PACKET: captures full Ethernet frames.
    if hasattr(socket, "AF_PACKET"):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            return s, True
        except OSError as e:
            raise CaptureError(
                "Could not open AF_PACKET socket (root privileges required): %s" % e
            )

    # Windows / AF_INET raw with promiscuous mode: captures IP packets.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((primary_outbound_ip(), 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except (AttributeError, OSError):
            pass
        return s, False
    except OSError as e:
        raise CaptureError(
            "Could not open raw socket. Run as Administrator/root. (%s)" % e
        )


def sniff_packets(*, count=None, duration=None, proto_filter="all",
                  src_filter=None, dst_filter=None, port_filter=None,
                  pcap_path=None, on_packet=None, stop_event=None):
    """Capture packets, applying filters and optionally saving to pcap.

    Stops when any of these is reached: *count* packets matched, *duration*
    seconds elapsed, or *stop_event* is set.

    on_packet(info, raw, timestamp) is called for each matched packet, where
    *info* is the dict from parse_ip_packet().

    Returns a stats dict: {total, proto_counts (Counter), talkers (Counter)}.
    Raises CaptureError if a capture socket cannot be created.
    """
    proto_filter = (proto_filter or "all").lower()
    wanted_proto = PROTO_FILTERS.get(proto_filter)  # None means "all" or unknown

    s, includes_ethernet = open_capture_socket()
    s.settimeout(0.5)  # so the loop can poll stop_event / duration
    eth_offset = 14 if includes_ethernet else 0

    total = 0
    proto_counts = collections.Counter()
    talkers = collections.Counter()
    pcap = PcapWriter(pcap_path) if pcap_path else None
    start = time.time()

    def matches(info):
        if not info:
            return False
        if proto_filter != "all" and info.get("proto") != wanted_proto:
            return False
        if src_filter and info.get("src") != src_filter:
            return False
        if dst_filter and info.get("dst") != dst_filter:
            return False
        if port_filter is not None:
            if port_filter not in (info.get("sport"), info.get("dport")):
                return False
        return True

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            if duration is not None and (time.time() - start) >= duration:
                break
            if count is not None and total >= count:
                break

            try:
                packet, _addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            timestamp = time.time()
            info = parse_ip_packet(packet[eth_offset:])
            if not matches(info):
                continue

            total += 1
            proto_counts[proto_name(info.get("proto"))] += 1
            talkers[info.get("src")] += 1

            if pcap:
                try:
                    pcap.write(timestamp, packet)
                except OSError:
                    pass
            if on_packet:
                on_packet(info, packet, timestamp)
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except (AttributeError, OSError):
            pass
        s.close()
        if pcap:
            pcap.close()

    return {"total": total, "proto_counts": proto_counts, "talkers": talkers}


def hexdump(data, length=48):
    """Return a space-separated hex string of the first *length* bytes."""
    return " ".join(f"{b:02x}" for b in data[:length])
