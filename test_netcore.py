#!/usr/bin/env python3
"""Unit tests for the pure (non-privileged) parts of netcore.

Run with:
    py -m unittest test_netcore
"""

import os
import struct
import tempfile
import threading
import unittest

import netcore


def build_ipv4(src, dst, proto, sport=0, dport=0, payload=b""):
    """Construct a minimal IPv4 packet (with TCP/UDP ports) for testing."""
    ver_ihl = (4 << 4) | 5
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    ip = struct.pack("!BBHHHBBH", ver_ihl, 0, 20 + len(payload), 0, 0, 64, proto, 0) + src_b + dst_b
    transport = b""
    if proto in (6, 17):
        transport = struct.pack("!HH", sport, dport) + b"\x00" * 4
    return ip + transport + payload


class ValidationTests(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(netcore.validate_ipv4("192.168.0.1"))
        self.assertTrue(netcore.validate_ipv4("0.0.0.0"))
        self.assertTrue(netcore.validate_ipv4("255.255.255.255"))

    def test_invalid_ipv4(self):
        self.assertFalse(netcore.validate_ipv4("256.0.0.1"))
        self.assertFalse(netcore.validate_ipv4("1.2"))          # shorthand rejected
        self.assertFalse(netcore.validate_ipv4("hello"))
        self.assertFalse(netcore.validate_ipv4(""))


class ParseTests(unittest.TestCase):
    def test_tcp(self):
        pkt = build_ipv4("10.0.0.1", "10.0.0.2", 6, 1234, 80)
        info = netcore.parse_ip_packet(pkt)
        self.assertEqual(info["src"], "10.0.0.1")
        self.assertEqual(info["dst"], "10.0.0.2")
        self.assertEqual(info["proto"], 6)
        self.assertEqual(info["sport"], 1234)
        self.assertEqual(info["dport"], 80)

    def test_udp(self):
        pkt = build_ipv4("1.1.1.1", "2.2.2.2", 17, 53, 9999)
        info = netcore.parse_ip_packet(pkt)
        self.assertEqual(info["proto"], 17)
        self.assertEqual(info["sport"], 53)

    def test_icmp_has_no_ports(self):
        pkt = build_ipv4("1.1.1.1", "2.2.2.2", 1)
        info = netcore.parse_ip_packet(pkt)
        self.assertEqual(info["proto"], 1)
        self.assertNotIn("sport", info)

    def test_too_short(self):
        self.assertEqual(netcore.parse_ip_packet(b"\x00" * 5), {})

    def test_non_ipv4_ignored(self):
        # version nibble 6 (IPv6) -> not parsed
        self.assertEqual(netcore.parse_ip_packet(b"\x60" + b"\x00" * 30), {})

    def test_proto_name(self):
        self.assertEqual(netcore.proto_name(6), "TCP")
        self.assertEqual(netcore.proto_name(99), "Other (99)")


class PcapTests(unittest.TestCase):
    def test_roundtrip_sizes(self):
        path = os.path.join(tempfile.gettempdir(), "netcore_test.pcap")
        pkt = build_ipv4("1.1.1.1", "2.2.2.2", 6, 1, 2)
        try:
            with netcore.PcapWriter(path) as w:
                w.write(1234.5, pkt)
                w.write(1235.0, pkt)
            # 24-byte global header + 2 * (16-byte record header + len(pkt))
            expected = 24 + 2 * (16 + len(pkt))
            self.assertEqual(os.path.getsize(path), expected)
            with open(path, "rb") as f:
                magic = struct.unpack("<I", f.read(4))[0]
            self.assertEqual(magic, 0xA1B2C3D4)
        finally:
            if os.path.exists(path):
                os.remove(path)


class ScanTests(unittest.TestCase):
    def test_scan_finds_listening_port(self):
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            open_ports = netcore.scan_ports("127.0.0.1", port, port, timeout=0.5)
            self.assertIn(port, open_ports)
        finally:
            srv.close()

    def test_scan_closed_port(self):
        # Bind then close to obtain a very likely-closed port.
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        open_ports = netcore.scan_ports("127.0.0.1", port, port, timeout=0.3)
        self.assertNotIn(port, open_ports)

    def test_invalid_range_raises(self):
        with self.assertRaises(ValueError):
            netcore.scan_ports("127.0.0.1", 100, 50)

    def test_stop_event_aborts(self):
        stop = threading.Event()
        stop.set()
        # With the stop flag pre-set, workers exit immediately -> no open ports.
        result = netcore.scan_ports("127.0.0.1", 1, 100, stop_event=stop)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
