# Network Analyzer

A small network toolkit with two capabilities:

- **Port Scanner** – fast, threaded TCP connect-scan over a port range.
- **Packet Sniffer** – live raw-socket capture with protocol/IP/port filters,
  a running summary (protocol counts, top talkers), and optional `.pcap` export.

It ships with both a **graphical interface** and a **command-line interface**,
sharing the same engine.

## Files

| File | Purpose |
|------|---------|
| `gui.py` | Tkinter GUI (recommended). |
| `net-toolkit.py` | Interactive command-line interface. |
| `netcore.py` | Shared engine: scanning, sniffing, packet parsing, pcap writing. |
| `test_netcore.py` | Unit tests for the engine. |

## Requirements

- Python 3.8+ (developed on 3.13). Tkinter ships with the standard
  python.org Windows installer.
- **Packet sniffing requires Administrator (Windows) or root (Linux)** because
  it uses raw sockets. Port scanning needs no special privileges.

## Running

GUI:

```
py gui.py
```

CLI:

```
py net-toolkit.py
```

To sniff packets, launch from an **elevated** terminal (Run as Administrator on
Windows). Port scanning works from a normal terminal.

## Tests

```
py -m unittest test_netcore -v
```

The suite covers IPv4 validation, IP/TCP/UDP header parsing, pcap output, and a
real loopback port scan. Sniffing isn't unit-tested because it requires
elevated privileges and live traffic.

## Notes

- The scanner caps the range to ports 1–65535 and runs up to 100 worker threads.
- The sniffer's capture loop polls a stop flag on a 0.5 s socket timeout, so
  the **Stop** button (GUI) and `Ctrl+C` (CLI) take effect promptly.
- On Windows the sniffer captures IPv4 packets via `SIO_RCVALL` promiscuous
  mode bound to the primary outbound interface; on Linux it uses `AF_PACKET`
  and captures full Ethernet frames.

## Legal

Only scan and capture traffic on systems and networks you own or are explicitly
authorized to test. Unauthorized scanning or interception may be illegal.
