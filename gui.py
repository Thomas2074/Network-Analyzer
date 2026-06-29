#!/usr/bin/env python3
"""Network Analyzer -- graphical interface.

A tkinter front-end for the toolkit in :mod:`netcore`. Provides two tabs:

  * Port Scanner -- threaded TCP connect scan over a port range.
  * Packet Sniffer -- live raw-socket capture with filters and pcap export.

Work runs on background threads; UI updates are marshalled back to the main
thread through a queue polled with ``after`` (tkinter is not thread-safe).

Usage:
    py gui.py
"""

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import netcore


class ScannerTab(ttk.Frame):
    """UI and logic for the port-scanning tab."""

    def __init__(self, master):
        super().__init__(master, padding=10)
        self._events = queue.Queue()
        self._stop = threading.Event()
        self._thread = None
        self._build()
        self.after(100, self._drain_events)

    def _build(self):
        form = ttk.Frame(self)
        form.pack(fill="x")

        ttk.Label(form, text="Target (IP or hostname):").grid(row=0, column=0, sticky="w", pady=3)
        self.target = ttk.Entry(form, width=30)
        self.target.insert(0, "127.0.0.1")
        self.target.grid(row=0, column=1, columnspan=3, sticky="we", padx=5)

        ttk.Label(form, text="Start port:").grid(row=1, column=0, sticky="w", pady=3)
        self.start_port = ttk.Entry(form, width=10)
        self.start_port.insert(0, "1")
        self.start_port.grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(form, text="End port:").grid(row=1, column=2, sticky="w", pady=3)
        self.end_port = ttk.Entry(form, width=10)
        self.end_port.insert(0, "1024")
        self.end_port.grid(row=1, column=3, sticky="w", padx=5)

        ttk.Label(form, text="Timeout (s):").grid(row=2, column=0, sticky="w", pady=3)
        self.timeout = ttk.Entry(form, width=10)
        self.timeout.insert(0, "0.5")
        self.timeout.grid(row=2, column=1, sticky="w", padx=5)

        form.columnconfigure(1, weight=1)

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=8)
        self.scan_btn = ttk.Button(btns, text="Start Scan", command=self._start)
        self.scan_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 4))

        self.status = ttk.Label(self, text="Ready.")
        self.status.pack(anchor="w")

        self.output = tk.Text(self, height=16, wrap="none", state="disabled")
        self.output.pack(fill="both", expand=True, pady=(6, 0))
        scroll = ttk.Scrollbar(self.output, command=self.output.yview)
        scroll.pack(side="right", fill="y")
        self.output.config(yscrollcommand=scroll.set)

    # -- background work -----------------------------------------------------
    def _start(self):
        target = self.target.get().strip()
        if not target:
            messagebox.showerror("Port Scanner", "Please enter a target.")
            return
        try:
            target_ip = netcore.resolve_host(target)
        except OSError:
            messagebox.showerror("Port Scanner", f"Could not resolve '{target}'.")
            return
        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            timeout = float(self.timeout.get())
        except ValueError:
            messagebox.showerror("Port Scanner", "Ports must be integers and timeout a number.")
            return
        if not (netcore.MIN_PORT <= start <= end <= netcore.MAX_PORT):
            messagebox.showerror(
                "Port Scanner",
                f"Invalid range. Use {netcore.MIN_PORT}-{netcore.MAX_PORT} with start <= end.")
            return

        self._stop.clear()
        self._set_running(True)
        self._clear_output()
        total = end - start + 1
        self.progress.config(maximum=total, value=0)
        self._log(f"Scanning {target_ip} ports {start}-{end} ...")

        def run():
            t0 = time.time()
            open_ports = netcore.scan_ports(
                target_ip, start, end, timeout=timeout,
                on_open=lambda p: self._events.put(("open", p)),
                on_progress=lambda d, t: self._events.put(("progress", d)),
                stop_event=self._stop,
            )
            self._events.put(("done", (open_ports, time.time() - t0)))

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def _stop_scan(self):
        self._stop.set()
        self.status.config(text="Stopping...")

    # -- event pump ----------------------------------------------------------
    def _drain_events(self):
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "open":
                    self._log(f"  Port {payload} is OPEN")
                elif kind == "progress":
                    self.progress.config(value=payload)
                    self.status.config(text=f"Scanned {payload}/{self.progress['maximum']} ports")
                elif kind == "done":
                    open_ports, elapsed = payload
                    self._finish(open_ports, elapsed)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _finish(self, open_ports, elapsed):
        self._set_running(False)
        if self._stop.is_set():
            self._log("\nScan stopped.")
        else:
            self.progress.config(value=self.progress["maximum"])
        self._log(f"\nDone in {elapsed:.1f}s. "
                  + (f"Open: {', '.join(map(str, open_ports))}" if open_ports
                     else "No open ports found."))
        self.status.config(text=f"Finished. {len(open_ports)} open port(s).")

    # -- helpers -------------------------------------------------------------
    def _set_running(self, running):
        self.scan_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")

    def _clear_output(self):
        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.config(state="disabled")

    def _log(self, text):
        self.output.config(state="normal")
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.config(state="disabled")


class SnifferTab(ttk.Frame):
    """UI and logic for the packet-sniffing tab."""

    def __init__(self, master):
        super().__init__(master, padding=10)
        self._events = queue.Queue()
        self._stop = threading.Event()
        self._thread = None
        self._build()
        self.after(100, self._drain_events)

    def _build(self):
        form = ttk.Frame(self)
        form.pack(fill="x")

        self.mode = tk.StringVar(value="count")
        ttk.Radiobutton(form, text="By count", variable=self.mode, value="count",
                        command=self._sync_mode).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(form, text="By duration", variable=self.mode, value="duration",
                        command=self._sync_mode).grid(row=0, column=1, sticky="w")

        ttk.Label(form, text="Count:").grid(row=1, column=0, sticky="w", pady=3)
        self.count = ttk.Entry(form, width=10)
        self.count.insert(0, "50")
        self.count.grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(form, text="Duration (s):").grid(row=1, column=2, sticky="w", pady=3)
        self.duration = ttk.Entry(form, width=10)
        self.duration.insert(0, "10")
        self.duration.grid(row=1, column=3, sticky="w", padx=5)

        ttk.Label(form, text="Protocol:").grid(row=2, column=0, sticky="w", pady=3)
        self.proto = ttk.Combobox(form, width=8, state="readonly",
                                  values=["all", "tcp", "udp", "icmp"])
        self.proto.set("all")
        self.proto.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(form, text="Port filter:").grid(row=2, column=2, sticky="w", pady=3)
        self.port = ttk.Entry(form, width=10)
        self.port.grid(row=2, column=3, sticky="w", padx=5)

        ttk.Label(form, text="Source IP:").grid(row=3, column=0, sticky="w", pady=3)
        self.src = ttk.Entry(form, width=18)
        self.src.grid(row=3, column=1, sticky="w", padx=5)

        ttk.Label(form, text="Dest IP:").grid(row=3, column=2, sticky="w", pady=3)
        self.dst = ttk.Entry(form, width=18)
        self.dst.grid(row=3, column=3, sticky="w", padx=5)

        self.save_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="Save to pcap:", variable=self.save_var,
                        command=self._sync_save).grid(row=4, column=0, sticky="w", pady=3)
        self.pcap_path = ttk.Entry(form, width=30, state="disabled")
        self.pcap_path.grid(row=4, column=1, columnspan=2, sticky="we", padx=5)
        self.browse_btn = ttk.Button(form, text="Browse...", command=self._browse, state="disabled")
        self.browse_btn.grid(row=4, column=3, sticky="w")

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=8)
        self.start_btn = ttk.Button(btns, text="Start Capture", command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self._stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.status = ttk.Label(self, text="Ready. (Raw capture needs Administrator/root.)")
        self.status.pack(anchor="w")

        self.output = tk.Text(self, height=16, wrap="none", state="disabled")
        self.output.pack(fill="both", expand=True, pady=(6, 0))
        scroll = ttk.Scrollbar(self.output, command=self.output.yview)
        scroll.pack(side="right", fill="y")
        self.output.config(yscrollcommand=scroll.set)

        self._sync_mode()

    def _sync_mode(self):
        by_count = self.mode.get() == "count"
        self.count.config(state="normal" if by_count else "disabled")
        self.duration.config(state="disabled" if by_count else "normal")

    def _sync_save(self):
        state = "normal" if self.save_var.get() else "disabled"
        self.pcap_path.config(state=state)
        self.browse_btn.config(state=state)

    def _browse(self):
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if path:
            self.pcap_path.delete(0, "end")
            self.pcap_path.insert(0, path)

    # -- background work -----------------------------------------------------
    def _start(self):
        count = duration = None
        try:
            if self.mode.get() == "count":
                count = int(self.count.get())
            else:
                duration = float(self.duration.get())
        except ValueError:
            messagebox.showerror("Packet Sniffer", "Count/duration must be numeric.")
            return

        port_raw = self.port.get().strip()
        port_filter = int(port_raw) if port_raw.isdigit() else None
        pcap_path = self.pcap_path.get().strip() if self.save_var.get() else None
        if self.save_var.get() and not pcap_path:
            messagebox.showerror("Packet Sniffer", "Choose a pcap file path or disable saving.")
            return

        kwargs = dict(
            count=count, duration=duration, proto_filter=self.proto.get(),
            src_filter=self.src.get().strip() or None,
            dst_filter=self.dst.get().strip() or None,
            port_filter=port_filter, pcap_path=pcap_path,
            on_packet=lambda info, raw, ts: self._events.put(("pkt", (info, len(raw), ts))),
            stop_event=self._stop,
        )

        self._stop.clear()
        self._set_running(True)
        self._clear_output()
        self._log("Capturing... (filters applied)")

        def run():
            try:
                stats = netcore.sniff_packets(**kwargs)
                self._events.put(("done", stats))
            except netcore.CaptureError as e:
                self._events.put(("error", str(e)))

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def _stop_capture(self):
        self._stop.set()
        self.status.config(text="Stopping...")

    # -- event pump ----------------------------------------------------------
    def _drain_events(self):
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "pkt":
                    info, length, ts = payload
                    self._log_packet(info, length, ts)
                elif kind == "done":
                    self._finish(payload)
                elif kind == "error":
                    self._set_running(False)
                    self.status.config(text="Capture failed.")
                    messagebox.showerror("Packet Sniffer", payload)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _log_packet(self, info, length, ts):
        timestr = time.strftime("%H:%M:%S", time.localtime(ts))
        line = (f"[{timestr}] {info.get('src')} -> {info.get('dst')} "
                f"{netcore.proto_name(info.get('proto'))} len={length}")
        if "sport" in info:
            line += f"  ports {info['sport']}->{info['dport']}"
        self._log(line)

    def _finish(self, stats):
        self._set_running(False)
        self._log("\n--- Capture summary ---")
        self._log(f"Total packets: {stats['total']}")
        if stats["proto_counts"]:
            self._log("Protocols: " + ", ".join(
                f"{p}={c}" for p, c in stats["proto_counts"].most_common()))
        if stats["talkers"]:
            self._log("Top talkers:")
            for ip, cnt in stats["talkers"].most_common(10):
                self._log(f"  {ip}: {cnt}")
        self.status.config(text=f"Finished. {stats['total']} packet(s) captured.")

    # -- helpers -------------------------------------------------------------
    def _set_running(self, running):
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")

    def _clear_output(self):
        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.config(state="disabled")

    def _log(self, text):
        self.output.config(state="normal")
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.config(state="disabled")


def main():
    root = tk.Tk()
    root.title("Network Analyzer")
    root.geometry("720x560")
    root.minsize(560, 440)

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)
    notebook.add(ScannerTab(notebook), text="Port Scanner")
    notebook.add(SnifferTab(notebook), text="Packet Sniffer")

    root.mainloop()


if __name__ == "__main__":
    main()
