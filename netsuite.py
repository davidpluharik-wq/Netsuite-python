#!/usr/bin/env python3
"""
NetSuite — Combined Network Toolkit
-------------------------------------
A single tabbed desktop app combining:
  1. Network Device Monitor (nmap)      — new devices joining the LAN
  2. WiFi Scanner (nmcli)               — nearby access points
  3. Brief Connection Watcher (scapy)   — devices connected only briefly
  4. System Resource Monitor (psutil)   — CPU / RAM / Disk / Network graphs

Requirements:
  sudo apt install nmap network-manager python3-tk python3-psutil python3-matplotlib
  scapy is required for tab 3 (already installed via apt on your system).

Root privileges:
  - Tab 1 (nmap) works without root, but loses MAC/vendor detection.
  - Tab 3 (scapy) REQUIRES root to sniff packets. If not running as root,
    that tab's Start button is disabled with an explanation instead of
    crashing — everything else still works normally.
  - Tabs 2 and 4 never need root.

  For full functionality (all four tabs), launch like this so root can
  still open the GUI window:

    sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 netsuite.py

  Or just run `python3 netsuite.py` normally and only tab 3 will be limited.
"""

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from collections import deque
from datetime import datetime
from pathlib import Path

import psutil
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

try:
    from scapy.all import sniff, ARP
except ImportError:
    sniff = None
    ARP = None

IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

STATE_FILE = Path.home() / ".netsuite_known_devices.json"
LOG_FILE = Path.home() / "netsuite.log"

BG_COLOR = "#1e1e1e"
FG_COLOR = "#00FF41"
ACCENT = "#4fa3f7"
WARN = "#e05656"
GOOD = "#5cc26a"


def log_to_file(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def notify_desktop(title: str, message: str):
    try:
        subprocess.run(["notify-send", title, message], check=False, timeout=5)
    except Exception:
        pass


# ===========================================================================
# TAB 1 — Network Device Monitor (nmap)
# ===========================================================================

class DeviceMonitorScanner(threading.Thread):
    def __init__(self, network, interval, event_queue, known_devices):
        super().__init__(daemon=True)
        self.network = network
        self.interval = interval
        self.event_queue = event_queue
        self.known_devices = known_devices
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    @staticmethod
    def parse_nmap_output(output):
        devices = {}
        current_ip = None
        ip_pattern = re.compile(r"Nmap scan report for (?:(\S+) \()?([\d\.]+)\)?")
        mac_pattern = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17}) \(?([^)]*)\)?")
        for line in output.splitlines():
            ip_match = ip_pattern.search(line)
            if ip_match:
                current_ip = ip_match.group(2)
                devices[current_ip] = {"mac": None, "vendor": None, "hostname": ip_match.group(1)}
                continue
            mac_match = mac_pattern.search(line)
            if mac_match and current_ip:
                devices[current_ip]["mac"] = mac_match.group(1)
                devices[current_ip]["vendor"] = mac_match.group(2) or None
        return devices

    def run(self):
        while not self._stop_flag.is_set():
            self.event_queue.put(("status", f"Scanning {self.network} ..."))
            try:
                result = subprocess.run(["nmap", "-sn", self.network], capture_output=True, text=True, timeout=120)
                if result.returncode != 0:
                    self.event_queue.put(("error", result.stderr.strip() or "nmap error"))
                else:
                    devices = self.parse_nmap_output(result.stdout)
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    new_ips = [ip for ip in devices if ip not in self.known_devices]
                    for ip in devices:
                        devices[ip]["first_seen"] = self.known_devices.get(ip, {}).get("first_seen", now_str)
                    self.known_devices.update(devices)
                    with open(STATE_FILE, "w") as f:
                        json.dump(self.known_devices, f, indent=2)
                    self.event_queue.put(("devices", dict(self.known_devices)))
                    if new_ips:
                        for ip in new_ips:
                            self.event_queue.put(("new_device", (ip, devices[ip])))
                    else:
                        self.event_queue.put(("status", f"No new devices. {len(devices)} online."))
            except FileNotFoundError:
                self.event_queue.put(("error", "nmap not installed (sudo apt install nmap)"))
                return
            except subprocess.TimeoutExpired:
                self.event_queue.put(("status", "Scan timed out, retrying next cycle."))

            slept = 0
            while slept < self.interval and not self._stop_flag.is_set():
                time.sleep(1)
                slept += 1


class DeviceMonitorTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.known_devices = self._load_known_devices()
        self.scanner_thread = None
        self.row_ips = {}
        self._build_ui()
        self._poll_queue()
        if self.known_devices:
            self._refresh_table(self.known_devices)

    def _load_known_devices(self):
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        ttk.Label(controls, text="Network:").grid(row=0, column=0, sticky="w")
        self.network_entry = ttk.Entry(controls, width=20)
        self.network_entry.insert(0, "192.168.50.0/24")
        self.network_entry.grid(row=0, column=1, padx=(5, 15))

        ttk.Label(controls, text="Interval (sec):").grid(row=0, column=2, sticky="w")
        self.interval_entry = ttk.Entry(controls, width=8)
        self.interval_entry.insert(0, "600")
        self.interval_entry.grid(row=0, column=3, padx=(5, 15))

        self.start_button = ttk.Button(controls, text="Start Monitoring", command=self.start)
        self.start_button.grid(row=0, column=4, padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=5, padx=5)

        self.status_label = ttk.Label(self.frame, text="Idle.")
        self.status_label.pack(fill="x", pady=(5, 5))

        columns = ("ip", "hostname", "mac", "vendor", "first_seen")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=12)
        for col, label, width in [("ip", "IP", 120), ("hostname", "Hostname", 150),
                                   ("mac", "MAC", 140), ("vendor", "Vendor", 160), ("first_seen", "First Seen", 150)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("new", background="#fff3b0")
        self.tree.pack(fill="both", expand=True)

        ttk.Label(self.frame, text="Activity Log:").pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(self.frame, height=6, state="disabled", wrap="word", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=False)

    def start(self):
        network = self.network_entry.get().strip()
        try:
            interval = int(self.interval_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid interval", "Interval must be a number of seconds.")
            return
        if not network:
            messagebox.showerror("Missing network", "Enter a network range, e.g. 192.168.1.0/24")
            return
        self.scanner_thread = DeviceMonitorScanner(network, interval, self.event_queue, self.known_devices)
        self.scanner_thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self._log(f"Started monitoring {network} every {interval}s.")

    def stop(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.scanner_thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Stopped.")
        self._log("Stopped monitoring.")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "status":
                    self.status_label.config(text=payload)
                    self._log(payload)
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
                elif kind == "devices":
                    self._refresh_table(payload)
                elif kind == "new_device":
                    ip, info = payload
                    self._handle_new_device(ip, info)
        except queue.Empty:
            pass
        self.frame.after(200, self._poll_queue)

    def _refresh_table(self, devices):
        self.tree.delete(*self.tree.get_children())
        self.row_ips.clear()
        for ip, info in sorted(devices.items(), key=lambda kv: tuple(int(p) for p in kv[0].split("."))):
            item_id = self.tree.insert("", "end", values=(
                ip, info.get("hostname") or "-", info.get("mac") or "-",
                info.get("vendor") or "-", info.get("first_seen") or "-"))
            self.row_ips[item_id] = ip

    def _handle_new_device(self, ip, info):
        description = ip
        if info.get("hostname"):
            description += f" ({info['hostname']})"
        if info.get("vendor"):
            description += f" — {info['vendor']}"
        self._log(f"NEW DEVICE DETECTED: {description}")
        log_to_file(f"[NetworkMonitor] NEW DEVICE: {description}")
        for item_id, item_ip in self.row_ips.items():
            if item_ip == ip:
                self.tree.item(item_id, tags=("new",))
        notify_desktop("New device on your network!", description)

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


# ===========================================================================
# TAB 2 — WiFi Scanner (nmcli)
# ===========================================================================

class WifiScannerThread(threading.Thread):
    def __init__(self, event_queue, interval, auto_refresh):
        super().__init__(daemon=True)
        self.event_queue = event_queue
        self.interval = interval
        self.auto_refresh = auto_refresh
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    @staticmethod
    def split_terse_line(line):
        parts = re.split(r"(?<!\\):", line)
        return [p.replace("\\:", ":") for p in parts]

    def scan(self):
        fields = ["SSID", "BSSID", "CHAN", "SIGNAL", "SECURITY", "RATE"]
        cmd = ["nmcli", "-t", "-f", ",".join(fields), "dev", "wifi", "list", "--rescan", "yes"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "nmcli error")
        networks = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            parts = self.split_terse_line(line)
            if len(parts) < 6:
                continue
            ssid, bssid, chan, signal, security, rate = parts[:6]
            networks.append({
                "ssid": ssid if ssid else "<Hidden Network>",
                "bssid": bssid, "channel": chan,
                "signal": int(signal) if signal.isdigit() else 0,
                "security": security if security else "Open", "rate": rate,
            })
        networks.sort(key=lambda n: n["signal"], reverse=True)
        return networks

    def run(self):
        while not self._stop_flag.is_set():
            try:
                self.event_queue.put(("networks", self.scan()))
            except FileNotFoundError:
                self.event_queue.put(("error", "nmcli not found (sudo apt install network-manager)"))
                return
            except Exception as e:
                self.event_queue.put(("error", str(e)))
            if not self.auto_refresh:
                break
            slept = 0
            while slept < self.interval and not self._stop_flag.is_set():
                time.sleep(1)
                slept += 1


def signal_bars(signal):
    if signal >= 80:
        return "▂▄▆█"
    elif signal >= 60:
        return "▂▄▆_"
    elif signal >= 40:
        return "▂▄__"
    elif signal >= 20:
        return "▂___"
    return "____"


class WifiScannerTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.scanner_thread = None
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        self.scan_button = ttk.Button(controls, text="Scan Now", command=self.scan_once)
        self.scan_button.grid(row=0, column=0, padx=(0, 15))

        self.auto_refresh_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Auto-refresh every", variable=self.auto_refresh_var,
                         command=self._toggle_auto_refresh).grid(row=0, column=1)

        self.interval_entry = ttk.Entry(controls, width=6)
        self.interval_entry.insert(0, "30")
        self.interval_entry.grid(row=0, column=2, padx=5)
        ttk.Label(controls, text="sec").grid(row=0, column=3)

        self.status_label = ttk.Label(controls, text="Idle.")
        self.status_label.grid(row=0, column=4, padx=20)

        columns = ("ssid", "signal", "bars", "channel", "security", "bssid", "rate")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=14)
        for col, label, width in [("ssid", "SSID", 200), ("signal", "Signal %", 70), ("bars", "Strength", 90),
                                   ("channel", "Channel", 70), ("security", "Security", 130),
                                   ("bssid", "BSSID", 150), ("rate", "Rate", 100)]:
            self.tree.heading(col, text=label, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("strong", foreground="#1a7a1a")
        self.tree.tag_configure("weak", foreground="#a04040")
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

        self.count_label = ttk.Label(self.frame, text="No scan yet.")
        self.count_label.pack(anchor="w", pady=(5, 0))

    def scan_once(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            return
        self.status_label.config(text="Scanning...")
        self.scanner_thread = WifiScannerThread(self.event_queue, interval=0, auto_refresh=False)
        self.scanner_thread.start()

    def _toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            try:
                interval = int(self.interval_entry.get().strip())
                if interval < 5:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid interval", "Enter 5 or more seconds.")
                self.auto_refresh_var.set(False)
                return
            if self.scanner_thread and self.scanner_thread.is_alive():
                self.scanner_thread.stop()
            self.scanner_thread = WifiScannerThread(self.event_queue, interval=interval, auto_refresh=True)
            self.scanner_thread.start()
            self.status_label.config(text=f"Auto-refreshing every {interval}s...")
        else:
            if self.scanner_thread:
                self.scanner_thread.stop()
            self.status_label.config(text="Auto-refresh stopped.")

    def _sort_by(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        if col in ("signal", "channel"):
            items.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=True)
        else:
            items.sort(key=lambda t: t[0].lower())
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "networks":
                    self._refresh_table(payload)
                    if not self.auto_refresh_var.get():
                        self.status_label.config(text="Idle.")
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self.count_label.config(text=payload)
        except queue.Empty:
            pass
        self.frame.after(300, self._poll_queue)

    def _refresh_table(self, networks):
        self.tree.delete(*self.tree.get_children())
        for net in networks:
            tag = "strong" if net["signal"] >= 60 else ("weak" if net["signal"] < 30 else "")
            self.tree.insert("", "end", values=(net["ssid"], net["signal"], signal_bars(net["signal"]),
                                                 net["channel"], net["security"], net["bssid"], net["rate"]),
                              tags=(tag,) if tag else ())
        self.count_label.config(text=f"{len(networks)} network(s) found.")


# ===========================================================================
# TAB 3 — Brief Connection Watcher (scapy)
# ===========================================================================

STALE_TIMEOUT = 6
BRIEF_THRESHOLD = 10


class BriefWatcherThread(threading.Thread):
    def __init__(self, iface, event_queue):
        super().__init__(daemon=True)
        self.iface = iface
        self.event_queue = event_queue
        self._stop_flag = threading.Event()
        self.active_sessions = {}
        self.lock = threading.Lock()

    def stop(self):
        self._stop_flag.set()

    def _handle_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return
        mac = pkt[ARP].hwsrc
        ip = pkt[ARP].psrc
        now = time.time()
        with self.lock:
            if mac not in self.active_sessions:
                self.active_sessions[mac] = {"ip": ip, "first_seen": now, "last_seen": now}
                self.event_queue.put(("device_appeared", {"mac": mac, "ip": ip}))
            else:
                self.active_sessions[mac]["last_seen"] = now
                self.active_sessions[mac]["ip"] = ip

    def _check_stale(self):
        now = time.time()
        with self.lock:
            stale = [m for m, s in self.active_sessions.items() if now - s["last_seen"] > STALE_TIMEOUT]
            for mac in stale:
                s = self.active_sessions.pop(mac)
                duration = s["last_seen"] - s["first_seen"]
                self.event_queue.put(("session_closed", {
                    "mac": mac, "ip": s["ip"], "duration": duration,
                    "first_seen": s["first_seen"], "last_seen": s["last_seen"]}))

    def run(self):
        last_check = time.time()
        try:
            while not self._stop_flag.is_set():
                try:
                    sniff(iface=self.iface, filter="arp", prn=self._handle_packet, store=False, timeout=1)
                except PermissionError:
                    self.event_queue.put(("error", "Permission denied — needs root."))
                    return
                except OSError as e:
                    self.event_queue.put(("error", f"Network error: {e}"))
                    return
                if time.time() - last_check >= 1:
                    self._check_stale()
                    last_check = time.time()
        finally:
            with self.lock:
                for mac, s in self.active_sessions.items():
                    duration = s["last_seen"] - s["first_seen"]
                    self.event_queue.put(("session_closed", {
                        "mac": mac, "ip": s["ip"], "duration": duration,
                        "first_seen": s["first_seen"], "last_seen": s["last_seen"]}))


class BriefWatcherTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.watcher_thread = None
        self.active_rows = {}
        self._build_ui()
        self._poll_queue()
        self._tick_active_table()

    def _list_interfaces(self):
        try:
            result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5)
            names = []
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip().split("@")[0]
                    if name != "lo":
                        names.append(name)
            return names
        except Exception:
            return []

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        ttk.Label(controls, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(controls, width=15, state="readonly")
        self.iface_combo["values"] = self._list_interfaces()
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(5, 15))

        can_run = sniff is not None and IS_ROOT
        self.start_button = ttk.Button(controls, text="Start Listening", command=self.start,
                                        state="normal" if can_run else "disabled")
        self.start_button.grid(row=0, column=2, padx=5)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5)

        self.status_label = ttk.Label(controls, text="Idle.")
        self.status_label.grid(row=0, column=4, padx=20)

        if not can_run:
            reason = "scapy is not installed." if sniff is None else "This tab requires root privileges."
            hint = ttk.Label(
                self.frame,
                text=f"⚠ {reason} Restart the whole app with:\n"
                     f"sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 netsuite.py",
                foreground=WARN
            )
            hint.pack(anchor="w", pady=(5, 5))

        paned = ttk.PanedWindow(self.frame, orient="vertical")
        paned.pack(fill="both", expand=True, pady=(10, 0))

        active_frame = ttk.Frame(paned)
        ttk.Label(active_frame, text="Currently Active Devices:").pack(anchor="w")
        self.active_tree = ttk.Treeview(active_frame, columns=("ip", "mac", "seen_for"), show="headings", height=6)
        for col, label, width in [("ip", "IP Address", 150), ("mac", "MAC Address", 180), ("seen_for", "Seen For", 100)]:
            self.active_tree.heading(col, text=label)
            self.active_tree.column(col, width=width, anchor="w")
        self.active_tree.pack(fill="both", expand=True)
        paned.add(active_frame, weight=1)

        history_frame = ttk.Frame(paned)
        ttk.Label(history_frame, text="Connection History (most recent first):").pack(anchor="w")
        self.history_tree = ttk.Treeview(history_frame, columns=("time", "ip", "mac", "duration", "flag"),
                                          show="headings", height=10)
        for col, label, width in [("time", "Ended At", 120), ("ip", "IP", 140), ("mac", "MAC", 170),
                                   ("duration", "Duration", 90), ("flag", "Note", 220)]:
            self.history_tree.heading(col, text=label)
            self.history_tree.column(col, width=width, anchor="w")
        self.history_tree.tag_configure("brief", background="#ffd6d6")
        self.history_tree.pack(fill="both", expand=True)
        paned.add(history_frame, weight=2)

        ttk.Label(self.frame, text="Activity Log:").pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(self.frame, height=5, state="disabled", wrap="word", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=False)

    def start(self):
        iface = self.iface_combo.get()
        if not iface:
            messagebox.showerror("No interface", "Select a network interface.")
            return
        self.watcher_thread = BriefWatcherThread(iface, self.event_queue)
        self.watcher_thread.start()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.iface_combo.config(state="disabled")
        self.status_label.config(text=f"Listening on {iface}...")
        self._log(f"Started listening on {iface}.")

    def stop(self):
        if self.watcher_thread:
            self.watcher_thread.stop()
            self.watcher_thread = None
        self.start_button.config(state="normal" if (sniff is not None and IS_ROOT) else "disabled")
        self.stop_button.config(state="disabled")
        self.iface_combo.config(state="readonly")
        self.status_label.config(text="Stopped.")
        self._log("Stopped listening.")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "device_appeared":
                    self._log(f"Device appeared: {payload['ip']} ({payload['mac']})")
                elif kind == "session_closed":
                    self._add_history_row(payload)
                    if payload["mac"] in self.active_rows:
                        self.active_tree.delete(self.active_rows.pop(payload["mac"]))
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
        except queue.Empty:
            pass
        self.frame.after(300, self._poll_queue)

    def _tick_active_table(self):
        if self.watcher_thread:
            with self.watcher_thread.lock:
                sessions = dict(self.watcher_thread.active_sessions)
            seen_macs = set(sessions.keys())
            for mac in list(self.active_rows.keys()):
                if mac not in seen_macs:
                    self.active_tree.delete(self.active_rows.pop(mac))
            now = time.time()
            for mac, session in sessions.items():
                seen_for = f"{now - session['first_seen']:.0f}s"
                if mac in self.active_rows:
                    self.active_tree.item(self.active_rows[mac], values=(session["ip"], mac, seen_for))
                else:
                    item_id = self.active_tree.insert("", "end", values=(session["ip"], mac, seen_for))
                    self.active_rows[mac] = item_id
        self.frame.after(1000, self._tick_active_table)

    def _add_history_row(self, payload):
        ended_at = datetime.fromtimestamp(payload["last_seen"]).strftime("%H:%M:%S")
        duration = payload["duration"]
        is_brief = duration < BRIEF_THRESHOLD
        note = f"⚠ Brief connection ({duration:.1f}s)" if is_brief else "Normal session"
        self.history_tree.insert("", 0, values=(ended_at, payload["ip"], payload["mac"], f"{duration:.1f}s", note),
                                  tags=("brief",) if is_brief else ())
        self._log(f"Session ended: {payload['ip']} ({payload['mac']}) — {duration:.1f}s — {note}")
        log_to_file(f"[BriefWatcher] {payload['ip']} ({payload['mac']}) — {duration:.1f}s — {note}")
        if is_brief:
            notify_desktop("Brief connection detected!",
                            f"{payload['ip']} ({payload['mac']}) was on the network for only {duration:.1f}s")

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


# ===========================================================================
# TAB 4 — System Resource Monitor (psutil)
# ===========================================================================

HISTORY_LENGTH = 60
UPDATE_INTERVAL_MS = 1000


class SystemMonitorTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.cpu_history = deque([0] * HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.ram_history = deque([0] * HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.net_sent_history = deque([0] * HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.net_recv_history = deque([0] * HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.last_net = psutil.net_io_counters()
        self._build_ui()
        self._update_loop()

    def _build_ui(self):
        top_frame = ttk.Frame(self.frame)
        top_frame.pack(fill="x")

        self.cpu_label = self._make_card(top_frame, "CPU", 0)
        self.ram_label = self._make_card(top_frame, "RAM", 1)
        self.disk_label = self._make_card(top_frame, "Disk", 2)
        self.net_label = self._make_card(top_frame, "Network", 3)
        for i in range(4):
            top_frame.columnconfigure(i, weight=1)

        graph_frame = ttk.Frame(self.frame)
        graph_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.fig = Figure(figsize=(9, 4.5), dpi=90, facecolor=BG_COLOR)
        self.ax_cpu = self.fig.add_subplot(311)
        self.ax_ram = self.fig.add_subplot(312)
        self.ax_net = self.fig.add_subplot(313)
        for ax, title in [(self.ax_cpu, "CPU %"), (self.ax_ram, "RAM %"), (self.ax_net, "Network (KB/s)")]:
            ax.set_facecolor("#141414")
            ax.set_title(title, color=FG_COLOR, fontsize=10, loc="left")
            ax.tick_params(colors="#888888", labelsize=8)
            for spine in ax.spines.values():
                spine.set_color("#444444")
        self.fig.tight_layout(pad=2)

        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        self.detail_label = ttk.Label(self.frame, text="")
        self.detail_label.pack(anchor="w", pady=(5, 0))

    def _make_card(self, parent, title, column):
        frame = ttk.Frame(parent, padding=8)
        frame.grid(row=0, column=column, sticky="nsew", padx=5)
        ttk.Label(frame, text=title).pack(anchor="w")
        value_label = ttk.Label(frame, text="--", font=("Consolas", 20, "bold"))
        value_label.pack(anchor="w")
        return value_label

    def _update_loop(self):
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        sent_rate = (net.bytes_sent - self.last_net.bytes_sent) / 1024
        recv_rate = (net.bytes_recv - self.last_net.bytes_recv) / 1024
        self.last_net = net

        self.cpu_history.append(cpu_percent)
        self.ram_history.append(mem.percent)
        self.net_sent_history.append(sent_rate)
        self.net_recv_history.append(recv_rate)

        self.cpu_label.config(text=f"{cpu_percent:.0f}%", foreground=self._color_for(cpu_percent))
        self.ram_label.config(text=f"{mem.percent:.0f}%", foreground=self._color_for(mem.percent))
        self.disk_label.config(text=f"{disk.percent:.0f}%", foreground=self._color_for(disk.percent))
        self.net_label.config(text=f"↑{sent_rate:.0f} ↓{recv_rate:.0f} KB/s", foreground=ACCENT)

        self.detail_label.config(text=(
            f"RAM: {self._gb(mem.used)} / {self._gb(mem.total)} GB   |   "
            f"Disk: {self._gb(disk.used)} / {self._gb(disk.total)} GB   |   "
            f"Cores: {psutil.cpu_count(logical=True)}   |   "
            f"Updated: {datetime.now().strftime('%H:%M:%S')}"
        ))

        self._redraw_graphs()
        self.frame.after(UPDATE_INTERVAL_MS, self._update_loop)

    def _color_for(self, percent):
        if percent >= 85:
            return WARN
        elif percent >= 60:
            return "#e0b356"
        return GOOD

    def _gb(self, bytes_val):
        return f"{bytes_val / (1024 ** 3):.1f}"

    def _redraw_graphs(self):
        x = range(len(self.cpu_history))

        self.ax_cpu.clear()
        self.ax_cpu.set_facecolor("#141414")
        self.ax_cpu.set_title("CPU %", color=FG_COLOR, fontsize=10, loc="left")
        self.ax_cpu.set_ylim(0, 100)
        self.ax_cpu.plot(x, self.cpu_history, color=ACCENT, linewidth=1.5)
        self.ax_cpu.fill_between(x, self.cpu_history, color=ACCENT, alpha=0.15)
        self.ax_cpu.tick_params(colors="#888888", labelsize=8)

        self.ax_ram.clear()
        self.ax_ram.set_facecolor("#141414")
        self.ax_ram.set_title("RAM %", color=FG_COLOR, fontsize=10, loc="left")
        self.ax_ram.set_ylim(0, 100)
        self.ax_ram.plot(x, self.ram_history, color="#c774e8", linewidth=1.5)
        self.ax_ram.fill_between(x, self.ram_history, color="#c774e8", alpha=0.15)
        self.ax_ram.tick_params(colors="#888888", labelsize=8)

        self.ax_net.clear()
        self.ax_net.set_facecolor("#141414")
        self.ax_net.set_title("Network (KB/s)", color=FG_COLOR, fontsize=10, loc="left")
        max_val = max(max(self.net_sent_history, default=1), max(self.net_recv_history, default=1), 1)
        self.ax_net.set_ylim(0, max_val * 1.2)
        self.ax_net.plot(x, self.net_recv_history, color=GOOD, linewidth=1.3, label="Download")
        self.ax_net.plot(x, self.net_sent_history, color=WARN, linewidth=1.3, label="Upload")
        self.ax_net.legend(loc="upper left", fontsize=7, facecolor="#141414", labelcolor=FG_COLOR, frameon=False)
        self.ax_net.tick_params(colors="#888888", labelsize=8)

        for ax in (self.ax_cpu, self.ax_ram, self.ax_net):
            ax.set_xticks([])
            for spine in ax.spines.values():
                spine.set_color("#444444")

        self.fig.tight_layout(pad=2)
        self.canvas.draw()


# ===========================================================================
# Main App — Notebook combining all tabs
# ===========================================================================

class NetSuiteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSuite — Combined Network Toolkit")
        self.root.geometry("1000x720")
        self.root.minsize(850, 600)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG_COLOR, foreground=FG_COLOR, font=("Consolas", 10))
        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background="#2a2a2a", foreground=FG_COLOR, padding=(12, 6))
        style.map("TNotebook.Tab", background=[("selected", "#3a3a3a")])
        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TButton", padding=5)
        self.root.configure(bg=BG_COLOR)

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.device_tab = DeviceMonitorTab(notebook)
        self.wifi_tab = WifiScannerTab(notebook)
        self.brief_tab = BriefWatcherTab(notebook)
        self.system_tab = SystemMonitorTab(notebook)

        notebook.add(self.device_tab.frame, text="Network Monitor")
        notebook.add(self.wifi_tab.frame, text="WiFi Scanner")
        notebook.add(self.brief_tab.frame, text="Brief Connections")
        notebook.add(self.system_tab.frame, text="System Monitor")

        if not IS_ROOT:
            status = ttk.Label(
                root,
                text="Running without root — 'Brief Connections' tab is disabled. "
                     "Restart with sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 netsuite.py for full features.",
                foreground="#e0b356", padding=5
            )
            status.pack(fill="x", side="bottom")

    def shutdown(self):
        if self.device_tab.scanner_thread:
            self.device_tab.scanner_thread.stop()
        if self.wifi_tab.scanner_thread:
            self.wifi_tab.scanner_thread.stop()
        if self.brief_tab.watcher_thread:
            self.brief_tab.watcher_thread.stop()


def main():
    root = tk.Tk()
    app = NetSuiteApp(root)

    def on_close():
        app.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
