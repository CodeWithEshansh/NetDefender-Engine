import sys
sys.stdout.reconfigure(encoding='utf-8')

from collections import defaultdict
import time
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Tuple
import random
import tkinter as tk
from tkinter import scrolledtext
import threading


SQL_PATTERNS = ["DROP TABLE", "DELETE FROM", "INSERT INTO", "UNION SELECT"]
XSS_PATTERNS = ["<SCRIPT>", "JAVASCRIPT:", "ONERROR=", "ONLOAD="]
CMD_PATTERNS = ["'; DROP", "|| rm ", "&& rm ", "; cat /etc/passwd", "RM -RF"]
ALL_PATTERNS = SQL_PATTERNS + XSS_PATTERNS + CMD_PATTERNS


class ConnectionState(Enum):
    SYN_SENT = "SYN_SENT"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSED = "CLOSED"


@dataclass
class SessionMetadata:
    state: ConnectionState
    timestamp: float
    last_activity: float
    packet_count: int = 0
    bytes_transferred: int = 0
    protocol: str = "TCP"
    is_established: bool = False


class Firewall:
    def __init__(self, session_timeout=300, ddos_threshold=100):
        self.state_table: Dict[Tuple, SessionMetadata] = {}
        self.packet_count = defaultdict(int)
        self.failed_attempts = defaultdict(int)
        self.port_scan_attempts = defaultdict(set)

        self.blocked_ips = set()
        self.whitelist_ips = set()

        self.session_timeout = session_timeout
        self.ddos_threshold = ddos_threshold
        self.max_failed_attempts = 5

        self.stats = defaultdict(int)
        self.enable_logging = True

    def log(self, msg, level="INFO"):
        if self.enable_logging:
            print(f"[{time.strftime('%H:%M:%S')}] [{level}] {msg}")

    def connection_key(self, p):
        return (p['src_ip'], p['src_port'], p['dst_ip'], p['dst_port'])

    def reverse_key(self, p):
        return (p['dst_ip'], p['dst_port'], p['src_ip'], p['src_port'])

    def block_packet(self, reason=""):
        self.stats["blocked"] += 1
        self.log(f"BLOCKED: {reason}", "SECURITY")
        return False

    def allow_packet(self):
        self.stats["allowed"] += 1
        return True

    def validate_packet(self, p):
        return all(k in p for k in ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'direction'])

    def apply_security_checks(self, p):
        ip = p['src_ip']

        self.packet_count[ip] += 1
        if self.packet_count[ip] > self.ddos_threshold:
            self.blocked_ips.add(ip)
            return False

        self.port_scan_attempts[ip].add(p['dst_port'])
        if len(self.port_scan_attempts[ip]) > 10:
            self.blocked_ips.add(ip)
            return False

        return True

    def inspect_payload(self, p):
        payload = p.get("payload", "").upper()
        return not any(pattern in payload for pattern in ALL_PATTERNS)

    def cleanup_sessions(self):
        now = time.time()
        self.state_table = {
            k: v for k, v in self.state_table.items()
            if now - v.last_activity <= self.session_timeout
        }

    def handle_tcp(self, p):
        flags = p.get("flags", "")
        key = self.connection_key(p)
        rev = self.reverse_key(p)

        if "SYN" in flags and p['direction'] == "OUT":
            self.state_table[key] = SessionMetadata(
                ConnectionState.SYN_SENT, time.time(), time.time()
            )
            return self.allow_packet()

        if "SYN-ACK" in flags and rev in self.state_table:
            self.state_table[rev].state = ConnectionState.ESTABLISHED
            return self.allow_packet()

        if "ACK" in flags:
            session = self.state_table.get(rev) or self.state_table.get(key)
            if session:
                session.last_activity = time.time()
                session.packet_count += 1
                return self.allow_packet()
            return self.block_packet("Invalid TCP State")

        return self.block_packet("Invalid TCP State")

    def handle_udp(self, p):
        key = (p['src_ip'], p['src_port'])
        if key not in self.state_table:
            self.state_table[key] = SessionMetadata(
                ConnectionState.ESTABLISHED, time.time(), time.time(), protocol="UDP"
            )
        return self.allow_packet()

    def process_packet(self, p):
        self.cleanup_sessions()
        self.stats["total"] += 1

        if not self.validate_packet(p):
            return self.block_packet("Invalid Packet")

        ip = p['src_ip']

        if ip in self.whitelist_ips:
            return self.allow_packet()

        if ip in self.blocked_ips:
            return self.block_packet("Blocked IP")

        if not self.apply_security_checks(p):
            return self.block_packet("Attack Detected")

        if not self.inspect_payload(p):
            self.failed_attempts[ip] += 1
            return self.block_packet("Malicious Payload")

        proto = p.get("protocol", "TCP")

        if proto == "TCP":
            return self.handle_tcp(p)
        elif proto == "UDP":
            return self.handle_udp(p)

        return self.block_packet("Unknown Protocol")


active_sessions = []


def generate_packet():
    ips = ["192.168.1.10", "1.2.3.4", "5.6.7.8"]

    if active_sessions and random.random() < 0.8:
        session = random.choice(active_sessions)
        return {
            "src_ip": session["src_ip"],
            "src_port": session["src_port"],
            "dst_ip": session["dst_ip"],
            "dst_port": session["dst_port"],
            "direction": "OUT",
            "flags": "ACK",
            "protocol": "TCP",
            "payload": "normal data"
        }

    src_ip = random.choice(ips)
    src_port = random.randint(1000, 6000)

    session = {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": "8.8.8.8",
        "dst_port": 80
    }

    active_sessions.append(session)

    payload = "normal data"
    if random.random() < 0.1:
        payload = "DROP TABLE users;"

    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": "8.8.8.8",
        "dst_port": 80,
        "direction": "OUT",
        "flags": "SYN",
        "protocol": "TCP",
        "payload": payload
    }


def generate_attack_packet(attack_type):
    packet = {
        "src_ip": "9.9.9.9",
        "src_port": random.randint(1000, 6000),
        "dst_ip": "8.8.8.8",
        "dst_port": 80,
        "direction": "OUT",
        "flags": "SYN",
        "protocol": "TCP"
    }

    if attack_type == "SQL":
        packet["payload"] = "DROP TABLE users;"
    elif attack_type == "XSS":
        packet["payload"] = "<script>alert(1)</script>"
    elif attack_type == "CMD":
        packet["payload"] = "rm -rf /"

    return packet


class FirewallGUI:
    def __init__(self, root, firewall):
        self.root = root
        self.fw = firewall

        self.root.title("Firewall Simulator")
        self.root.geometry("900x550")
        self.root.configure(bg="#1e1e1e")

        tk.Label(root, text="Firewall Dashboard",
                 font=("Arial", 16, "bold"),
                 fg="white", bg="#1e1e1e").pack(pady=10)

        frame = tk.Frame(root, bg="#1e1e1e")
        frame.pack(pady=10)

        self.blocked_box = scrolledtext.ScrolledText(frame, height=20, width=45, bg="black", fg="red")
        self.blocked_box.grid(row=0, column=0, padx=10)

        self.allowed_box = scrolledtext.ScrolledText(frame, height=20, width=45, bg="black", fg="lime")
        self.allowed_box.grid(row=0, column=1, padx=10)

        self.stats_label = tk.Label(root, text="Allowed: 0 | Blocked: 0",
                                   fg="white", bg="#1e1e1e")
        self.stats_label.pack(pady=5)

        btn_frame = tk.Frame(root, bg="#1e1e1e")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Start", command=self.start_simulation,
                  bg="green", fg="white").grid(row=0, column=0, padx=10)

        tk.Button(btn_frame, text="Stop", command=self.stop_simulation,
                  bg="red", fg="white").grid(row=0, column=1, padx=10)

        tk.Button(btn_frame, text="Simulate Attack",
                  command=self.simulate_attack,
                  bg="orange", fg="black").grid(row=0, column=2, padx=10)

        self.running = False
        self.fw.log = self.gui_log

    def gui_log(self, msg, level="INFO"):
        log_msg = f"[{level}] {msg}\n"

        if "BLOCKED" in msg or level == "SECURITY":
            self.blocked_box.insert(tk.END, log_msg)
            self.blocked_box.see(tk.END)
        else:
            self.allowed_box.insert(tk.END, log_msg)
            self.allowed_box.see(tk.END)

    def update_stats(self):
        self.stats_label.config(
            text=f"Allowed: {self.fw.stats['allowed']} | Blocked: {self.fw.stats['blocked']}"
        )

    def simulate(self):
        while self.running:
            pkt = generate_packet()
            result = self.fw.process_packet(pkt)

            if result:
                self.gui_log("Packet Allowed")

            self.update_stats()
            time.sleep(0.7)

    def start_simulation(self):
        if not self.running:
            self.running = True
            threading.Thread(target=self.simulate, daemon=True).start()

    def stop_simulation(self):
        self.running = False

    def simulate_attack(self):
        win = tk.Toplevel(self.root)
        win.title("Select Attack")

        def run_attack(a):
            pkt = generate_attack_packet(a)
            res = self.fw.process_packet(pkt)

            if res:
                self.gui_log(f"{a} Attack Passed")
            else:
                self.gui_log(f"{a} Attack Blocked", "SECURITY")

            self.update_stats()
            win.destroy()

        tk.Button(win, text="SQL Injection", command=lambda: run_attack("SQL")).pack(pady=5)
        tk.Button(win, text="XSS Attack", command=lambda: run_attack("XSS")).pack(pady=5)
        tk.Button(win, text="Command Injection", command=lambda: run_attack("CMD")).pack(pady=5)


if __name__ == "__main__":
    fw = Firewall()
    root = tk.Tk()
    app = FirewallGUI(root, fw)
    root.mainloop()