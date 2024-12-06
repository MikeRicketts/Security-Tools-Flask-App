import json
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import AsyncSniffer
import time
from collections import deque
import socket
import threading

class PacketSniffer:
    def __init__(self, interface=None, store=False, filter_str=""):
        self.interface = interface
        self.store = store
        self.filter_str = filter_str
        self.packets = deque(maxlen=1000)  # Limit to 1000 packets
        self.sniffing = threading.Event()
        self.sniffer = None
        self.lock = threading.Lock()

    def start_sniffing(self):
        """Starts the packet sniffing asynchronously."""
        if not self.sniffing.is_set():
            self.sniffing.set()
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.filter_str,
                prn=self.process_packet,
                store=self.store
            )
            self.sniffer.start()
            print("[*] Packet sniffing started.")

    def stop_sniffing(self):
        """Stops the packet sniffing."""
        if self.sniffing.is_set():
            self.sniffing.clear()
            print("[*] Stopping packet sniffing...")
            if self.sniffer:
                self.sniffer.stop()
            print("[*] Packet sniffing stopped.")

    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else None
            payload_data = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload) if UDP in packet else None

            if payload_data:
                try:
                    readable_payload = payload_data.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    readable_payload = ''.join('.' if not chr(b).isprintable() else chr(b) for b in payload_data)
                payload_representation = readable_payload
            else:
                payload_representation = None

            packet_summary = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "protocol": protocol,
                "payload": payload_representation,
                "application_protocol": self.detect_application_protocol(packet, payload_data)
            }

            with self.lock:
                self.packets.append(packet_summary)

    def detect_application_protocol(self, packet, payload_data):
        if not payload_data:
            return None
        if payload_data.startswith(b"USER ") or payload_data.startswith(b"PASS "):
            return "FTP"
        if TCP in packet and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
            return "SSH"
        if payload_data.startswith(b"EHLO") or payload_data.startswith(b"MAIL FROM"):
            return "SMTP"
        if TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
            return "HTTPS"
        return "Unknown"

    def get_captured_packets(self):
        """Returns a copy of the captured packets."""
        with self.lock:
            return list(self.packets)

    def clear_packets(self):
        """Clears the captured packets."""
        with self.lock:
            self.packets.clear()

    def save_packets_to_json(self, filename):
        """Saves the captured packets to a JSON file."""
        with self.lock:
            with open(filename, 'w') as f:
                json.dump(list(self.packets), f, indent=4)

    def load_packets_from_json(self, filename):
        """Loads packets from a JSON file."""
        with open(filename, 'r') as f:
            packets = json.load(f)
        with self.lock:
            self.packets = deque(packets, maxlen=1000)

if __name__ == "__main__":
    sniffer = PacketSniffer(interface=None, store=True, filter_str="tcp")
    sniffer.start_sniffing()

    try:
        for _ in range(10):
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    sniffer.stop_sniffing()

    packets = sniffer.get_captured_packets()
    for packet in packets:
        print(packet)

    # Save packets to a JSON file
    sniffer.save_packets_to_json("captured_packets.json")

    # Load packets from a JSON file (for testing)
    sniffer.load_packets_from_json("captured_packets.json")
    for packet in sniffer.get_captured_packets():
        print(packet)
