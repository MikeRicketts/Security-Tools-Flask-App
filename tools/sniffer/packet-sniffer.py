from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import AsyncSniffer
import time
from collections import deque
import threading


def detect_application_protocol(packet_detect, payload_data):
    """Detects the application protocol based on the packet payload."""
    if not payload_data:
        return None
    if payload_data.startswith(b"USER ") or payload_data.startswith(b"PASS "):
        return "FTP" # File Transfer Protocol
    if TCP in packet_detect and (packet_detect[TCP].sport == 22 or packet_detect[TCP].dport == 22):
        return "SSH" # Secure Shell
    if payload_data.startswith(b"EHLO") or payload_data.startswith(b"MAIL FROM"):
        return "SMTP" # Simple Mail Transfer Protocol
    if TCP in packet_detect and (packet_detect[TCP].sport == 443 or packet_detect[TCP].dport == 443):
        return "HTTPS" # Hypertext Transfer Protocol Secure
    return "Unknown" # Unknown protocol


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
        """Starts the packet sniffing."""
        if not self.sniffing.is_set():
            self.sniffing.set()
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.filter_str,
                prn=self.process_packet,
                store=self.store
            )
            self.sniffer.start()

    def stop_sniffing(self):
        """Stops the packet sniffing."""
        if self.sniffing.is_set():
            self.sniffing.clear()
            if self.sniffer:
                self.sniffer.stop()


    def process_packet(self, packet_proc):
        """Processes packet and extracts relevant information."""
        if IP in packet_proc:
            ip_layer = packet_proc[IP]
            protocol = "TCP" if TCP in packet_proc else "UDP" if UDP in packet_proc else None
            payload_data = bytes(packet_proc[TCP].payload) if TCP in packet_proc else bytes(
                packet_proc[UDP].payload) if UDP in packet_proc else None

            if payload_data:
                readable_payload = payload_data.hex()
            else:
                readable_payload = None

            packet_summary = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "protocol": protocol,
                "payload": readable_payload,
                "application_protocol": detect_application_protocol(packet_proc, payload_data)
            }

            with self.lock:
                self.packets.append(packet_summary)

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
            packets_load = json.load(f)
        with self.lock:
            self.packets = deque(packets_load, maxlen=1000)

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
