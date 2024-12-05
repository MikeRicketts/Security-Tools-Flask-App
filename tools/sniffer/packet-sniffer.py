import json
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import AsyncSniffer
import threading
import time
from collections import deque

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
        """Starts the packet sniffing in a separate thread."""
        if not self.sniffing.is_set():
            self.sniffing.set()
            self.thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.thread.start()
            print("[*] Packet sniffing started.")

    def stop_sniffing(self):
        """Stops the packet sniffing."""
        if self.sniffing.is_set():
            self.sniffing.clear()
            print("[*] Stopping packet sniffing...")
            if self.sniffer:
                self.sniffer.stop()
            if self.thread is not None:
                self.thread.join()
            print("[*] Packet sniffing stopped.")

    def sniff_packets(self):
        """Sniffs packets and processes them."""
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.filter_str,
            prn=self.process_packet,
            store=self.store
        )
        self.sniffer.start()
        while self.sniffing.is_set():
            time.sleep(0.1)

    def process_packet(self, packet):
        """Processes each captured packet and stores relevant information."""
        if IP in packet:
            ip_layer = packet[IP]
            protocol = None
            payload = None

            if TCP in packet:
                protocol = "TCP"
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                protocol = "UDP"
                payload = bytes(packet[UDP].payload)
            else:
                protocol = ip_layer.proto  # Numeric protocol

            packet_info = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "protocol": protocol,
                "payload": payload.hex() if payload else None  # Convert to hex for safer serialization
            }

            with self.lock:
                self.packets.append(packet_info)

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
