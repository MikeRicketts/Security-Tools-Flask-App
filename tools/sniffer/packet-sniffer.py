from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import threading
import time

class PacketSniffer:
    def __init__(self, interface=None, store=False, filter_str=""):
        """
        Initializes the PacketSniffer.

        :param interface: Network interface to sniff on. If None, scapy selects the default.
        :param store: Whether to store packets in scapy's memory. False to minimize memory usage.
        :param filter_str: BPF filter string to filter packets (e.g., 'tcp', 'udp port 53').
        """
        self.interface = interface
        self.store = store
        self.filter_str = filter_str
        self.packets = []
        self.sniffing = False
        self.thread = None
        self.lock = threading.Lock()

    def start_sniffing(self):
        """Starts the packet sniffing in a separate thread."""
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.thread.start()
            print("[*] Packet sniffing started.")

    def stop_sniffing(self):
        """Stops the packet sniffing."""
        if self.sniffing:
            self.sniffing = False
            print("[*] Stopping packet sniffing...")
            if self.thread is not None:
                self.thread.join()
            print("[*] Packet sniffing stopped.")

    def sniff_packets(self):
        """Sniffs packets and processes them."""
        sniff(
            iface=self.interface,
            filter=self.filter_str,
            prn=self.process_packet,
            store=self.store,
            stop_filter=lambda pkt: not self.sniffing
        )

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
                "payload": payload.decode(errors='ignore')[:100]  # Limit payload size for readability
            }

            with self.lock:
                self.packets.append(packet_info)
                # Optional: Limit stored packets to prevent memory issues
                if len(self.packets) > 1000:
                    self.packets.pop(0)

    def get_captured_packets(self):
        """Returns a copy of the captured packets."""
        with self.lock:
            return list(self.packets)

    def clear_packets(self):
        """Clears the captured packets."""
        with self.lock:
            self.packets.clear()


if __name__ == "__main__":
    # Initialize the packet sniffer with default interface
    sniffer = PacketSniffer(interface=None, store=True, filter_str="tcp")

    # Start sniffing
    sniffer.start_sniffing()

    # Keep the main thread alive for 10 seconds
    try:
        for _ in range(10):
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # Stop sniffing
    sniffer.stop_sniffing()

    # Retrieve captured packets
    packets = sniffer.get_captured_packets()

    # Print captured packets
    for packet in packets:
        print(packet)