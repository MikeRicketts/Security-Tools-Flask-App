"""Capture packets for a fixed duration and emit them as JSON on stdout.

Usage: python packet_sniffer.py [--iface eth0] [--duration 10] [--filter tcp]
"""
import argparse
import json
import logging
import sys
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # silence noisy warnings
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import AsyncSniffer


def detect_application_protocol(packet, payload):
    """Best-effort application-protocol guess from ports and payload prefixes."""
    if payload:
        if payload.startswith((b"USER ", b"PASS ")):
            return "FTP"
        if payload.startswith((b"EHLO", b"HELO", b"MAIL FROM")):
            return "SMTP"
    if TCP in packet:
        ports = {packet[TCP].sport, packet[TCP].dport}
        if 22 in ports:
            return "SSH"
        if 443 in ports:
            return "HTTPS"
        if 80 in ports:
            return "HTTP"
    return "Unknown"


def summarise(packet):
    """Reduce a Scapy packet to a JSON-serialisable dict, or None if not IP."""
    if IP not in packet:
        return None
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
    layer = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
    payload = bytes(layer.payload) if layer else b""
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": protocol,
        "payload": payload.hex() or None,
        "application_protocol": detect_application_protocol(packet, payload),
    }


def capture(iface, duration, bpf_filter):
    packets = []

    def handle(pkt):
        summary = summarise(pkt)
        if summary:
            packets.append(summary)

    sniffer = AsyncSniffer(iface=iface, filter=bpf_filter, prn=handle, store=False)
    sniffer.start()
    time.sleep(duration)
    sniffer.stop()
    return packets[:1000]


def main():
    parser = argparse.ArgumentParser(description="Capture packets and print JSON.")
    parser.add_argument("--iface", default=None, help="Interface to sniff (default: all)")
    parser.add_argument("--duration", type=int, default=10, help="Capture seconds")
    parser.add_argument("--filter", default="ip", help="BPF filter (default: ip)")
    args = parser.parse_args()

    try:
        packets = capture(args.iface, args.duration, args.filter)
    except PermissionError:
        sys.exit("packet capture requires elevated privileges (root / NET_RAW)")
    except Exception as exc:  # e.g. no capture backend (libpcap/Npcap) available
        sys.exit(f"packet capture failed: {exc}")

    json.dump(packets, sys.stdout)


if __name__ == "__main__":
    main()
