"""Minimal pcap reader, just enough to feed the matching engine. Kept
separate and standalone rather than depending on pcap-toolkit, so this repo
builds and runs on its own."""

from scapy.all import ICMP, TCP, UDP, IP, Raw, rdpcap


def read_packets(path):
    packets = []
    for pkt in rdpcap(str(path)):
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        entry = {
            "time": float(pkt.time),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "payload": bytes(pkt[Raw].load) if Raw in pkt else b"",
        }

        if TCP in pkt:
            entry["proto"] = "tcp"
            entry["src_port"] = pkt[TCP].sport
            entry["dst_port"] = pkt[TCP].dport
        elif UDP in pkt:
            entry["proto"] = "udp"
            entry["src_port"] = pkt[UDP].sport
            entry["dst_port"] = pkt[UDP].dport
        elif ICMP in pkt:
            entry["proto"] = "icmp"
            entry["src_port"] = None
            entry["dst_port"] = None
        else:
            entry["proto"] = "other"
            entry["src_port"] = None
            entry["dst_port"] = None

        packets.append(entry)

    return packets
