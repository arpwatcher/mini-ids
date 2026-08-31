"""Builds tests/fixtures/sample.pcap. Not part of the test suite - run
manually if it ever needs regenerating:
    python tests/fixtures/make_sample_pcap.py
"""

from pathlib import Path

from scapy.all import ICMP, TCP, UDP, IP, wrpcap

packets = []
t = 1700000000.0


def add(pkt, dt=0.01):
    global t
    pkt.time = t
    packets.append(pkt)
    t += dt


add(IP(src="203.0.113.5", dst="10.0.0.10") / TCP(sport=51000, dport=22, flags="S"))
add(IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=52000, dport=53))
add(IP(src="10.0.0.5", dst="10.0.0.20") / TCP(sport=53000, dport=23, flags="S"))
add(IP(src="10.0.0.5", dst="10.0.0.20") / TCP(sport=53000, dport=443, flags="S"))
add(IP(src="10.0.0.5", dst="10.0.0.1") / ICMP())

out_path = Path(__file__).parent / "sample.pcap"
wrpcap(str(out_path), packets)
print(f"wrote {len(packets)} packets to {out_path}")
