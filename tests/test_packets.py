from pathlib import Path

from ids import packets

FIXTURE = Path(__file__).parent / "fixtures" / "sample.pcap"


def test_read_packets_count():
    result = packets.read_packets(FIXTURE)
    assert len(result) == 11


def test_tcp_packet_fields():
    result = packets.read_packets(FIXTURE)
    ssh_pkt = next(p for p in result if p["dst_port"] == 22)
    assert ssh_pkt["src_ip"] == "203.0.113.5"
    assert ssh_pkt["proto"] == "tcp"


def test_icmp_packet_has_no_ports():
    result = packets.read_packets(FIXTURE)
    icmp_pkt = next(p for p in result if p["proto"] == "icmp")
    assert icmp_pkt["src_port"] is None
    assert icmp_pkt["dst_port"] is None
