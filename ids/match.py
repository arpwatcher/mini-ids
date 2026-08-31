"""Matches parsed rules against packets. Kept separate from rules.py so the
rule language and the matching logic can change independently."""


def _ip_to_int(ip_str):
    parts = ip_str.split(".")
    value = 0
    for part in parts:
        value = (value << 8) | int(part)
    return value


def ip_matches(value, pattern):
    if pattern == "any":
        return True

    if "/" in pattern:
        network, prefix_len = pattern.split("/")
        prefix_len = int(prefix_len)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF if prefix_len else 0
        return (_ip_to_int(value) & mask) == (_ip_to_int(network) & mask)

    return value == pattern


def port_matches(value, pattern):
    if pattern == "any":
        return True
    if value is None:
        return False

    if ":" in pattern:
        low, high = pattern.split(":")
        return int(low) <= value <= int(high)

    return value == int(pattern)


def proto_matches(value, pattern):
    return pattern == "any" or value == pattern


def rule_matches(rule, packet):
    return (
        proto_matches(packet["proto"], rule.proto)
        and ip_matches(packet["src_ip"], rule.src_ip)
        and ip_matches(packet["dst_ip"], rule.dst_ip)
        and port_matches(packet.get("src_port"), rule.src_port)
        and port_matches(packet.get("dst_port"), rule.dst_port)
    )


def evaluate(rules, packets):
    """Run every rule against every packet, return a flat list of alerts."""
    alerts = []
    for packet in packets:
        for rule in rules:
            if rule_matches(rule, packet):
                alerts.append({"rule": rule, "packet": packet})
    return alerts
