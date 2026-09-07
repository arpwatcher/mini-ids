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


def content_matches(payload, pattern):
    """pattern is None when the rule doesn't care about payload content -
    that always matches. Otherwise it's a plain substring search, case
    sensitive, same as snort's basic content matching."""
    if pattern is None:
        return True
    return pattern.encode() in payload


def _endpoints_match(rule, packet, reverse=False):
    if reverse:
        src_ip_pattern, dst_ip_pattern = rule.dst_ip, rule.src_ip
        src_port_pattern, dst_port_pattern = rule.dst_port, rule.src_port
    else:
        src_ip_pattern, dst_ip_pattern = rule.src_ip, rule.dst_ip
        src_port_pattern, dst_port_pattern = rule.src_port, rule.dst_port

    return (
        ip_matches(packet["src_ip"], src_ip_pattern)
        and ip_matches(packet["dst_ip"], dst_ip_pattern)
        and port_matches(packet.get("src_port"), src_port_pattern)
        and port_matches(packet.get("dst_port"), dst_port_pattern)
    )


def rule_matches(rule, packet):
    if not proto_matches(packet["proto"], rule.proto):
        return False
    if not content_matches(packet.get("payload", b""), rule.content):
        return False

    if _endpoints_match(rule, packet):
        return True
    if rule.bidirectional and _endpoints_match(rule, packet, reverse=True):
        return True
    return False


def evaluate(rules, packets):
    """Run every rule against every packet, return a flat list of alerts."""
    alerts = []
    for packet in packets:
        for rule in rules:
            if rule_matches(rule, packet):
                alerts.append({"rule": rule, "packet": packet})
    return alerts
