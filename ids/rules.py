"""Parses a small snort/suricata-inspired rule language.

    alert tcp any any -> 10.0.0.10 22 (msg:"ssh connection attempt"; sid:1000001;)
    alert udp any any -> any 53 (msg:"dns query"; sid:1000002;)

Only the "->" direction is supported for now (no bidirectional "<>" yet).
"""

import re
from dataclasses import dataclass, field

HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+"
    r"->\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<options>.*)\)\s*$"
)


class RuleParseError(ValueError):
    pass


@dataclass
class Rule:
    action: str
    proto: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    msg: str
    sid: int
    options: dict = field(default_factory=dict)


def _parse_options(raw):
    options = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            key, _, value = part.partition(":")
            options[key.strip()] = value.strip().strip('"')
        else:
            options[part] = True
    return options


def parse_rule(line):
    line = line.strip()
    match = HEADER_RE.match(line)
    if not match:
        raise RuleParseError(f"malformed rule: {line}")

    fields = match.groupdict()
    options = _parse_options(fields["options"])

    if "msg" not in options:
        raise RuleParseError(f"rule missing msg option: {line}")
    if "sid" not in options:
        raise RuleParseError(f"rule missing sid option: {line}")

    return Rule(
        action=fields["action"],
        proto=fields["proto"].lower(),
        src_ip=fields["src_ip"],
        src_port=fields["src_port"],
        dst_ip=fields["dst_ip"],
        dst_port=fields["dst_port"],
        msg=options["msg"],
        sid=int(options["sid"]),
        options=options,
    )


def parse_rules_file(path):
    rules = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(parse_rule(line))
    return rules
