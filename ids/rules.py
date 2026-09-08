"""Parses a small snort/suricata-inspired rule language.

    alert tcp any any -> 10.0.0.10 22 (msg:"ssh connection attempt"; sid:1000001;)
    alert udp any any -> any 53 (msg:"dns query"; sid:1000002;)

A rule can also carry count/seconds options to make it stateful - instead of
alerting on every matching packet, it tracks matches per source ip and only
fires once that source crosses count matches within a rolling window:

    alert tcp any any -> any 22 (msg:"ssh brute force"; sid:1000004; count:5; seconds:60;)

A rule can also carry a content option to match against the packet payload,
a plain substring search (case sensitive) over the raw bytes:

    alert tcp any any -> any 21 (msg:"ftp cleartext password"; sid:1000005; content:"PASS ";)

Adding nocase makes the content match case insensitive, same as snort:

    alert tcp any any -> any 21 (msg:"ftp password, any case"; sid:1000007; content:"pass "; nocase;)

The direction operator can be "->" (one way, src to dst) or "<>" (either
direction - matches traffic from src to dst or from dst to src):

    alert tcp any any <> any 445 (msg:"smb traffic either direction"; sid:1000006;)
"""

import re
from dataclasses import dataclass, field

HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+"
    r"(?P<direction>->|<>)\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<options>.*)\)\s*$"
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
    count: int = None
    seconds: int = None
    content: str = None
    nocase: bool = False
    bidirectional: bool = False

    @property
    def is_stateful(self):
        return self.count is not None


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

    has_count = "count" in options
    has_seconds = "seconds" in options
    if has_count != has_seconds:
        raise RuleParseError(f"count and seconds must be used together: {line}")

    if "nocase" in options and "content" not in options:
        raise RuleParseError(f"nocase requires a content option: {line}")

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
        count=int(options["count"]) if has_count else None,
        seconds=int(options["seconds"]) if has_seconds else None,
        content=options.get("content"),
        nocase="nocase" in options,
        bidirectional=fields["direction"] == "<>",
    )


def parse_rules_file(path):
    rules = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(parse_rule(line))
    return rules
