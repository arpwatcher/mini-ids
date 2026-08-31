# mini-ids

A small rule based intrusion detection engine, snort/suricata style but stripped down to
the core idea: write rules describing traffic you care about, run them against a capture,
get alerts back. Started as a step up from pcap-toolkit - that one analyzes traffic after
the fact, this one is closer to how a real IDS actually works (a rule language plus a
matching engine).

- `rules.py` - parses the rule language into `Rule` objects. Syntax:
  `alert tcp any any -> 10.0.0.10 22 (msg:"ssh connection attempt"; sid:1000001;)`.
  Only the `->` direction is supported for now, msg and sid are required options.
- `match.py` - the matching engine: protocol, ip (exact or CIDR), and port (exact or
  range, e.g. `8000:9000`) matching, plus `evaluate()` which runs a full ruleset against
  a list of packets and returns every match as an alert.
- `packets.py` - a small standalone pcap reader built on scapy. Deliberately not shared
  with pcap-toolkit so this repo builds and runs entirely on its own.

Still to come: stateful rules (rate/threshold based, e.g. "5 connections in 10 seconds"),
payload content matching, live capture instead of just pcap files.

## Usage

```
pip install -r requirements.txt
python -m ids.cli check-rules tests/fixtures/sample.rules
python -m ids.cli run tests/fixtures/sample.rules tests/fixtures/sample.pcap
```

Write your own rules in a `.rules` file, one per line, `#` for comments.

## Tests

```
pytest
```

22 tests. `tests/fixtures/sample.pcap` is a small synthetic capture built with
`tests/fixtures/make_sample_pcap.py`, `tests/fixtures/sample.rules` is a matching ruleset,
so the whole pipeline (parse rules, read pcap, match, alert) gets exercised end to end.
