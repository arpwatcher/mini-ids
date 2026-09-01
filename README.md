# mini-ids

A small rule based intrusion detection engine, snort/suricata style but stripped down to
the core idea: write rules describing traffic you care about, run them against a capture,
get alerts back. Started as a step up from pcap-toolkit - that one analyzes traffic after
the fact, this one is closer to how a real IDS actually works (a rule language plus a
matching engine).

- `rules.py` - parses the rule language into `Rule` objects. Syntax:
  `alert tcp any any -> 10.0.0.10 22 (msg:"ssh connection attempt"; sid:1000001;)`.
  Only the `->` direction is supported for now, msg and sid are required options.
- `match.py` - single-packet matching: protocol, ip (exact or CIDR), and port (exact or
  range, e.g. `8000:9000`).
- `engine.py` - ties matching together with time-windowed state. A rule with `count` and
  `seconds` options becomes stateful - instead of alerting on every match, it tracks
  matches per source ip and fires one alert per burst once a source crosses the threshold
  within the window, e.g. `count:5; seconds:60;` for "5 connection attempts inside a
  minute". Once a burst qualifies, tracking jumps past it rather than re-alerting on every
  packet past the threshold - that would be noise, not signal.
- `packets.py` - a small standalone pcap reader built on scapy. Deliberately not shared
  with pcap-toolkit so this repo builds and runs entirely on its own.

Still to come: payload content matching (a `content:"..."` option), an alert log file,
live capture instead of just pcap files.

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

33 tests. `tests/fixtures/sample.pcap` is a small synthetic capture built with
`tests/fixtures/make_sample_pcap.py`, `tests/fixtures/sample.rules` is a matching ruleset
including a stateful brute-force rule, so the whole pipeline (parse rules, read pcap,
match, threshold tracking, alert) gets exercised end to end. The fixture includes a
deliberate six-attempt ssh burst from one source to trigger the threshold rule.
