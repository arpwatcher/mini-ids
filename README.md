# mini-ids

A small rule based intrusion detection engine, snort/suricata style but stripped down to
the core idea: write rules describing traffic you care about, run them against a capture,
get alerts back. Started as a step up from pcap-toolkit - that one analyzes traffic after
the fact, this one is closer to how a real IDS actually works (a rule language plus a
matching engine).

- `rules.py` - parses the rule language into `Rule` objects. Syntax:
  `alert tcp any any -> 10.0.0.10 22 (msg:"ssh connection attempt"; sid:1000001;)`.
  msg and sid are required options. Direction can be `->` (one way) or `<>`
  (bidirectional - matches traffic from src to dst or dst to src, useful when you
  don't care which side initiated).
- `match.py` - single-packet matching: protocol, ip (exact or CIDR), port (exact or
  range, e.g. `8000:9000`), payload content (a `content:"..."` option, plain
  case-sensitive substring search over the raw tcp/udp payload - catches things like
  cleartext ftp passwords going over the wire, optionally case-insensitive with
  `nocase;`), and direction (checks both ways for a bidirectional rule).
- `engine.py` - ties matching together with time-windowed state. A rule with `count` and
  `seconds` options becomes stateful - instead of alerting on every match, it tracks
  matches per source ip and fires one alert per burst once a source crosses the threshold
  within the window, e.g. `count:5; seconds:60;` for "5 connection attempts inside a
  minute". Once a burst qualifies, tracking jumps past it rather than re-alerting on every
  packet past the threshold - that would be noise, not signal.
- `packets.py` - a small standalone pcap reader built on scapy. Deliberately not shared
  with pcap-toolkit so this repo builds and runs entirely on its own.
- `alertlog.py` - writes alerts to a log file, one line each, snort-fast-format inspired -
  timestamp, sid, message, then either the packet's src/dst or the burst summary for a
  threshold alert. Also has a plain-dict representation of an alert for `--format json`.

Still to come: live capture instead of just pcap files.

## Usage

```
pip install -r requirements.txt
python -m ids.cli check-rules tests/fixtures/sample.rules
python -m ids.cli run tests/fixtures/sample.rules tests/fixtures/sample.pcap
python -m ids.cli run tests/fixtures/sample.rules tests/fixtures/sample.pcap --log alerts.log
python -m ids.cli run tests/fixtures/sample.rules tests/fixtures/sample.pcap --format json
```

Write your own rules in a `.rules` file, one per line, `#` for comments.

## Tests

```
pytest
```

68 tests. `tests/fixtures/sample.pcap` is a small synthetic capture built with
`tests/fixtures/make_sample_pcap.py`, `tests/fixtures/sample.rules` is a matching ruleset
covering every feature (protocol/ip/port matching, a stateful brute-force rule, a content
match on a cleartext ftp password, a bidirectional smb rule), so the whole pipeline gets
exercised end to end.
