from ids import engine, rules

THRESHOLD_RULE = rules.parse_rule(
    'alert tcp any any -> any 22 (msg:"ssh brute force"; sid:1; count:5; seconds:60;)'
)
STATELESS_RULE = rules.parse_rule('alert tcp any any -> any 443 (msg:"https"; sid:2;)')


def make(src, t, port=22, dst="10.0.0.10"):
    return {"time": t, "proto": "tcp", "src_ip": src, "src_port": 40000, "dst_ip": dst, "dst_port": port}


def test_threshold_rule_fires_once_for_a_burst():
    packets = [make("10.0.0.99", t) for t in [0, 5, 10, 15, 20, 25, 30, 35]]
    alerts = engine.evaluate_threshold_rule(THRESHOLD_RULE, packets)
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "10.0.0.99"
    assert alerts[0]["count"] == 8


def test_threshold_rule_below_count_no_alert():
    packets = [make("10.0.0.99", t) for t in [0, 5, 10]]
    assert engine.evaluate_threshold_rule(THRESHOLD_RULE, packets) == []


def test_threshold_rule_spread_too_wide_no_alert():
    packets = [make("10.0.0.99", t) for t in [0, 100, 200, 300, 400]]
    assert engine.evaluate_threshold_rule(THRESHOLD_RULE, packets) == []


def test_threshold_rule_tracks_sources_independently():
    packets = (
        [make("10.0.0.99", t) for t in [0, 5, 10, 15, 20]]
        + [make("10.0.0.50", t) for t in [0, 5]]
    )
    alerts = engine.evaluate_threshold_rule(THRESHOLD_RULE, packets)
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "10.0.0.99"


def test_threshold_rule_two_separate_bursts_from_same_source():
    first_burst = [make("10.0.0.99", t) for t in [0, 5, 10, 15, 20]]
    second_burst = [make("10.0.0.99", t) for t in [200, 205, 210, 215, 220]]
    alerts = engine.evaluate_threshold_rule(THRESHOLD_RULE, first_burst + second_burst)
    assert len(alerts) == 2


def test_evaluate_combines_stateless_and_threshold():
    packets = [make("10.0.0.5", 0, port=443)] + [make("10.0.0.99", t) for t in [0, 5, 10, 15, 20]]
    alerts = engine.evaluate([THRESHOLD_RULE, STATELESS_RULE], packets)
    assert len(alerts) == 2
    sids = {a["rule"].sid for a in alerts}
    assert sids == {1, 2}


def test_evaluate_stateless_only_ruleset_unaffected():
    packets = [make("10.0.0.5", 0, port=443)]
    alerts = engine.evaluate([STATELESS_RULE], packets)
    assert len(alerts) == 1
    assert "packet" in alerts[0]
