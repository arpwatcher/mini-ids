from ids import match, rules


def make_packet(proto="tcp", src_ip="10.0.0.5", src_port=1234, dst_ip="10.0.0.10", dst_port=22):
    return {"proto": proto, "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port}


def test_ip_matches_any():
    assert match.ip_matches("1.2.3.4", "any")


def test_ip_matches_exact():
    assert match.ip_matches("10.0.0.5", "10.0.0.5")
    assert not match.ip_matches("10.0.0.6", "10.0.0.5")


def test_ip_matches_cidr():
    assert match.ip_matches("192.168.1.50", "192.168.1.0/24")
    assert not match.ip_matches("192.168.2.50", "192.168.1.0/24")


def test_ip_matches_cidr_boundary():
    assert match.ip_matches("192.168.1.0", "192.168.1.0/24")
    assert match.ip_matches("192.168.1.255", "192.168.1.0/24")


def test_ip_matches_negated_exact():
    assert match.ip_matches("10.0.0.6", "!10.0.0.5")
    assert not match.ip_matches("10.0.0.5", "!10.0.0.5")


def test_ip_matches_negated_cidr():
    assert match.ip_matches("8.8.8.8", "!192.168.1.0/24")
    assert not match.ip_matches("192.168.1.50", "!192.168.1.0/24")


def test_rule_with_negated_source_excludes_that_host():
    rule = rules.parse_rule('alert tcp !10.0.0.5 any -> any 22 (msg:"ssh from elsewhere"; sid:1;)')
    assert not match.rule_matches(rule, make_packet(src_ip="10.0.0.5"))
    assert match.rule_matches(rule, make_packet(src_ip="10.0.0.9"))


def test_port_matches_any():
    assert match.port_matches(443, "any")


def test_port_matches_exact():
    assert match.port_matches(22, "22")
    assert not match.port_matches(23, "22")


def test_port_matches_range():
    assert match.port_matches(8080, "8000:9000")
    assert not match.port_matches(7999, "8000:9000")


def test_port_matches_none_value_only_matches_any():
    assert match.port_matches(None, "any")
    assert not match.port_matches(None, "22")


def test_proto_matches():
    assert match.proto_matches("tcp", "any")
    assert match.proto_matches("tcp", "tcp")
    assert not match.proto_matches("tcp", "udp")


def test_rule_matches_full_packet():
    rule = rules.parse_rule('alert tcp any any -> 10.0.0.10 22 (msg:"ssh"; sid:1;)')
    assert match.rule_matches(rule, make_packet())
    assert not match.rule_matches(rule, make_packet(dst_port=443))


def test_evaluate_returns_alert_per_match():
    ruleset = [rules.parse_rule('alert tcp any any -> any 22 (msg:"ssh"; sid:1;)')]
    packets = [make_packet(dst_port=22), make_packet(dst_port=443), make_packet(dst_port=22)]
    alerts = match.evaluate(ruleset, packets)
    assert len(alerts) == 2


def test_evaluate_no_alerts_when_nothing_matches():
    ruleset = [rules.parse_rule('alert tcp any any -> any 22 (msg:"ssh"; sid:1;)')]
    packets = [make_packet(dst_port=443)]
    assert match.evaluate(ruleset, packets) == []
