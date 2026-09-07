from ids import match, rules

BIDIR_RULE = rules.parse_rule('alert tcp 10.0.0.5 any <> 10.0.0.10 445 (msg:"smb"; sid:1;)')
ONEWAY_RULE = rules.parse_rule('alert tcp 10.0.0.5 any -> 10.0.0.10 445 (msg:"smb oneway"; sid:2;)')


def make_packet(src_ip, src_port, dst_ip, dst_port, proto="tcp"):
    return {"proto": proto, "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port}


def test_bidirectional_matches_forward_direction():
    pkt = make_packet("10.0.0.5", 5000, "10.0.0.10", 445)
    assert match.rule_matches(BIDIR_RULE, pkt)


def test_bidirectional_matches_reverse_direction():
    pkt = make_packet("10.0.0.10", 445, "10.0.0.5", 5000)
    assert match.rule_matches(BIDIR_RULE, pkt)


def test_bidirectional_does_not_match_unrelated_hosts():
    pkt = make_packet("10.0.0.20", 5000, "10.0.0.30", 445)
    assert not match.rule_matches(BIDIR_RULE, pkt)


def test_oneway_matches_forward_only():
    forward = make_packet("10.0.0.5", 5000, "10.0.0.10", 445)
    reverse = make_packet("10.0.0.10", 445, "10.0.0.5", 5000)
    assert match.rule_matches(ONEWAY_RULE, forward)
    assert not match.rule_matches(ONEWAY_RULE, reverse)


def test_bidirectional_still_respects_proto():
    pkt = make_packet("10.0.0.5", 5000, "10.0.0.10", 445, proto="udp")
    assert not match.rule_matches(BIDIR_RULE, pkt)


def test_bidirectional_reverse_wrong_port_no_match():
    pkt = make_packet("10.0.0.10", 9999, "10.0.0.5", 5000)
    assert not match.rule_matches(BIDIR_RULE, pkt)
