from ids import match, rules


def make_packet(payload=b"", proto="tcp", src_ip="10.0.0.5", src_port=1234,
                 dst_ip="10.0.0.20", dst_port=21):
    return {"proto": proto, "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port, "payload": payload}


def test_content_matches_none_pattern_always_true():
    assert match.content_matches(b"anything at all", None)
    assert match.content_matches(b"", None)


def test_content_matches_substring_found():
    assert match.content_matches(b"USER admin\r\nPASS hunter2\r\n", "PASS ")


def test_content_matches_substring_not_found():
    assert not match.content_matches(b"USER admin\r\n", "PASS ")


def test_content_matches_case_sensitive():
    assert not match.content_matches(b"pass hunter2", "PASS ")


def test_content_matches_nocase():
    assert match.content_matches(b"pass hunter2", "PASS ", nocase=True)
    assert match.content_matches(b"PaSs hunter2", "pass ", nocase=True)


def test_content_matches_nocase_still_requires_substring():
    assert not match.content_matches(b"USER admin\r\n", "PASS ", nocase=True)


def test_rule_matches_with_nocase_option():
    rule = rules.parse_rule(
        'alert tcp any any -> any 21 (msg:"x"; sid:1; content:"pass "; nocase;)'
    )
    assert match.rule_matches(rule, make_packet(payload=b"PASS hunter2\r\n"))
    assert match.rule_matches(rule, make_packet(payload=b"pass hunter2\r\n"))


def test_rule_matches_with_content_option():
    rule = rules.parse_rule('alert tcp any any -> any 21 (msg:"x"; sid:1; content:"PASS ";)')
    matching_pkt = make_packet(payload=b"PASS hunter2\r\n")
    non_matching_pkt = make_packet(payload=b"USER admin\r\n")
    assert match.rule_matches(rule, matching_pkt)
    assert not match.rule_matches(rule, non_matching_pkt)


def test_rule_without_content_ignores_payload():
    rule = rules.parse_rule('alert tcp any any -> any 21 (msg:"x"; sid:1;)')
    assert match.rule_matches(rule, make_packet(payload=b"anything"))
    assert match.rule_matches(rule, make_packet(payload=b""))


def test_rule_matches_still_checks_other_fields_with_content():
    rule = rules.parse_rule('alert tcp any any -> any 21 (msg:"x"; sid:1; content:"PASS ";)')
    wrong_port = make_packet(payload=b"PASS hunter2", dst_port=22)
    assert not match.rule_matches(rule, wrong_port)
