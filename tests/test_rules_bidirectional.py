from ids import rules


def test_one_way_rule_not_bidirectional():
    rule = rules.parse_rule('alert tcp any any -> any 22 (msg:"ssh"; sid:1;)')
    assert rule.bidirectional is False


def test_bidirectional_rule_parses_direction():
    rule = rules.parse_rule('alert tcp any any <> any 445 (msg:"smb"; sid:1;)')
    assert rule.bidirectional is True


def test_bidirectional_rule_keeps_other_fields():
    rule = rules.parse_rule('alert tcp 10.0.0.5 any <> 10.0.0.10 445 (msg:"smb"; sid:1;)')
    assert rule.src_ip == "10.0.0.5"
    assert rule.dst_ip == "10.0.0.10"
    assert rule.dst_port == "445"


def test_bidirectional_rule_can_combine_with_content():
    rule = rules.parse_rule(
        'alert tcp any any <> any 445 (msg:"smb"; sid:1; content:"SMB";)'
    )
    assert rule.bidirectional is True
    assert rule.content == "SMB"
