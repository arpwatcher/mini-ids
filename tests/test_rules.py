from pathlib import Path

import pytest

from ids import rules

FIXTURE = Path(__file__).parent / "fixtures" / "sample.rules"


def test_parse_rule_basic_fields():
    rule = rules.parse_rule('alert tcp any any -> 10.0.0.10 22 (msg:"ssh"; sid:1;)')
    assert rule.action == "alert"
    assert rule.proto == "tcp"
    assert rule.src_ip == "any"
    assert rule.dst_ip == "10.0.0.10"
    assert rule.dst_port == "22"
    assert rule.msg == "ssh"
    assert rule.sid == 1


def test_parse_rule_lowercases_protocol():
    rule = rules.parse_rule('alert TCP any any -> any any (msg:"x"; sid:1;)')
    assert rule.proto == "tcp"


def test_parse_rule_missing_msg_raises():
    with pytest.raises(rules.RuleParseError):
        rules.parse_rule('alert tcp any any -> any any (sid:1;)')


def test_parse_rule_missing_sid_raises():
    with pytest.raises(rules.RuleParseError):
        rules.parse_rule('alert tcp any any -> any any (msg:"x";)')


def test_parse_rule_malformed_raises():
    with pytest.raises(rules.RuleParseError):
        rules.parse_rule("not a rule at all")


def test_parse_rules_file_count():
    parsed = rules.parse_rules_file(FIXTURE)
    assert len(parsed) == 4


def test_parse_rules_file_skips_comments_and_blanks():
    parsed = rules.parse_rules_file(FIXTURE)
    sids = [r.sid for r in parsed]
    assert sids == [1000001, 1000002, 1000003, 1000004]
