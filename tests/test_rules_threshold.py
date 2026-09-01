import pytest

from ids import rules


def test_stateful_rule_parses_count_and_seconds():
    rule = rules.parse_rule('alert tcp any any -> any 22 (msg:"brute force"; sid:1; count:5; seconds:60;)')
    assert rule.count == 5
    assert rule.seconds == 60
    assert rule.is_stateful


def test_stateless_rule_has_no_count_or_seconds():
    rule = rules.parse_rule('alert tcp any any -> any 22 (msg:"ssh"; sid:1;)')
    assert rule.count is None
    assert rule.seconds is None
    assert not rule.is_stateful


def test_count_without_seconds_raises():
    with pytest.raises(rules.RuleParseError):
        rules.parse_rule('alert tcp any any -> any 22 (msg:"x"; sid:1; count:5;)')


def test_seconds_without_count_raises():
    with pytest.raises(rules.RuleParseError):
        rules.parse_rule('alert tcp any any -> any 22 (msg:"x"; sid:1; seconds:60;)')
