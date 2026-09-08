import pytest

from ids import rules


def test_rule_with_content_option():
    rule = rules.parse_rule('alert tcp any any -> any 21 (msg:"ftp password"; sid:1; content:"PASS ";)')
    assert rule.content == "PASS "
    assert rule.nocase is False


def test_rule_without_content_has_none():
    rule = rules.parse_rule('alert tcp any any -> any 22 (msg:"ssh"; sid:1;)')
    assert rule.content is None


def test_content_and_threshold_can_combine():
    rule = rules.parse_rule(
        'alert tcp any any -> any 21 (msg:"repeated login attempts"; sid:1; '
        'content:"PASS "; count:3; seconds:30;)'
    )
    assert rule.content == "PASS "
    assert rule.is_stateful


def test_rule_with_nocase_option():
    rule = rules.parse_rule(
        'alert tcp any any -> any 21 (msg:"ftp password, any case"; sid:1; '
        'content:"pass "; nocase;)'
    )
    assert rule.content == "pass "
    assert rule.nocase is True


def test_nocase_without_content_is_rejected():
    with pytest.raises(rules.RuleParseError):
        rules.parse_rule('alert tcp any any -> any 21 (msg:"bad rule"; sid:1; nocase;)')
