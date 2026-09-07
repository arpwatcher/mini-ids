import json

from ids import alertlog, rules

RULE = rules.parse_rule('alert tcp any any -> any 21 (msg:"ftp cleartext password"; sid:1000005; content:"PASS ";)')
THRESHOLD_RULE = rules.parse_rule(
    'alert tcp any any -> any 22 (msg:"ssh brute force"; sid:1000004; count:5; seconds:60;)'
)


def make_packet_alert():
    packet = {"time": 1700000000.0, "proto": "tcp", "src_ip": "10.0.0.5", "src_port": 54000,
              "dst_ip": "10.0.0.20", "dst_port": 21}
    return {"rule": RULE, "packet": packet}


def make_threshold_alert():
    last_packet = {"time": 1700000030.0}
    return {"rule": THRESHOLD_RULE, "src_ip": "10.0.0.88", "count": 6,
            "window_seconds": 60, "first_packet": {"time": 1700000000.0}, "last_packet": last_packet}


def test_alert_to_dict_packet_kind():
    d = alertlog.alert_to_dict(make_packet_alert())
    assert d["kind"] == "packet"
    assert d["sid"] == 1000005
    assert d["src_ip"] == "10.0.0.5"
    assert d["dst_port"] == 21


def test_alert_to_dict_threshold_kind():
    d = alertlog.alert_to_dict(make_threshold_alert())
    assert d["kind"] == "threshold"
    assert d["sid"] == 1000004
    assert d["src_ip"] == "10.0.0.88"
    assert d["count"] == 6
    assert d["window_seconds"] == 60


def test_alert_to_dict_is_json_serializable():
    dicts = [alertlog.alert_to_dict(make_packet_alert()), alertlog.alert_to_dict(make_threshold_alert())]
    serialized = json.dumps(dicts)
    parsed = json.loads(serialized)
    assert len(parsed) == 2
    assert parsed[0]["sid"] == 1000005
    assert parsed[1]["sid"] == 1000004
