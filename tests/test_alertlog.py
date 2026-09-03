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


def test_format_packet_alert_includes_sid_and_msg():
    line = alertlog.format_alert(make_packet_alert())
    assert "[1000005]" in line
    assert "ftp cleartext password" in line
    assert "10.0.0.5:54000 -> 10.0.0.20:21" in line


def test_format_threshold_alert_includes_burst_info():
    line = alertlog.format_alert(make_threshold_alert())
    assert "[1000004]" in line
    assert "ssh brute force" in line
    assert "10.0.0.88 made 6 matches within 60s" in line


def test_write_alerts_creates_file_with_one_line_per_alert(tmp_path):
    log_path = tmp_path / "alerts.log"
    alertlog.write_alerts([make_packet_alert(), make_threshold_alert()], log_path, append=False)

    lines = log_path.read_text().splitlines()
    assert len(lines) == 2


def test_write_alerts_append_mode_adds_to_existing_file(tmp_path):
    log_path = tmp_path / "alerts.log"
    alertlog.write_alerts([make_packet_alert()], log_path, append=False)
    alertlog.write_alerts([make_packet_alert()], log_path, append=True)

    lines = log_path.read_text().splitlines()
    assert len(lines) == 2


def test_write_alerts_overwrite_mode_replaces_file(tmp_path):
    log_path = tmp_path / "alerts.log"
    alertlog.write_alerts([make_packet_alert(), make_threshold_alert()], log_path, append=False)
    alertlog.write_alerts([make_packet_alert()], log_path, append=False)

    lines = log_path.read_text().splitlines()
    assert len(lines) == 1
