"""Writes alerts to a log file, one line each, loosely modeled on snort's
"fast" alert format - readable on its own, greppable, one alert per line."""

from datetime import datetime, timezone


def format_alert(alert):
    rule = alert["rule"]

    if "packet" in alert:
        pkt = alert["packet"]
        ts = datetime.fromtimestamp(pkt["time"], tz=timezone.utc).isoformat()
        src = f"{pkt['src_ip']}:{pkt.get('src_port')}"
        dst = f"{pkt['dst_ip']}:{pkt.get('dst_port')}"
        return f"{ts} [**] [{rule.sid}] {rule.msg} [**] {{{pkt['proto']}}} {src} -> {dst}"

    ts = datetime.fromtimestamp(alert["last_packet"]["time"], tz=timezone.utc).isoformat()
    return (
        f"{ts} [**] [{rule.sid}] {rule.msg} [**] {{{rule.proto}}} "
        f"{alert['src_ip']} made {alert['count']} matches within {alert['window_seconds']}s"
    )


def write_alerts(alerts, path, append=True):
    mode = "a" if append else "w"
    with open(path, mode) as f:
        for alert in alerts:
            f.write(format_alert(alert) + "\n")
