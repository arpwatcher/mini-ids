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


def alert_to_dict(alert):
    """Plain-data version of an alert, safe to json.dumps - the raw alert
    dicts carry a Rule object, which isn't serializable on its own."""
    rule = alert["rule"]
    base = {"sid": rule.sid, "msg": rule.msg, "proto": rule.proto}

    if "packet" in alert:
        pkt = alert["packet"]
        base.update({
            "kind": "packet",
            "time": pkt["time"],
            "src_ip": pkt["src_ip"],
            "src_port": pkt.get("src_port"),
            "dst_ip": pkt["dst_ip"],
            "dst_port": pkt.get("dst_port"),
        })
    else:
        base.update({
            "kind": "threshold",
            "time": alert["last_packet"]["time"],
            "src_ip": alert["src_ip"],
            "count": alert["count"],
            "window_seconds": alert["window_seconds"],
        })

    return base
