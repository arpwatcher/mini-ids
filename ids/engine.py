"""Ties rule matching together with time-windowed state tracking for
threshold rules. Stateless rules still go through match.evaluate() as
before - this only adds the extra pass for rules that carry count/seconds.
"""

from collections import defaultdict

from ids import match


def evaluate_threshold_rule(rule, packets):
    """Find every source ip that crosses `rule.count` matches within a
    rolling `rule.seconds` window, and emit one alert per burst.

    Once a burst qualifies, tracking for that source resets past the end
    of the burst rather than sliding one packet at a time - otherwise a
    long attack would fire an alert on every single packet once past the
    threshold, which is noise, not signal.
    """
    matching = sorted(
        (p for p in packets if match.rule_matches(rule, p)),
        key=lambda p: p["time"],
    )

    by_src = defaultdict(list)
    for pkt in matching:
        by_src[pkt["src_ip"]].append(pkt)

    alerts = []
    for src_ip, events in by_src.items():
        i = 0
        while i < len(events):
            window_start = events[i]["time"]
            window = [e for e in events[i:] if e["time"] - window_start <= rule.seconds]

            if len(window) >= rule.count:
                alerts.append({
                    "rule": rule,
                    "src_ip": src_ip,
                    "count": len(window),
                    "window_seconds": rule.seconds,
                    "first_packet": window[0],
                    "last_packet": window[-1],
                })
                i += len(window)
            else:
                i += 1

    return alerts


def evaluate(rules, packets):
    """Run a mixed ruleset (stateless and threshold) against packets.
    Returns a flat list of alerts - single-packet alerts have a "packet"
    key, threshold alerts have "src_ip"/"count"/"window_seconds" instead."""
    stateless_rules = [r for r in rules if not r.is_stateful]
    threshold_rules = [r for r in rules if r.is_stateful]

    alerts = match.evaluate(stateless_rules, packets)
    for rule in threshold_rules:
        alerts.extend(evaluate_threshold_rule(rule, packets))
    return alerts
