"""Entry point: run a ruleset against a pcap file, print alerts."""

import argparse
import json
import sys

from ids import alertlog, engine, packets, rules


def cmd_run(args):
    ruleset = rules.parse_rules_file(args.rules)
    pkts = packets.read_packets(args.pcap)
    alerts = engine.evaluate(ruleset, pkts)

    if args.format == "json":
        print(json.dumps([alertlog.alert_to_dict(a) for a in alerts], indent=2))
    else:
        print(f"loaded {len(ruleset)} rules, read {len(pkts)} packets")

        if not alerts:
            print("no alerts")
        else:
            print(f"\n{len(alerts)} alerts:")
            for a in alerts:
                rule = a["rule"]
                if "packet" in a:
                    pkt = a["packet"]
                    print(f"  [sid:{rule.sid}] {rule.msg} - {pkt['src_ip']}:{pkt.get('src_port')} "
                          f"-> {pkt['dst_ip']}:{pkt.get('dst_port')} ({pkt['proto']})")
                else:
                    print(f"  [sid:{rule.sid}] {rule.msg} - {a['src_ip']} made {a['count']} matches "
                          f"within {a['window_seconds']}s")

    if args.log:
        alertlog.write_alerts(alerts, args.log, append=True)
        if args.format != "json":
            print(f"\nappended {len(alerts)} alerts to {args.log}")


def cmd_check_rules(args):
    ruleset = rules.parse_rules_file(args.rules)
    print(f"{len(ruleset)} rules loaded ok")
    for rule in ruleset:
        print(f"  sid:{rule.sid} {rule.proto} {rule.src_ip}:{rule.src_port} -> "
              f"{rule.dst_ip}:{rule.dst_port} - {rule.msg}")


def build_parser():
    parser = argparse.ArgumentParser(prog="mini-ids", description="rule based pcap analysis")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run a ruleset against a pcap file")
    run_parser.add_argument("rules")
    run_parser.add_argument("pcap")
    run_parser.add_argument("--log", help="append alerts to this log file")
    run_parser.add_argument("--format", choices=["text", "json"], default="text",
                             help="output format for alerts printed to stdout")
    run_parser.set_defaults(func=cmd_run)

    check_parser = sub.add_parser("check-rules", help="parse and list a ruleset without running it")
    check_parser.add_argument("rules")
    check_parser.set_defaults(func=cmd_check_rules)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (FileNotFoundError, rules.RuleParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
