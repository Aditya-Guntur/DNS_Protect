import argparse
import json
import logging
from utils.config import load_config
from utils.logging_setup import setup_logging
from pipeline import run_pcap_pipeline


def main():
    parser = argparse.ArgumentParser(description="DNS Covert Communication Detection CLI")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--config", help="Path to config JSON", default=None)
    parser.add_argument("--out", help="Write full JSON report to file", default=None)
    parser.add_argument("--enable-web-checks", action="store_true", help="Enable web/WHOIS/SSL checks")
    parser.add_argument("--log-level", default=None, help="Logging level (DEBUG, INFO, WARNING)")

    args = parser.parse_args()

    config = load_config(args.config)
    if args.enable_web_checks:
        config.setdefault('pipeline', {})['enable_web_checks'] = True
    if args.log_level:
        config.setdefault('logging', {})['level'] = args.log_level

    setup_logging(config.get('logging', {}).get('level', 'INFO'))

    report = run_pcap_pipeline(args.pcap, config)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(_serialize_report(report), f, default=str, indent=2)
        print(f"Report written to {args.out}")
    else:
        print(json.dumps(_serialize_report(report), default=str, indent=2))


def _serialize_report(report):
    # Convert non-serializable fields, like datetime
    def convert(obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return obj
    return json.loads(json.dumps(report, default=convert))


if __name__ == "__main__":
    main()
