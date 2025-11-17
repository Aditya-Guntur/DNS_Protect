import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from utils.config import load_config
from utils.logging_setup import setup_logging
from pipeline import run_pcap_pipeline


def main():
    parser = argparse.ArgumentParser(description="DNS Covert Communication Detection CLI")

    # Backward-compatible analyze path: allow providing a PCAP directly
    parser.add_argument("pcap", nargs='?', help="Path to PCAP file")

    # Common options
    parser.add_argument("--config", help="Path to config JSON", default=None)
    parser.add_argument("--out", help="Write full JSON report to file", default=None)
    parser.add_argument("--enable-web-checks", action="store_true", help="Enable web/WHOIS/SSL checks")
    parser.add_argument("--log-level", default=None, help="Logging level (DEBUG, INFO, WARNING)")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command")

    capture = subparsers.add_parser("capture", help="Capture DNS traffic with Tshark and analyze it")
    capture.add_argument("-i", "--interface", help="Tshark interface index or name (use 'tshark -D' to list)")
    capture.add_argument("-d", "--duration", type=int, default=60, help="Capture duration in seconds (default: 60)")
    capture.add_argument("--out-pcap", default=None, help="Where to save the captured PCAP (default: ./capture_dns.pcap)")

    args = parser.parse_args()

    # Configure logging as early as possible
    config = load_config(args.config)
    if args.enable_web_checks:
        config.setdefault('pipeline', {})['enable_web_checks'] = True
    if args.log_level:
        config.setdefault('logging', {})['level'] = args.log_level
    setup_logging(config.get('logging', {}).get('level', 'INFO'))

    if args.command == "capture":
        _run_capture_then_analyze(args, config)
        return

    # Analyze mode (backward compatible): require a PCAP path
    if not args.pcap:
        parser.print_usage(sys.stderr)
        print("error: please provide a PCAP path or use the 'capture' subcommand", file=sys.stderr)
        sys.exit(2)

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


def _run_capture_then_analyze(args, config):
    tshark_path = shutil.which("tshark") or r"C:\\Program Files\\Wireshark\\tshark.exe"
    if not os.path.exists(tshark_path):
        print("Tshark not found. Please install Wireshark (includes Tshark) and ensure it's in PATH.", file=sys.stderr)
        print("Download: https://www.wireshark.org/download.html", file=sys.stderr)
        sys.exit(1)

    if not args.interface:
        # Show interfaces to help the user choose
        try:
            result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True, check=True)
            print("Available interfaces:")
            print(result.stdout)
            print("Please rerun with -i <index|name>. Example: python cli.py capture -i 1 -d 60", file=sys.stderr)
        except Exception:
            print("Unable to list interfaces. Run 'tshark -D' manually to list interfaces.", file=sys.stderr)
        sys.exit(2)

    out_pcap = args.out_pcap or os.path.join(os.getcwd(), "capture_dns.pcap")

    capture_filter = "udp port 53 or tcp port 53"
    cmd = [
        tshark_path,
        "-i", str(args.interface),
        "-f", capture_filter,
        "-a", f"duration:{int(args.duration)}",
        "-F", "libpcap",  # Force classic PCAP format
        "-w", out_pcap,
    ]

    logging.getLogger(__name__).info("Starting Tshark capture: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Tshark capture failed: {e}", file=sys.stderr)
        sys.exit(e.returncode or 1)

    logging.getLogger(__name__).info("Capture complete. Saved to: %s", out_pcap)

    # Analyze captured PCAP
    report = run_pcap_pipeline(out_pcap, config)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(_serialize_report(report), f, default=str, indent=2)
        print(f"Report written to {args.out}")
    else:
        print(json.dumps(_serialize_report(report), default=str, indent=2))


if __name__ == "__main__":
    main()
