import argparse
import json
from pathlib import Path
from unv.engine import run
from unv.cli_printer import pretty

BANNER = Path(__file__).resolve().parent / "assets" / "banner.txt"

def main():
    if BANNER.exists():
        print(BANNER.read_text())

    p = argparse.ArgumentParser(
        prog="unveil",
        description="UNVEIL RADAR — Persistent Exploitability Surface Mapper",
        formatter_class=argparse.RawTextHelpFormatter
    )

    p.add_argument("--version", action="version", version="UNVEIL RADAR v1.0.1")

    p.add_argument("-C", "--target", required=True,
                   help="Target directory or application bundle to analyze")

    p.add_argument("-e", action="store_true",
                   help="Enable extended surface expansion (deep persistence & lateral surfaces)")

    p.add_argument("-O", action="store_true",
                   help="Enable offensive surface synthesis (exploit-chain modeling)")

    p.add_argument("-f", action="store_true",
                   help="Force analysis of unsigned / malformed binaries")

    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress banner and pretty rendering")

    p.add_argument("-xh", metavar="FILE",
                   help="Export pretty rendered report to HTML")

    p.add_argument("-xj", metavar="FILE",
                   help="Export full JSON report (indented)")

    p.add_argument("-xx", metavar="FILE",
                   help="Export compact raw JSON report")

    args = p.parse_args()

    report = run(args.target)

    if not args.quiet:
        pretty(report)

    if args.xh:
        from unv.renderer import render
        Path(args.xh).write_text(render(report))

    if args.xj:
        Path(args.xj).write_text(json.dumps(report, indent=2))

    if args.xx:
        Path(args.xx).write_text(json.dumps(report))

if __name__ == "__main__":
    main()
