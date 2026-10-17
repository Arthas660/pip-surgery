import argparse
from pathlib import Path

from pip_surgery.inventory import main as run_inventory


def main() -> None:
    parser = argparse.ArgumentParser(prog="surgery",description="Analyze Python dependencies. No files are removed.",)

    commands = parser.add_subparsers(
        dest="command",
        required=True,)

    inventory_parser = commands.add_parser(
        "inventory",
        help="List installed packages and save a JSON inventory.",)

    inventory_parser.add_argument("--output",type=Path,help="Report path. Existing files are never overwritten.",)
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            run_inventory(output=args.output)

    except FileExistsError:
        parser.exit(
            status=1,
            message="Error: output path already exists. Choose another path.\n",)

    except OSError as exc:
        parser.exit(status=1,message=f"Error: {exc}\n",)

if __name__ == "__main__":
    main()