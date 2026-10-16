import argparse
from pip_surgery.inventory import main as run_inventory

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pip-surgery",
        description="Analyze Python dependencies. No files are removed.",)

    commands = parser.add_subparsers(
        dest="command",
        required=True,)

    commands.add_parser(
        "inventory",
        help="List installed packages and save a JSON inventory.",)

    args = parser.parse_args()
    if args.command == "inventory":
        run_inventory()

if __name__ == "__main__":
    main()