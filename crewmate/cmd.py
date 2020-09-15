import argparse
import os

from crewmate.dissector import Dissector


def parse_arguments():
    parser = argparse.ArgumentParser(description="Crewmate")
    parser.add_argument(
        "--dissect",
        metavar="<pcap filename>",
        help="path to .pcapng file to dissect"
    )
    return vars(parser.parse_args())


def validate_arguments(args):
    errors = []
    dissect = args.get("dissect", False)
    if dissect:
        if not os.path.exists(dissect):
            errors.append(f"File not found: {dissect}")
    return errors


def execute(args):
    if "dissect" in args:
        dissector = Dissector(args["dissect"])
        dissector.process_pcap()


def execute_from_commandline():
    args = parse_arguments()
    errors = validate_arguments(args)
    if not errors:
        execute(args)
    for error in errors:
        print(error)

