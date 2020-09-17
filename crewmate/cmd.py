import argparse
import os

from crewmate.capture import Capturer
from crewmate.dissector import PcapDissector


def parse_arguments():
    parser = argparse.ArgumentParser(description="Crewmate")
    parser.add_argument(
        "--dissect",
        metavar="<pcap filename>",
        help="path to .pcapng file to dissect"
    )
    parser.add_argument(
        "--capture",
        help="capture traffic in real time from an among us instance",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--pid",
        metavar="<pid>",
        help="pid of an among us instance",
        required=False,
        default=None,
    )
    return vars(parser.parse_args())


def validate_arguments(args):
    errors = []
    dissect = args.get("dissect", False)
    if dissect:
        if not os.path.exists(dissect):
            errors.append(f"File not found: {dissect}")
    pid = args.get("pid", False)
    if pid:
        try:
            args["pid"] = int(pid)
        except ValueError:
            errors.append(f"Invalid capture PID: {pid}")
    return errors


def execute(args):
    if args.get("dissect"):
        dissector = PcapDissector(args["dissect"])
        dissector.process_pcap()
    if args.get("capture"):
        capturer = Capturer(args.get("pid", None))
        capturer.capture()


def execute_from_commandline():
    args = parse_arguments()
    errors = validate_arguments(args)
    if not errors:
        execute(args)
    for error in errors:
        print(error)

