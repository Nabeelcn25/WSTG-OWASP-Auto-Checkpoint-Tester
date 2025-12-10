#!/usr/bin/env python3

import argparse

from architecture import TargetBrain, Reporter, AI_Verifier
from modules import info

from modules.idnt.idnt import run_idnt_checks
from modules.auth.auth import run_auth_checks
from modules.authz.authz04 import check_athz_04

from modules.conf.conf02 import check_conf_02
from modules.conf.conf05 import check_conf_05
from modules.conf.conf07 import check_conf_07

from modules.inpv.inpv import check_inpt_01, check_inpt_13
from modules.error.errh01 import check_errh_01

COLOR_RESET = "\033[0m"
COLOR_CYAN = "\033[36m"

# Optional late-stage INFO checks
try:
    from modules.infochecks.info07 import check_info_07
except ImportError:
    check_info_07 = None

try:
    from modules.infochecks.info10 import check_info_10
except ImportError:
    check_info_10 = None


def parse_args():
    parser = argparse.ArgumentParser(
        description="OWASP WSTG scanner"
    )

    parser.add_argument("target", help="Target URL or hostname")

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Run all info checks (default if no -f is specified)",
    )
    group.add_argument(
        "-f",
        "--function",
        nargs="+",
        metavar="CHECK",
        help=(
            "Run only specific checks, e.g. -f info01 info03. "
            f"Available: {', '.join(info.available_checks())}"
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    brain = TargetBrain(args.target, verbose=args.verbose)
    brain.initialize()

    verifier = AI_Verifier()
    reporter = Reporter(brain.domain, verbose=args.verbose)

    # INFO checks (early)
    if args.function:
        print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running selected INFO checks ...")
        info.run_selected_checks(brain, reporter, verifier, args.function)
    else:
        print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running INFO checks (01–04) ...")
        info.run_all_checks(brain, reporter, verifier)

    # IDNT
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running IDNT checks ...")
    run_idnt_checks(brain, reporter)

    # ATHN
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running ATHN checks ...")
    run_auth_checks(brain, reporter)

    # AUTHZ
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running AUTHZ-04 ...")
    check_athz_04(brain, reporter)

    # CONF
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running CONF-02 ...")
    check_conf_02(brain, reporter)
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running CONF-05 ...")
    check_conf_05(brain, reporter)
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running CONF-07 ...")
    check_conf_07(brain, reporter)

    # INPV
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running INPV-01 ...")
    check_inpt_01(brain, reporter)
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running INPV-13 ...")
    check_inpt_13(brain, reporter)

    # ERRH
    print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running ERRH-01 ...")
    check_errh_01(brain, reporter)

    # Late INFO checks
    if check_info_07 is not None:
        print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running INFO-07 (late stage) ...")
        check_info_07(brain, reporter, verifier)

    if check_info_10 is not None:
        print(f"{COLOR_CYAN}[*]{COLOR_RESET} Running INFO-10 (late stage) ...")
        check_info_10(brain, reporter, verifier)

    reporter.generate_report(brain)


if __name__ == "__main__":
    main()
