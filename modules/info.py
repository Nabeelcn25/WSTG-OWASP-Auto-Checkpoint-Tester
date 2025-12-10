# modules/info.py

from modules.info_checks import info02, info03, info04
# If/when you add info01.py, import it too:
# from modules.info_checks import info01


INFO_CHECKS = {
    # "info01": info01.check_info_01,  # uncomment when info01 exists
    "info02": info02.check_info_02,
    "info03": info03.check_info_03,
    "info04": info04.check_info_04,
}


def available_checks():
    """Return sorted list of available check function keys."""
    return sorted(INFO_CHECKS.keys())


def run_all_checks(brain, reporter, verifier=None):
    """Run all info checks in fixed order."""
    for name in ["info02", "info03", "info04"]:
        func = INFO_CHECKS.get(name)
        if func:
            print(f"[*] Running {name} ...")
            func(brain, reporter, verifier)


def run_selected_checks(brain, reporter, verifier, selected):
    """Run only selected checks from a list like ['info02', 'info04']."""
    for name in selected:
        key = name.lower()
        func = INFO_CHECKS.get(key)
        if not func:
            print(f"[!] Unknown check: {name} (skipping)")
            continue
        print(f"[*] Running {key} ...")
        func(brain, reporter, verifier)
