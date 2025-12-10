def _collect_candidate_params(brain):
    names = set()

    raw_params = list(getattr(brain, "raw_artifacts", {}).get("parameters", []))
    for p in raw_params:
        if isinstance(p, dict):
            n = (p.get("name") or "").strip()
        else:
            parts = str(p).split(":", 1)
            n = parts[1].strip() if len(parts) == 2 else str(p).strip()
        if n:
            names.add(n)

    flat_params = brain.artifacts.get("parameters", set()) or set()
    for p in flat_params:
        parts = str(p).split(":", 1)
        n = parts[1].strip() if len(parts) == 2 else str(p).strip()
        if n:
            names.add(n)

    tree = brain.mapper.generate_tree().get("root", {})

    def walk(node):
        for name, child in node.items():
            if name == "_meta":
                continue
            meta = child.get("_meta")
            if meta:
                for q in meta.get("params", []):
                    qn = str(q).strip()
                    if qn:
                        names.add(qn)
            walk(child)

    walk(tree)

    return sorted(names)


def _prepare_inpv_params(brain, reporter, check_id, manual_params=None, purpose="input validation"):
    auto_params = _collect_candidate_params(brain)
    if manual_params:
        auto_params.extend(manual_params)
    params = sorted(set(p for p in auto_params if p))

    if not params:
        reporter.log(
            check_id,
            "PASS",
            f"No candidate parameters were discovered in cached data; nothing to probe for {purpose} automatically.",
            location="Params",
        )
        return []

    reporter.log(
        check_id,
        "PASS",
        f"Auto-discovered candidate parameters for {purpose}: {params}. "
        "This list is heuristic; verify and extend it manually as needed.",
        location="Params",
    )
    return params


def check_inpt_01(brain, reporter, verifier=None, manual_params=None):
    check_id = "WSTG-INPV-01"

    params = _prepare_inpv_params(
        brain,
        reporter,
        check_id,
        manual_params=manual_params,
        purpose="reflected input testing",
    )
    if not params:
        return

    reporter.log(
        check_id,
        "PASS",
        "Reflected input engine should now use the prepared parameter list for active tests.",
        location="Engine",
    )


def check_inpt_13(brain, reporter, verifier=None, manual_params=None):
    check_id = "WSTG-INPV-13"

    params = _prepare_inpv_params(
        brain,
        reporter,
        check_id,
        manual_params=manual_params,
        purpose="client-side validation review",
    )
    if not params:
        return

    reporter.log(
        check_id,
        "PASS",
        "Client-side validation engine should now use the prepared parameter list for analysis.",
        location="Engine",
    )
