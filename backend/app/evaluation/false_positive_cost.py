from app.core.decision import RiskDecisionMatrix


def false_positive_rate(run_pipeline_fn, clean_variants):
    """pipeline(variant) -> findings or {findings, verdicts?}.

    Unit is a clean variant, not a sample: any REVIEW/QUARANTINE is a false
    positive. Supplied verdicts are authoritative; otherwise use the decision
    matrix. Empty evaluations return rate=None and evaluated=False, not success.
    """
    total = flagged = quarantined = 0
    for variant in clean_variants:
        report = run_pipeline_fn(variant)
        if isinstance(report, dict):
            verdicts = report.get("verdicts")
            if verdicts is None:
                verdicts = RiskDecisionMatrix().decide(report["findings"])
        else:
            verdicts = RiskDecisionMatrix().decide(report)
        statuses = {verdict["verdict"].upper() for verdict in verdicts}
        if statuses - {"ACCEPT", "REVIEW", "QUARANTINE"}:
            raise ValueError("Unknown verdict")
        total += 1
        flagged += bool(statuses & {"REVIEW", "QUARANTINE"})
        quarantined += "QUARANTINE" in statuses
    rate = flagged / total if total else None
    return {"rate": rate, "flag": rate > 0.05 if rate is not None else False,
            "quarantine_rate": quarantined / total if total else None,
            "evaluated": bool(total), "variant_count": total, "false_positive_count": flagged}
