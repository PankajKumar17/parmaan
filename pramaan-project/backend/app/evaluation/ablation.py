from app.evaluation.metrics import _counts


def run_ablation(run_pipeline_fn, module_names):
    """Call pipeline(disabled_modules=tuple) -> {findings, ground_truth}.

    Reuse the identical ground truth for every run. Deltas are ablated minus
    baseline precision/recall on unique flagged assets; detectors remain separate
    in the primary metrics module. Callbacks own fixed inputs and random seeds.
    """
    names = list(module_names)
    if len(set(names)) != len(names):
        raise ValueError("Module names must be unique")

    def evaluate(disabled):
        report = run_pipeline_fn(disabled_modules=disabled)
        truth = report["ground_truth"]
        predicted = {str(finding.asset_id) for finding in report["findings"]
                     if finding.recommended_action.lower() != "accept" and finding.severity > 0 and finding.confidence > 0}
        return _counts(predicted, set(map(str, truth["affected"]))), truth

    baseline, ground_truth = evaluate(())
    result = {}
    for name in names:
        metrics, truth = evaluate((name,))
        if truth != ground_truth:
            raise ValueError("Ablation changed ground truth; comparisons would be invalid")
        result[name] = {"baseline": baseline.copy(), "ablated": metrics,
                        "precision_delta": metrics["precision"] - baseline["precision"],
                        "recall_delta": metrics["recall"] - baseline["recall"]}
    return result
