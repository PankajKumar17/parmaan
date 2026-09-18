# PRAMAAN — Sequential Build Prompts for Claude Code

**How to use this doc:** Paste each prompt below into Claude Code (VS Code), in order, one at a time. Let Claude Code finish and verify each phase (run it, check the output) before pasting the next prompt — each phase builds on files created by the previous one. Don't skip ahead even if a later prompt looks independent; the shared interfaces are established early and everything downstream depends on them.

This doc encodes the full design from our planning session: the Evidence-Carrying AI thesis, the Attack-Agnostic Evidence Architecture, all five core modules, every algorithm/technique discussed, the four provenance properties, the risk/decision logic, the evaluation harness, and every differentiator. Nothing here introduces anything beyond what we already scoped — this is that design turned into buildable steps.

---

## Phase 0 — Project Scaffolding & Core Architecture

```
I'm building PRAMAAN — an offline, model-agnostic Computer Vision Integrity
Assurance system. Core thesis: "Evidence-Carrying AI" — every dataset, model,
and inference output carries its own evidence, provenance, confidence, and
limitations. Nothing is trusted by default.

Set up the project skeleton in Python 3.11 with this structure:

pramaan/
  core/
    evidence.py       # Finding, Evidence, and EvidenceProvider base classes
    correlation.py    # Correlation Engine (empty for now)
    decision.py        # Risk Decision Matrix (empty for now)
    lineage.py         # End-to-End Integrity Lineage graph (empty for now)
  ingestion/
    coco_yolo.py        # dataset parsers (stub)
    model_loader.py      # ONNX / TorchScript loader (stub)
  manifests/            # empty, filled in Phase 1
  provenance/            # empty, filled in Phase 1
  modules/
    data_integrity/      # empty, filled in Phase 2-3
    model_integrity/      # empty, filled in Phase 2-4
    drift/                # empty, filled in Phase 3
  evaluation/             # empty, filled in Phase 5
  dashboard/               # empty, filled in Phase 6
  tests/
  requirements.txt
  README.md

Build ONLY core/evidence.py fully right now. It must implement the
Attack-Agnostic Evidence Architecture — the single interface every detector
in this project will plug into, regardless of what attack type it targets:

  Evidence Provider → Finding → Evidence → Correlation → Decision

Requirements for core/evidence.py:
1. An `EvidenceProvider` abstract base class with an `analyze(asset) -> list[Finding]`
   method, plus fields for `detector_id` and `version` (every provider must
   declare these — they get embedded in every Finding it produces).
2. A `Modality` enum: PIXEL, EMBEDDING, ANNOTATION, ACTIVATION, BEHAVIORAL.
   (This is the Multi-Modal Evidence Formalization — every piece of evidence
   must declare which modality it came from, because later the Correlation
   Engine treats agreement ACROSS modalities as stronger than agreement
   within one modality.)
3. A `Finding` dataclass with these exact fields (this is the standard
   finding schema, don't simplify it):
   - asset_id: str
   - finding_type: str
   - severity: float (0-1)          # how bad IF true
   - confidence: float (0-1)          # how sure we are it's true — MUST be
     tracked separately from severity, never collapsed into one number
   - evidence: list[str]              # human-readable evidence strings
   - modality: Modality
   - provenance: dict                 # {detector_id, version, input_hashes: list[str], config_hash: str}
   - recommended_action: str          # "accept" | "review" | "quarantine"
   - quarantine_scope: str | None     # "sample" | "batch" | "contributor" | "model" | "inference_record"
   - access_assumptions: str          # "white_box" | "gray_box" | "black_box"
   - counter_evidence: list[str]       # evidence AGAINST this finding, for
     Decision Explanation — even a first-cut detector should support this
     field being populated later
4. An `Evidence` dataclass wrapping a single piece of evidence with its own
   modality tag, so the Correlation Engine can group by modality later.

Write a short README.md explaining the Evidence-Carrying AI thesis in 3-4
sentences and this core interface, so future me (or teammates) understands
why every detector must go through this interface rather than returning
ad-hoc dicts.

Also create requirements.txt with: numpy, torch, onnxruntime, scikit-learn,
opencv-python, pillow, cryptography, networkx, pycocotools, fastapi,
uvicorn streamlit (we'll decide between FastAPI+React and Streamlit for the
dashboard later — install both for now).

Do not implement any detectors yet. Do not implement manifests, provenance,
or the dashboard yet. This phase is ONLY the shared interface.
```

---

## Phase 1 — Manifests, Provenance Core & Self-Integrity Check

```
Continuing PRAMAAN. core/evidence.py from Phase 0 is in place. Now build the
foundational layer everything else depends on: manifests, cryptographic
provenance, and the self-integrity check. Build these fully — this is not a
stub phase.

### 1. manifests/dataset_manifest.py
A DatasetManifest that hashes and records: dataset version, per-sample
hashes, an aggregate annotation hash, class distribution, and
contributor/batch metadata (contributor_id, batch_id per sample). Provide
`build_from_coco(path)` and `build_from_yolo(path)` constructors, and a
`verify(current_path) -> bool` method that re-hashes the dataset and
compares against the stored manifest — this is what will later power
Assurance Staleness detection, so make it cheap to call repeatedly.

### 2. manifests/model_manifest.py
A ModelReferenceManifest ("golden baseline") storing: model hash (SHA-256
of the weight file), architecture identifier, expected metrics on a fixed
reference battery, baseline activation statistics (mean/std per layer on a
fixed calibration set), and output fingerprints. Support ONNX and
TorchScript. Include `identity_check(supplied_model_path) -> Finding` that
does SHA-256(supplied) vs SHA-256(reference) — this is the Model Identity
check, and it must be kept as a SEPARATE method/class concept from anything
behavioral (behavioral integrity comes in Phase 3) — identity is a certain,
binary check; behavioral is probabilistic evidence. Don't conflate them.

### 3. manifests/pipeline_manifest.py
A PipelineEnvironmentManifest binding: preprocessing parameters, confidence
thresholds, NMS settings, input resolution, model identifier, framework/
runtime version, pipeline version. This gets embedded in every provenance
record in step 4 below.

### 4. provenance/canonical.py
A canonical serialization function: given a dict, produce a deterministic
byte string (sorted keys, fixed float precision to 6 decimal places, UTF-8,
no whitespace variance) BEFORE anything gets hashed. This must be used
everywhere hashing happens in this project — identical logical records must
always produce identical hashes.

### 5. provenance/chain.py
This is the core provenance mechanism. Implement the FULL binding explicitly
— don't abbreviate this:

  input image hash → model/weight digest → preprocessing/config hash →
  output hash → Ed25519 signature → sequence/nonce/timestamp replay state

Concretely:
- `InferenceRecord` dataclass: input_hash, model_digest, config_hash (from
  the PipelineEnvironmentManifest), output_hash, sequence_number, nonce,
  timestamp.
- Canonically serialize the record (using canonical.py), SHA-256 it, sign
  the hash with Ed25519 (use the `cryptography` library).
- Hash-chain records: each record also stores the hash of the previous
  record, so the whole log is tamper-evident even without the signature.
- A `Verifier` class that maintains STATE — a set of seen (sequence_number,
  nonce) pairs. This is important: replay protection does NOT come from the
  nonce/sequence/timestamp fields existing on the record. It only exists
  because the verifier tracks which ones it has already seen and rejects
  repeats. Implement this state tracking explicitly, in-memory is fine for
  now (persist to disk in a later phase).
- The Verifier must be able to independently re-walk a chain of records and
  report exactly which record (and which of: hash integrity / signature /
  replay state) failed, if any.

Explicitly implement these as FOUR SEPARATE, NAMED properties (don't merge
them into one "verify()" black box) — integrity, authenticity, freshness,
and computation-correctness. For computation-correctness, for now just add
a stub method `verify_computation_consistency()` that returns "not yet
implemented — planned via Merkle tree over activations + spot re-execution
in a later phase, full guarantee would require zkML which is out of scope."
Being honest about what's NOT yet proven here matters more than looking
complete.

### 6. provenance/keys.py
Ed25519 keypair generation for offline setup: generate once, save private
key to a local keys/ directory (gitignored), expose the public key for the
Verifier config. Document in a comment that there's no live key rotation at
this project's scope — stated explicitly, not left implicit.

### 7. core/self_integrity.py
Assurance-of-the-Assurer: at startup, hash this project's own detector code
files, config files, and manifest schemas, compare against a known-good
checksum file (checksums.json, generated by a `scripts/record_checksums.py`
helper you should also write). If anything doesn't match, the system must
flag itself as running in a DEGRADED/UNVERIFIED state (set a global flag
other modules can check) rather than silently continuing. Keep this to a
single startup self-check — not recursive self-verification.

### 8. Wire it together
Write scripts/phase1_demo.py that: builds a DatasetManifest from a small
sample COCO folder (create a tiny synthetic 5-image COCO dataset for
testing if none exists), builds a ModelReferenceManifest from any small
ONNX model (download or create a trivial one for testing), creates a few
InferenceRecords, signs and chains them, then runs the Verifier over the
chain and prints a pass. Then tamper with one record and show the Verifier
catching exactly which one and why.

Write tests/test_provenance.py covering: canonical serialization
determinism, hash chain tamper detection, signature verification, and
replay detection (submit the same nonce twice, confirm rejection).
```

---

## Phase 2 — Data Integrity Basics, Model Identity Wiring, Lineage Graph, Dashboard Skeleton

```
Continuing PRAMAAN. Phases 0-1 are done (evidence interface, manifests,
provenance chain, self-integrity check). Now build:

### 1. modules/data_integrity/duplicates.py
An EvidenceProvider (subclassing the Phase-0 base class) for near-duplicate
flooding detection, using BOTH:
- Perceptual hashing (pHash) for fast, cheap first-pass duplicate detection
- CLIP or ResNet embedding clustering (use a pretrained, offline-cached
  model) for semantic near-duplicates pHash misses
Tag findings with Modality.PIXEL (for pHash) and Modality.EMBEDDING (for
the clustering pass) — these are two different modalities even though they
solve the same problem, and that distinction matters later for Evidence
Convergence.

### 2. modules/data_integrity/mislabeling.py
An EvidenceProvider for systematic mislabelling and label-flip detection:
train (or load) a quick reference classifier on the dataset, flag samples
where the classifier's confident prediction disagrees with the stated
label. Tag as Modality.ANNOTATION / Modality.BEHAVIORAL.

### 3. modules/data_integrity/ood.py
An EvidenceProvider for out-of-distribution insertion: Mahalanobis distance
in embedding space from per-class centroids. Tag Modality.EMBEDDING.

### 4. modules/data_integrity/annotation_integrity.py
An EvidenceProvider for annotation-level tampering: invalid bounding boxes
(out of image bounds, zero/negative area), deleted labels (heuristic: large
unlabeled region where a similar image has a label), and systematically
shifted boxes (consistent offset across many boxes in a batch — evidence of
programmatic tampering, not random noise). Tag Modality.ANNOTATION.

### 5. modules/model_integrity/identity.py
Wire the Phase-1 `identity_check` into an EvidenceProvider wrapper so it
participates in the same pipeline as everything else, emitting a Finding
with very high confidence (this is a certain check) and
access_assumptions="black_box" (hash comparison needs no model access
beyond the file itself).

### 6. core/lineage.py — End-to-End Integrity Lineage
Build this now, fully, using networkx. Every asset — contributor, dataset,
model, inference record, and Finding — becomes a node, hash-referenced, with
edges representing "produced by" / "derived from" relationships:

  Contributor → Dataset → Model → Inference → Finding

Provide:
- `add_contributor(id)`, `add_dataset(manifest, contributor_id)`,
  `add_model(manifest)`, `add_inference_record(record, model_id, dataset_id)`,
  `add_finding(finding, asset_id)`
- `downstream_of(asset_id) -> list[nodes]` — traversal for Blast-Radius
  Analysis later (don't build blast-radius reporting yet, just make sure
  this traversal method works, since a later phase builds directly on it)
- This graph is built ONCE and reused — do not let individual modules build
  their own separate tracking structures.

### 7. dashboard/ — Skeleton only
Set up a Streamlit app (dashboard/app.py) with empty placeholder pages for:
Requirement Traceability Matrix, Access-Level Capability Matrix. For the
Traceability Matrix, hardcode the PS-clause → module → evidence-artifact
table we defined (data integrity, model integrity, provenance, drift,
governance, ingestion — map each to what we've built or plan to build).
For the Capability Matrix, hardcode this table (values will become real
once behavioral checks exist in Phase 3-4):

| Check | White-box | Gray-box | Black-box |
|---|---|---|---|
| Model Identity (hash check) | yes | yes | yes |
| Weight/activation statistics | yes | partial | no |
| Trigger reconstruction | yes | partial | no |
| Fine-Pruning | yes | no | no |
| Reference-battery comparison | yes | yes | yes (output-only) |
| Merkle activation commitment | yes | partial | no |

Don't build any other dashboard pages yet.

### 8. Wire and test
Write scripts/phase2_demo.py: run all four data-integrity providers plus
the model identity check over the Phase-1 synthetic test dataset/model,
print all Findings, and populate the lineage graph with the results. Write
tests covering each provider on obvious synthetic cases (inject a duplicate
image, a flipped label, an out-of-bounds box, a substituted model file) and
confirm each is caught.
```

---

## Phase 3 — Behavioral Integrity, Drift Module, Activation-Based Detectors, Tiered Computation

```
Continuing PRAMAAN. Phases 0-2 done. Now build model behavioral integrity,
distribution-shift detection, and the activation-based data-integrity
detectors — plus the tiered computation ordering that governs how expensive
these get to run.

### 1. modules/model_integrity/behavioral.py
EvidenceProviders for Model BEHAVIORAL Integrity — explicitly separate
concept from Identity (Phase 2). Implement:
- Reference-battery comparison: run a fixed calibration set through the
  supplied model, compare output distribution to the ModelReferenceManifest
  baseline. This is DIRECT comparison evidence (higher confidence).
- Layer-wise weight/activation statistics: compare weight norms, sparsity,
  and activation statistics against the reference baseline, flag outliers.
  This is CANDIDATE evidence — tag confidence lower, note in the Finding's
  evidence text that outlier statistics alone don't confirm tampering.
Each Finding here must set access_assumptions correctly (reference-battery
works even black-box/output-only; weight/activation stats need white-box).

### 2. modules/model_integrity/counterfactual.py
Build Counterfactual Validation as a REUSABLE utility function (not
buried inside one detector) — `test_counterfactual(model, sample, mask_fn)`
that removes/masks a suspected component (a region of an image, a specific
neuron/channel) and reports whether the suspicious behavior disappears.
Other modules (Phase 4's Fine-Pruning and STRIP) will call this shared
utility rather than reimplementing the pattern.

### 3. modules/data_integrity/activation_based.py
Two more EvidenceProviders for training-data integrity, both tagged
Modality.ACTIVATION:
- Spectral Signatures (Tran et al. 2018): covariance-outlier detection on
  penultimate-layer activations to flag likely-poisoned samples.
- Activation Clustering (Chen et al. 2018): k-means on per-class
  activations, flag samples forming a separable secondary cluster.
Both are CANDIDATE evidence for poisoning — say so explicitly in the
Finding's evidence text, don't overstate certainty.

### 4. modules/data_integrity/strip.py
STRIP detector (Modality.BEHAVIORAL): overlay each test input with several
random other images, check if the model's prediction stays unnaturally
stable — that stability under perturbation is the backdoor signature. Use
the counterfactual.py utility from step 2 where it fits naturally.

### 5. modules/drift/
Build the Distribution-Shift & Anomaly Assessment module:
- `mmd.py`: MMD / KL-divergence between reference and incoming embedding
  distributions.
- `energy_ood.py`: Energy-based OOD scoring (Liu et al. 2020) from model
  logits — more calibrated than raw softmax confidence.
- `cause_breakdown.py`: decompose a detected shift into likely CAUSE
  categories — illumination/color-histogram stats, blur/noise stats
  (sensor), and note explicitly this maps to terrain/season/sensor/
  illumination causes named in the problem statement.
- `drift_vs_manipulation.py`: THIS IS IMPORTANT — every shift Finding
  produced by this module must NOT default to "suspicious." It must
  populate BOTH `evidence` (reasons this looks like an attack) AND
  `counter_evidence` (reasons this looks like ordinary operational drift —
  e.g., "cause-breakdown attributes 80% of shift to illumination change,
  consistent with time-of-day variation, not injected content"). A drift
  finding with no counter_evidence populated should be treated as
  incomplete — add a lint/test asserting this.

### 6. core/tiered_computation.py — Assurance Budget
Build the tiered-triggering rule: define a cheap-tier (hash comparison,
basic statistics, reference-battery) that ALWAYS runs first, and an
expensive-tier (trigger reconstruction, fine-pruning, Merkle/zkML —
Phase 4 stuff) that only runs if cheap-tier findings cross a risk
threshold you define (e.g., any cheap-tier finding with severity > 0.4).
Wire this as an orchestrator function `run_assessment(asset)` that calls
providers in the right order and short-circuits expensive ones when not
warranted. Log which tier each check ran at and why (for the Detector
Runtime & Resource Cost evaluation later) — record wall-clock time per
provider call.

### 7. Wire and test
scripts/phase3_demo.py: run the full provider set (cheap + expensive-if-
triggered) over test assets including a deliberately shifted-distribution
batch (simulate illumination change) and confirm the drift finding carries
both evidence and counter_evidence. Tests: confirm tiered computation
skips expensive checks when cheap-tier is clean, and runs them when it
isn't.
```

---

## Phase 4 — Trigger Reconstruction, Fine-Pruning, Evidence Convergence, Provenance Computation-Consistency, Unclassified Anomalies

```
Continuing PRAMAAN. Phases 0-3 done. This phase adds the most
research-adjacent detectors, the Correlation Engine, and closes the
computation-consistency gap left open in Phase 1.

### 1. modules/model_integrity/trigger_reconstruction.py
Neural Cleanse-style trigger reconstruction: for each class, optimize a
minimal patch/perturbation that flips predictions to that class; compute
the anomaly index (median absolute deviation of reconstructed-trigger L1
norms across classes) as the original paper does. CRITICAL: the Finding
this produces must explicitly state "candidate evidence, not proof — known
false positives on naturally small decision boundaries per class." Do not
let the Finding's evidence text imply certainty.

### 2. modules/model_integrity/fine_pruning.py
Fine-Pruning verification: prune low-activation neurons on clean data,
re-run the reference battery, check if previously-flagged suspicious
behavior changes. Use the counterfactual.py utility from Phase 3. The
Finding must say "supporting evidence for the backdoor hypothesis, not
confirmation — pruned neurons can also be legitimate rare-feature
detectors."

### 3. provenance/merkle.py + provenance/spot_reexecution.py
Close the computation-correctness gap from Phase 1:
- merkle.py: build a Merkle tree over a model's intermediate-layer
  activations during inference; store only the Merkle root in the
  InferenceRecord (not the full activations). Support revealing a few
  activation values with their Merkle proof on request.
- spot_reexecution.py: periodically (configurable sample rate) pick a
  random past InferenceRecord, re-run the actual model on the stored input,
  and compare resulting activations/output against what was recorded and
  against the Merkle root.
Update provenance/chain.py's `verify_computation_consistency()` to actually
call these now, and make sure its docstring/Finding evidence text says
"honest, partial assurance — proves the log wasn't altered post-hoc and
spot-checks match, not a full cryptographic guarantee of computation (that
would require zkML, out of scope)."

### 4. core/correlation.py — Evidence Convergence
This is the Correlation Engine. Implement:
- Group Findings by asset_id, then by Modality.
- `converge(findings) -> Finding`: when 2+ findings from DIFFERENT
  modalities agree on the same asset, combine them into one composite
  Finding with boosted confidence — cite which detectors and which
  modalities converged in the evidence text. When findings agree but come
  from the SAME modality or from detectors that are known to share an
  underlying signal (document this as a naive-correlation limitation, see
  below), do NOT boost confidence the same way.
- IMPORTANT — do not claim statistical independence anywhere in code
  comments or Finding text. Findings/detectors are described as
  "complementary" or "modality-diverse" signals, never "independent."
- Add a `known_limitations()` method/constant that documents: "this
  convergence logic does not yet correct for detector signal correlation —
  treated as a known, stated limitation, not silently ignored."

### 5. modules/drift/unclassified.py
Unknown/Unclassified Anomaly Detection: after running all drift and data-
integrity checks, if something scores as high-confidence-anomalous but
doesn't match any of this project's defined finding_types, emit a Finding
with finding_type="unclassified_anomaly" rather than force-fitting it into
an existing category. This feeds the Coverage Statement in a later phase.

### 6. Wire and test
scripts/phase4_demo.py: run trigger reconstruction + fine-pruning on a
model you've deliberately backdoored for testing (write a small script to
inject a simple backdoor into a toy model for this purpose), show both
producing appropriately-hedged Findings, then run them through
correlation.py and show the composite finding. Also demonstrate Merkle +
spot re-execution catching a tampered activation record. Tests for each
new component, plus a test asserting no Finding or docstring in the
codebase contains the word "independent" applied to detectors/evidence
(grep-based test is fine).
```

---

## Phase 5 — Contributor Risk, Risk Decision Matrix, Blast-Radius, Evaluation Harness

```
Continuing PRAMAAN. Phases 0-4 done (all detectors + correlation engine
exist). Now build the risk-aggregation and decision layer, plus the full
evaluation harness that measures whether any of this actually works.

### 1. modules/data_integrity/contributor_risk.py
Contributor Risk Aggregation — explicitly TEMPORAL, across multiple
batches, not a single flat score:
- Aggregate sample-level Findings into batch-level patterns, then
  batch-level patterns into a per-contributor risk score.
- Factor in: severity, prevalence (how many samples affected), evidence
  convergence (how many independent modalities agree), batch concentration
  (is risk spread thin or concentrated in one batch), AND temporal
  change-point.
- Temporal Drift-Point Analysis: track each contributor's per-batch
  anomaly rate as a time series (ordered by batch_id/timestamp from the
  Dataset Manifest), implement a simple CUSUM or rolling-window changepoint
  detector, and report WHEN a contributor's behavior shifted, not just
  their current aggregate rate. Store this as (contributor_id,
  change_point_batch, before_rate, after_rate) so the dashboard can plot a
  sparkline later.

### 2. core/decision.py — Risk Decision Matrix
- Implement ACCEPT/REVIEW/QUARANTINE derivation from a severity × confidence
  matrix (define explicit thresholds, e.g. a small lookup table/function —
  don't just average severity and confidence into a single score).
- Quarantine Scope Decision: every REVIEW/QUARANTINE verdict must specify
  its scope by consulting core/lineage.py — sample, batch, contributor,
  model, or specific inference records — not an undifferentiated verdict.
- Decision Explanation / Counter-Evidence: when rendering a verdict, surface
  both the Finding's `evidence` (supporting) and `counter_evidence` (against)
  fields side by side. If counter_evidence is empty for a QUARANTINE
  verdict, log a warning — a verdict with zero considered counter-evidence
  is a signal the decision logic needs a second look.
- Unified Trust Score: implement this ONLY as a decomposed display value
  (a dict of component scores + one rollup number) — the rollup number must
  never be the sole input to the ACCEPT/REVIEW/QUARANTINE decision above;
  the severity × confidence matrix is.

### 3. core/lineage.py additions — Blast-Radius & Confidence Propagation
Extend the Phase-2 lineage graph:
- `blast_radius(compromised_asset_id) -> dict`: traverse downstream_of()
  and report which models, inference records, datasets, and "consumers"
  (treat downstream inference records grouped by some consumer_id field as
  a stand-in for this) are potentially affected. Return counts and the
  actual list of affected node ids.
- `propagate_confidence(finding, lineage)`: downstream confidence is capped
  by the MINIMUM upstream confidence along the lineage chain — implement
  this as a simple min() traversal, not a full Bayesian model. Apply it
  when a Finding about a model or inference record has upstream data-
  integrity Findings with lower confidence.

### 4. modules/model_integrity/access_matrix.py + coverage.py
- Formalize the Access-Level Capability Matrix from Phase 2's hardcoded
  table into real code: given what access level was actually available for
  a given model, report which checks ran, which were skipped, and why —
  never silently skip.
- Coverage Confidence: compute and report what fraction of the requested
  assurance surface was actually evaluated (e.g., % of samples with
  contributor metadata, % of models checked white-box vs black-box).
- Assurance Debt: for every skipped/degraded check, emit an explicit named
  gap with a recommendation string (e.g., "trigger-reconstruction
  unavailable — obtain white-box/gradient access to enable").

### 5. evaluation/
Build the full evaluation harness:
- `attack_toolkit.py`: functions to generate synthetic poisoned datasets
  (inject configurable-rate label flips, duplicate flooding, OOD samples),
  backdoored models (inject a simple trigger pattern into a toy model,
  configurable trigger and poison rate), substituted models (swap weight
  file), and tampered inference logs (corrupt a record post-hoc) — all with
  DOCUMENTED GROUND TRUTH (which samples/records are actually attacked).
- `metrics.py`: given ground truth + this project's Findings, compute
  precision/recall/ROC/PR curves PER DETECTOR (not one blended number).
- `ablation.py`: re-run the pipeline with each module disabled one at a
  time, report the precision/recall delta.
- `adaptive_attacker.py`: optimize a trigger specifically to evade ONE
  named detector (pick trigger_reconstruction.py as the target), report
  the resulting (likely degraded) detection rate honestly.
- `false_positive_cost.py`: run the full pipeline on CLEAN, legitimate
  variation (natural drift, legitimate near-duplicates) and report the
  false-positive/quarantine rate — flag if it's operationally high.
- `runtime_cost.py`: aggregate the per-provider timing logged by Phase 3's
  tiered_computation.py into a runtime/memory report per detector.
- `reproducibility.py`: pin random seeds and detector versions, rerun the
  full pipeline once on the same input, diff the output Findings, confirm
  determinism (this closes the loop: clean baseline → synthetic attack →
  assurance run → measured precision/recall/false-positive rate →
  reproducible result).
- `calibration.py`: Confidence Calibration — using the same ground truth as
  metrics.py, compute a reliability diagram / Brier score comparing stated
  confidence values to actual correctness rates. Store the calibration
  mapping and apply it so reported confidence is CALIBRATED, not a raw
  score — add an explicit flag/field on Findings indicating whether
  calibration has been applied.

### 6. Wire and test
scripts/phase5_demo.py: run the attack_toolkit to generate a full synthetic
attack scenario (poisoned batch + backdoored model + tampered log +
substituted model), run the complete pipeline end to end, print the Risk
Decision Matrix verdicts with scope and counter-evidence, run blast-radius
on the compromised model, and print the evaluation metrics (precision/
recall, false-positive cost, runtime cost, calibration report). Tests
covering contributor temporal change-point detection on a synthetic
multi-batch scenario, and a reproducibility test that fails loudly if two
runs on the same input produce different Findings.
```

---

## Phase 6 — Assurance Passport, Coverage Statement, Dashboard, Robustness, Demo Prep

```
Continuing PRAMAAN. Phases 0-5 done — the full detection, correlation,
decision, and evaluation pipeline exists. This final phase produces the
end-user-facing artifact and dashboard, hardens the system for a live
demo, and ships the deliverables.

### 1. core/passport.py — Assurance Passport
This is the FINAL end-to-end artifact of the whole pipeline — make that
explicit in the code/docstring. Build `generate_passport(asset_id,
lineage, findings) -> Passport` that assembles, for a given asset, a
signed (Ed25519, reuse provenance/keys.py), human-readable document
containing EXACTLY: finding, human-readable reason, evidence, confidence,
severity, affected asset, disposition (accept/review/quarantine + scope),
limitations, and coverage statement (see #2 below). Support export to both
JSON (for machine use) and a readable Markdown/HTML render (for a human to
actually read).

### 2. core/coverage_statement.py
Assemble the final Coverage Statement artifact, versioned, combining: which
attack classes are supported (list them explicitly: label-flip, near-
duplicate flooding, OOD insertion, model substitution, candidate backdoors,
inference tampering & replay), access assumptions used, black-box fallback
behavior taken, and known/unsupported limitations (pull directly from
core/correlation.py's known_limitations(), evaluation's ablation/adaptive-
attacker results, and Assurance Debt from Phase 5). Where possible, map
each supported class to a recognized external taxonomy reference (a simple
string label is fine, e.g. "cf. MITRE ATLAS: ML Supply Chain Compromise").

### 3. core/staleness.py
Assurance Expiration/Staleness: given a previously-issued Passport and the
CURRENT state of the dataset/model/pipeline manifests, re-hash and compare.
If anything no longer matches, mark the Passport STALE/INVALIDATED — this
should be a cheap, near-instant check reusing the manifest `.verify()`
methods from Phase 1. Wire this to run automatically whenever a Passport is
displayed or re-fetched.

### 4. dashboard/ — full build-out
Build out the Streamlit dashboard (or FastAPI+React if you decided that
route earlier — stay consistent with whatever Phase 2 started) with ALL of
these panels, each backed by real data from the pipeline, not mocked:
1. Contributor risk heatmap with the Phase-5 temporal sparkline and
   change-point marker
2. Model integrity radar (Identity + Behavioral checks + confidence)
3. Live provenance chain visualizer — clickable blocks showing hash/
   signature/replay-state, red-highlighted on any of the four provenance
   properties failing (wire this to provenance/chain.py's Verifier)
4. Drift timeline with cause-category breakdown and the drift-vs-
   manipulation evidence/counter-evidence split visible
5. Risk Decision Matrix (severity × confidence grid) as the PRIMARY
   decision display, with quarantine scope and counter-evidence shown per
   verdict
6. Unified Trust Score — decomposed view only, labeled clearly as a triage
   aid, never presented as the decision itself
7. Access & Confidence / Capability Matrix, with Coverage Confidence and
   Assurance Debt shown together
8. Evidence Graph visualization (networkx + a rendering library of your
   choice) with Blast-Radius highlighting when an asset is selected
9. Audit log viewer with visible tamper-evidence (show a chain-break if you
   feed it a tampered record)
10. Operational-impact panel: given a quarantine decision, show what % of
    data/models/inference records would be affected
11. Assurance Passport preview/export (JSON + readable render), with the
    staleness indicator from #3 wired in live
12. Self-Integrity status indicator (from Phase 1's core/self_integrity.py)
    shown prominently — if degraded, the whole dashboard should visibly
    flag it
13. Incident Timeline: chronological view combining Evidence Graph
    correlations and Temporal Drift-Point findings across contributor →
    dataset → model → inference — this is a presentation-layer view over
    data you already have, no new detection logic needed
14. Confidence calibration reliability view (reads from evaluation/
    calibration.py's output — show this in an "evaluation mode" toggle
    since it needs ground truth, unlike the other panels)

### 5. Robustness & Demo Safety
- Pre-warm all models/detectors at app startup (no cold-start hang on first
  dashboard interaction).
- Hard timeouts and size/batch caps on every inference/detector call, with
  a graceful fallback message on timeout, not a crash.
- Wrap every module call in try/except; on failure, report degraded status
  through the Access-Level Capability Matrix display, never a silent skip
  or an unhandled dashboard error.
- If using FastAPI, switch from the dev server to gunicorn/uvicorn workers
  for concurrent-access resilience; if Streamlit, document the single-
  session limitation honestly.
- Pin all dependency versions in requirements.txt (freeze exact versions).
- Add a one-click "reset demo state" action in the dashboard that clears
  the audit log / signature store / lineage graph back to a known clean
  state.
- Confirm nothing in the codebase makes an external network call at
  runtime — grep for `requests.`, `urllib`, CDN script tags in any HTML —
  this must work with network access fully disabled.
- Make sure core/self_integrity.py's startup check runs FIRST, before
  anything else initializes.

### 6. Final deliverables
- Write a top-level README.md covering: the Evidence-Carrying AI thesis,
  architecture diagram (ASCII is fine), how to run the demo end-to-end
  (`scripts/full_demo.py` — write this, chaining everything from Phases
  1-5's demo scripts into one script), and the Requirement Traceability
  Matrix as a markdown table.
- Confirm the Coverage Statement, evaluation results (precision/recall,
  ROC/PR, ablation, adaptive-attacker, false-positive cost, runtime cost,
  reproducibility, calibration), and at least one full Assurance Passport
  example are all saved as artifacts in an `artifacts/` directory, since
  these are required submission deliverables.
- Write scripts/record_demo.md with a short, rehearsed, SCRIPTED (not
  live-improvised) walkthrough: inject a known backdoor and a known
  tampered record ahead of time, then narrate discovering them live —
  attack → evidence → convergence → severity/confidence → verdict, ending
  on the Assurance Passport for that asset.

Do not add any features beyond what's listed above and in the earlier
phases — the feature set is frozen. If you notice something that seems
missing, flag it to me in your response rather than building it.
```

---

## After Phase 6

Once all six phases are done and verified, you have the complete system
matching the master plan: the Evidence-Carrying AI thesis realized in code,
the Attack-Agnostic Evidence Architecture, End-to-End Lineage, all detection
modules (data integrity, model identity + behavioral, provenance with all
four properties, drift with negative evidence), the Correlation Engine, the
Risk Decision Matrix with Blast-Radius and Confidence Propagation, the full
evaluation harness, and the Assurance Passport as the final artifact — with
Self-Integrity checking and Assurance Staleness running throughout.

If you want to extend further afterward, the master plan's §14 lists what
was deliberately scoped OUT for this build (cross-run differential
assurance, full detector-independence correction, multi-detector adversarial
testing, human-in-the-loop feedback, a verification-only mode, and
assurance federation) — those are documented next steps, not gaps.
