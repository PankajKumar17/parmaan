# PRAMAAN: Evidence-Carrying AI Assurance System

PRAMAAN implements the "Evidence-Carrying AI" paradigm where every dataset, model, and inference output carries its own evidence, provenance, confidence, and limitations. Nothing is trusted by default - all claims about AI system integrity must be backed by verifiable evidence that travels with the artifact.

## Architecture Overview
```
Evidence Provider → Finding → Evidence → Correlation → Decision → Passport
```

```
┌─────────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Data Integr   │    │ Model        │    │  Provenance  │    │     Drift    │
│   (duplicates,  │    │ Integrity    │    │  (hash chai  │    │  (MMD, ener  │
│   mislabeling,  │    │ (identity,   │    │  + signature)│    │  gy OOD, etc)│
│   OOD, annot.)  │    │  behavior)   │    │              │    │              │
└─────────┬───────┘    └───────┬──────┘    └───────┬──────┘    └───────┬──────┘
          │                    │                 │                    │
          ▼                    ▼                 ▼                    ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                     Finding Standardization                       │
    │  (asset_id, type, severity, confidence, evidence list, modality,  │
    │   provenance, recommended_action, quarantine_scope, assumptions,  │
    │   counter_evidence)                                               │
    └───────────────────────────────────────────────────────────────────┘
                                                      │
                                                      ▼
                                            ┌──────────────────┐
                                            │  Correlation     │
                                            │  Engine          │
                                            │  (cross-modality │
                                            │   agreement ↑↑)  │
                                            └─────────┬────────┘
                                                      │
                                                      ▼
                                            ┌──────────────────┐
                                            │  Risk Decision   │
                                            │  Matrix          │
                                            │  (severity×conf) │
                                            └─────────┬────────┘
                                                      │
                                                      ▼
                                            ┌──────────────────┐
                                            │  Assurance       │
                                            │  Passport        │
                                            │  (signed,       │
                                            │   human-readable)│
                                            └──────────────────┘
```

## Folder Structure
```
pramaan-project/
├── backend/                     # FastAPI Service (Python 3.11)
│   ├── app/
│   │   ├── api/                 # REST endpoints (auth, assets, passports, assessment)
│   │   ├── core/                # evidence.py, lineage.py, correlation.py, decision.py,
│   │   │                        # passport.py, tiered_computation.py, self_integrity.py,
│   │   │                        # config.py, security.py
│   │   ├── db/                  # SQLAlchemy models and session management
│   │   ├── evaluation/          # attack toolkit, metrics, ablation, etc.
│   │   ├── ingestion/           # COCO/YOLO dataset loaders
│   │   ├── manifests/           # dataset, model, pipeline manifests
│   │   ├── modules/             # detection modules (data_integrity, model_integrity, drift)
│   │   │   ├── data_integrity/
│   │   │   │   ├── duplicates.py
│   │   │   │   ├── mislabeling.py
│   │   │   │   ├── ood.py
│   │   │   │   ├── annotation_integrity.py
│   │   │   │   └── strip.py
│   │   │   ├── model_integrity/
│   │   │   │   ├── identity.py
│   │   │   │   ├── behavioral.py
│   │   │   │   ├── counterfactual.py
│   │   │   │   ├── fine_pruning.py
│   │   │   │   └── trigger_reconstruction.py
│   │   │   └── drift/
│   │   │       ├── mmd.py
│   │   │       ├── energy_ood.py
│   │   │       ├── cause_breakdown.py
│   │   │       ├── drift_vs_manipulation.py
│   │   │       └── unclassified.py
│   │   └── provenance/          # canonical.py, chain.py, keys.py, merkle.py, spot_reexecution.py
│   ├── artifacts/               # Generated passports, coverage statements, evaluation results
│   ├── keys/                    # Ed25519 keypairs (gitignored)
│   ├── scripts/
│   │   ├── synthetic_fixtures.py   # deterministic dataset/model builders
│   │   ├── full_demo.py            # end-to-end demo (offline)
│   │   ├── record_demo.md          # scripted walkthrough
│   │   ├── record_checksums.py     # create integrity baseline
│   │   └── create_user.py          # create first admin user
│   ├── requirements.txt            # pinned dependencies
│   └── render.yaml                 # deployment configuration (Render)
├── frontend/                     # React (Vite) Dashboard
│   ├── src/
│   │   ├── components/             # Radar charts, lineage graphs, heatmaps, matrices
│   │   ├── hooks/                  # API data fetching hooks
│   │   ├── pages/
│   │   │   ├── Dashboard/          # Unified Trust Score, Heatmaps, Matrix, etc.
│   │   │   ├── LineageView/        # NetworkX-style Evidence Graph + Blast-Radius
│   │   │   └── Passport/           # Assurance Passport render & export
│   │   ├── services/               # Typed API client (axios)
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── styles.css
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts              # proxies /api → http://localhost:8000
│   └── vercel.json                 # Vercel deployment
└── README.md
```

## How to Run the Demo

### Option 1: Offline Full Demo (no server)
```bash
# Clone the repository and navigate to the backend directory
cd pramaan-project/backend

# Install dependencies (requires internet)
pip install -r requirements.txt

# Record the integrity baseline (run after any change to source code)
python -B scripts/record_checksums.py --record --force

# Run the full end-to-end assessment on synthetic data
python -B scripts/full_demo.py

# Artifacts will be saved to backend/artifacts/
# Review the generated passport (JSON and Markdown), coverage statement, etc.
```

### Option 2: Live Server + Frontend
```bash
# 1. Backend
cd pramaan-project/backend
pip install -r requirements.txt
python -B scripts/record_checksums.py --record --force  # record baseline
python -B scripts/create_user.py --email analyst@example.com  # follow prompts
uvicorn app.main:app --port 8000  # starts the API server

# 2. Frontend (in another terminal)
cd pramaan-project/frontend
npm install  # requires internet
npm run dev  # starts Vite dev server at http://localhost:5173

# 3. Use the dashboard:
#    - Navigate to http://localhost:5173
#    - Login with the credentials you just created
#    - Use the Passport page to assess an asset (you can paste a synthetic payload)
#    - Explore the dashboard panels (heatmap, radar, matrix, lineage, etc.)
```

### Option 3: Run the Test Suite
```bash
cd pramaan-project/backend
python -m pytest tests -v  # or python -B -m unittest discover -s tests -v
```

## Requirement Traceability Matrix

| PS-Clause (from spec) | Module/File | Evidence Artifact |
|-----------------------|-------------|-------------------|
| Data Integrity (duplicates, mislabeling, OOD, annotation integrity) | backend/app/modules/data_integrity/duplicates.py, mislabeling.py, ood.py, annotation_integrity.py | backend/artifacts/assessment_result.json (findings) |
| Model Integrity (identity) | backend/app/modules/model_integrity/identity.py | backend/artifacts/assessment_result.json |
| Model Integrity (behavioral) | backend/app/modules/model_integrity/behavioral.py, counterfactual.py, fine_pruning.py, trigger_reconstruction.py | backend/artifacts/assessment_result.json |
| Provenance (4 properties: integrity, authenticity, freshness, computation-correctness) | backend/app/provenance/chain.py, keys.py, canonical.py, merkle.py, spot_reexecution.py | backend/artifacts/lineage.json, passport_example.json (signature) |
| Drift (distribution shift with evidence/counter-evidence) | backend/app/modules/drift/mmd.py, energy_ood.py, cause_breakdown.py, drift_vs_manipulation.py | backend/artifacts/assessment_result.json |
| Tiered Computation (cheap/expensive ordering) | backend/app/core/tiered_computation.py | backend/artifacts/assessment_result.json (tier_logs) |
| Evidence Convergence (Correlation Engine) | backend/app/core/correlation.py | backend/artifacts/assessment_result.json (converged findings) |
| Risk Decision Matrix (scope from lineage) | backend/app/core/decision.py, backend/app/core/lineage.py | backend/artifacts/assessment_result.json (verdicts with scope) |
| Contributor Risk & Temporal Change-Point | backend/app/modules/data_integrity/contributor_risk.py | (not fully exercised in demo; see code) |
| Lineage Graph & Blast-Radius Analysis | backend/app/core/lineage.py | backend/artifacts/lineage.json, blast_radius.json |
| Evaluation Harness (attack toolkit, metrics, etc.) | backend/app/evaluation/attack_toolkit.py, metrics.py, ablation.py, adaptive_attacker.py, false_positive_cost.py, runtime_cost.py, reproducibility.py, calibration.py | backend/artifacts/ (evaluation_metrics.json, false_positive_cost.json, etc.) |
| Assurance Passport (signed, human-readable) | backend/app/core/passport.py | backend/artifacts/passport_example.json, passport_example.md |
| Coverage Statement (versioned, limitations) | backend/app/core/coverage_statement.py | backend/artifacts/coverage_statement.json |
| Staleness Check (fail-closed) | backend/app/core/staleness.py | backend/artifacts/staleness_report.json |
| Self-Integrity Check (fail-closed on REQUIRE_SELF_INTEGRITY=true) | backend/app/core/self_integrity.py, scripts/record_checksums.py | backend/checksums.json (baseline) |
| Secure Authentication (JWT, PBKDF2, rate limiting) | backend/app/core/security.py, backend/app/api/auth.py | (tested in test_api.py) |
| Persistent Storage (SQLAlchemy, UUID primary keys) | backend/app/db/models.py, backend/app/db/session.py | (tested in test_database.py) |

## Deployment
- Backend: Configured for Render (see backend/render.yaml)
- Frontend: Configured for Vercel (see frontend/vercel.json)

## Notes
- The system is designed to work offline; no external network calls are made at runtime.
- All dependencies are pinned in requirements.txt for reproducibility.
- The Ed25519 keypair is generated once and stored in backend/keys/ (gitignored).
- The integrity baseline must be explicitly recorded via `scripts/record_checksums.py --record` after any change to source code, configuration, or dependencies.