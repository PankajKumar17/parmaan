# PRAMAAN: React (Vite) + FastAPI Implementation Plan

This plan adapts the PRAMAAN Evidence-Carrying AI architecture (from `spec.md`) into a robust React (Vite) + FastAPI full-stack application, translating the core ML pipeline into backend services and the dashboard into a frontend SPA.

## 1. Folder Structure

```text
pramaan-project/
├── frontend/                     # React (Vite) Dashboard
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── components/           # Reusable UI (Radar charts, Lineage graphs, Heatmaps)
│   │   ├── hooks/                # Data fetching hooks (e.g., SWR or React Query)
│   │   ├── pages/
│   │   │   ├── Dashboard/        # Unified Trust Score, Heatmaps, Matrix
│   │   │   ├── LineageView/      # NetworkX-style Evidence Graph
│   │   │   └── Passport/         # Assurance Passport render & export
│   │   ├── services/             # Axios API calls
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   ├── vercel.json               # Vercel configuration
│   └── vite.config.ts
├── backend/                      # FastAPI Service (Python 3.11)
│   ├── app/
│   │   ├── api/                  # FastAPI routers (endpoints)
│   │   ├── core/                 # evidence.py, correlation.py, decision.py, lineage.py, passport.py, staleness.py, self_integrity.py, tiered_computation.py, coverage_statement.py
│   │   ├── db/                   # Database schemas and sessions
│   │   ├── evaluation/           # attack_toolkit.py, metrics.py, etc.
│   │   ├── ingestion/            # coco_yolo.py, model_loader.py
│   │   ├── manifests/            # dataset_manifest.py, model_manifest.py, pipeline_manifest.py
│   │   ├── modules/              
│   │   │   ├── data_integrity/   # duplicates.py, mislabeling.py, ood.py, etc.
│   │   │   ├── model_integrity/  # identity.py, behavioral.py, trigger_reconstruction.py, etc.
│   │   │   └── drift/            # mmd.py, energy_ood.py, drift_vs_manipulation.py, etc.
│   │   ├── provenance/           # canonical.py, chain.py, keys.py, merkle.py
│   │   └── main.py               # FastAPI entrypoint (uvicorn)
│   ├── artifacts/                # Generated Passports and Coverage Statements
│   ├── keys/                     # Ed25519 keypairs (gitignored)
│   ├── requirements.txt          # Pinned dependencies
│   └── render.yaml               # Render configuration
└── .gitignore
```

## 2. DB Schema (PostgreSQL)

*Note: While PRAMAAN is largely file/hash-based, a relational DB tracks state over time for the dashboard.*

**1. Users (Auth)**
- `id`: UUID (PK)
- `email`: String (Unique)
- `hashed_password`: String
- `is_active`: Boolean

**2. Assets (Datasets, Models, Contributors)**
- `id`: String (PK) (e.g., hash or contributor ID)
- `asset_type`: Enum (DATASET, MODEL, CONTRIBUTOR)
- `manifest_hash`: String (For staleness checks)
- `created_at`: DateTime

**3. InferenceRecords (Provenance Chain)**
- `id`: UUID (PK)
- `input_hash`: String
- `model_digest`: String
- `config_hash`: String
- `output_hash`: String
- `sequence_number`: Integer
- `nonce`: String (Unique constraint)
- `timestamp`: DateTime
- `previous_record_hash`: String (For hash-chaining)
- `merkle_root`: String (Nullable)

**4. Findings**
- `id`: UUID (PK)
- `asset_id`: String (FK to Assets.id)
- `finding_type`: String
- `severity`: Float (0-1)
- `confidence`: Float (0-1)
- `evidence`: JSON (List of strings)
- `counter_evidence`: JSON
- `modality`: Enum (PIXEL, EMBEDDING, ANNOTATION, ACTIVATION, BEHAVIORAL)
- `recommended_action`: String
- `quarantine_scope`: String

## 3. Auth Flow (OAuth2 with JWT)

1. **Setup**: Ed25519 is used for provenance signatures, but standard HS256 JWTs are used for dashboard auth.
2. **Login**: User submits POST `/api/auth/login` (email/password).
3. **Token**: Backend validates against the `Users` table and issues a short-lived `access_token`.
4. **Access**: React app stores the token and attaches `Authorization: Bearer <token>` to all subsequent requests.
5. **Protection**: All PRAMAAN analysis endpoints require auth to prevent unauthorized pipeline execution.

## 4. API Contracts

### Auth
- `POST /api/auth/login` -> `{ "access_token": "...", "token_type": "bearer" }`

### Dashboard Aggregations
- `GET /api/dashboard/heatmap` -> Returns temporal drift-point analysis for contributors (sparklines).
- `GET /api/dashboard/radar/{model_id}` -> Returns identity and behavioral integrity vectors.
- `GET /api/dashboard/matrix` -> Returns Risk Decision Matrix (severity x confidence) with `quarantine_scope`.
- `GET /api/dashboard/coverage` -> Returns Access-Level Capability Matrix and Assurance Debt.

### Core PRAMAAN Actions
- `POST /api/assess` -> Body: `{ "asset_id": "..." }`. Triggers `tiered_computation.run_assessment()`. Returns assessment ID.
- `GET /api/lineage/{asset_id}` -> Returns NetworkX graph serialization for Evidence Graph visualization and Blast-Radius.
- `GET /api/passport/{asset_id}` -> Returns generated Assurance Passport (JSON format), triggers `staleness.py` check.
- `GET /api/passport/{asset_id}/export` -> Returns HTML/Markdown render of the Passport.

## 5. Environment Variables Needed

**Backend (`backend/.env`)**
- `DATABASE_URL`: PostgreSQL connection string (for findings and provenance history)
- `JWT_SECRET_KEY`: String for auth token signing
- `ED25519_PRIVATE_KEY_PATH`: Path to the offline-generated signature key
- `MODEL_CACHE_DIR`: Directory for downloading/caching ResNet/CLIP models for duplicate detection
- `REQUIRE_SELF_INTEGRITY`: Boolean (If True, failure in `core/self_integrity.py` prevents app startup)

**Frontend (`frontend/.env`)**
- `VITE_API_URL`: Base URL for the FastAPI backend

## 6. Step-by-Step Build Order

1. **Scaffolding & Self-Integrity**: Set up FastAPI and React. Implement `core/self_integrity.py` to run immediately on backend startup.
2. **Core Architecture**: Implement `core/evidence.py` (Finding/Evidence schemas) and base `EvidenceProvider`.
3. **Database & Auth**: Set up PostgreSQL schema and JWT auth flow for dashboard security.
4. **Manifests & Provenance**: Implement manifest generation, canonical serialization, and `InferenceRecord` hash-chaining logic.
5. **Detection Modules (Phase 2 & 3)**: Implement Data Integrity (pHash, MMD, OOD) and Model Integrity (Identity, Behavioral) checks.
6. **Tiered Computation & Correlation**: Implement orchestrator to run cheap checks first, then expensive ones, followed by Evidence Convergence.
7. **Risk & Lineage**: Implement NetworkX lineage graph, Blast-Radius analysis, and Risk Decision Matrix logic.
8. **Frontend Dashboard**: Build React components for Heatmaps, Risk Matrix, Evidence Graph, and Audit Log viewers.
9. **Assurance Passport**: Implement final Passport generation, Coverage Statement export, and staleness checks.
10. **Deployment**: Configure Render (gunicorn/uvicorn workers) and Vercel.

## 7. Deployment Configurations

### Frontend (`frontend/vercel.json`)
```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

### Backend (`backend/render.yaml`)
```yaml
services:
  - type: web
    name: pramaan-backend
    env: python
    buildCommand: "pip install -r requirements.txt"
    startCommand: "gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120"
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: pramaan-db
          property: connectionString
      - key: JWT_SECRET_KEY
        generateValue: true

databases:
  - name: pramaan-db
    databaseName: pramaandb
    user: pramaanuser
    plan: free
```
