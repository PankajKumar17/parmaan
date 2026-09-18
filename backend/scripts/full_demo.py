#!/usr/bin/env python3
"""
PRAMAAN full demo script.
Runs an end-to-end assessment on synthetic data and saves artifacts.
"""
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
import sys

# Ensure the backend is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
from PIL import Image

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.core.lineage import IntegrityLineage
from app.core.correlation import CorrelationEngine
from app.core.decision import RiskDecisionMatrix
from app.core.tiered_computation import run_assessment
from app.core.passport import generate_passport
from app.core.coverage_statement import build_coverage_statement
from app.core.staleness import check_staleness, StalenessReport
from app.provenance.chain import ProvenanceChain, InferenceRecord
from app.provenance.keys import get_or_generate_keypair
from app.core.self_integrity import check_self_integrity, IntegrityReport
from app.db.models import Base, Asset, FindingRow, AssessmentRow
from app.db.session import create_database
from app.core.config import Settings
from app.core.security import hash_password, issue_token
from app.modules.data_integrity.duplicates import DuplicateDetector
from app.modules.data_integrity.mislabeling import MislabelingDetector
from app.modules.data_integrity.ood import OODDetector
from app.modules.data_integrity.annotation_integrity import AnnotationIntegrityDetector
from app.modules.model_integrity.identity import ModelIdentityDetector
from app.modules.model_integrity.behavioral import ReferenceBatteryProvider, WeightStatsProvider
from app.modules.model_integrity.counterfactual import test_counterfactual
from app.modules.data_integrity.activation_based import SpectralSignatureProvider, ActivationClusteringProvider
from app.modules.data_integrity.strip import STRIPDetector
from app.modules.drift.mmd import mmd_rbf
from app.modules.drift.energy_ood import energy_score
from app.modules.drift.cause_breakdown import classify_shift
from app.modules.drift.drift_vs_manipulation import DriftVsManipulationProvider
from app.modules.drift.unclassified import UnclassifiedAnomalyProvider
from app.modules.data_integrity.contributor_risk import ContributorRiskAggregator
from scripts.synthetic_fixtures import build_demo_dataset, build_demo_model, build_manifests

def main():
    print("=== PRAMAAN Full Demo ===")
    # Step 0: Self-integrity check (should pass if we haven't tampered)
    integrity_report = check_self_integrity()
    print(f"Self-integrity status: {integrity_report.status}")
    if integrity_report.degraded:
        print("WARNING: Self-integrity check failed. Artifacts may be affected.")
        for error in integrity_report.errors:
            print(f"  - {error}")

    # Step 1: Create temporary directories for synthetic data
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        dataset_dir = tmpdir / "dataset"
        model_dir = tmpdir / "model"
        artifacts_dir = Path(__file__).resolve().parents[1] / "artifacts"
        artifacts_dir.mkdir(exist_ok=True)

        print(f"\n[1] Building synthetic dataset and model in {tmpdir}...")
        # Build synthetic dataset and model
        gt_dataset = build_demo_dataset(dataset_dir)
        gt_model = build_demo_model(model_dir)
        manifests = build_manifests(dataset_dir, model_dir)
        dataset_manifest = manifests["dataset_manifest"]
        model_manifest = manifests["model_manifest"]
        pipeline_manifest = manifests["pipeline_manifest"]

        print(f"  Dataset hash: {dataset_manifest.compute_hash()}")
        print(f"  Model hash: {model_manifest.compute_hash()}")

        # Step 2: Provenance chain (Phase 1 style)
        print("\n[2] Building provenance chain...")
        chain = ProvenanceChain()
        # We'll create three records: two normal, one we will tamper with
        # For simplicity, we'll use dummy data for the records.
        # In a real scenario, these would come from actual inferences.
        # We'll just use the dataset and model hashes as inputs.
        input_hash = dataset_manifest.compute_hash()
        model_digest = model_manifest.compute_hash()
        config_hash = pipeline_manifest.compute_hash()
        output_hash1 = hashlib.sha256(b"output1").hexdigest()
        output_hash2 = hashlib.sha256(b"output2").hexdigest()
        output_hash3 = hashlib.sha256(b"output3").hexdigest()

        record1 = chain.append(input_hash, model_digest, config_hash, output_hash1)
        record2 = chain.append(input_hash, model_digest, config_hash, output_hash2)
        record3 = chain.append(input_hash, model_digest, config_hash, output_hash3)

        # Verify the chain
        verifier = chain.signer.public_key  # Actually, we need a Verifier instance
        from app.provenance.chain import Verifier
        verifier = Verifier(chain.signer.public_key)
        report = chain.verify(verifier)
        print(f"  Initial chain verification: {'PASS' if report['passed'] else 'FAIL'}")
        if not report['passed']:
            print("  Failures:", report)

        # Tamper with the second record by changing its output_hash
        print("  Tampering with record 2 (output_hash)...")
        # We need to modify the record in the chain. Since records are immutable, we'll rebuild the chain with a tampered record.
        # Instead, let's create a new chain and replace the second record.
        chain2 = ProvenanceChain()
        record1_2 = chain2.append(input_hash, model_digest, config_hash, output_hash1)
        # Tampered record: change output_hash
        record2_2 = chain2.append(input_hash, model_digest, config_hash, hashlib.sha256(b"tampered").hexdigest())
        record3_2 = chain2.append(input_hash, model_digest, config_hash, output_hash3)
        report2 = chain2.verify(verifier)
        print(f"  After tampering verification: {'PASS' if report2['passed'] else 'FAIL'}")
        if not report2['passed']:
            print("  Failures:")
            for prop in ['integrity', 'authenticity', 'freshness']:
                for f in report2[prop]:
                    print(f"    Record {f['index']}: {f['property']} - {f['reason']}")

        # Step 3: Run assessment on the dataset/model
        print("\n[3] Running assessment...")
        # We need to build asset payloads for each provider.
        # For simplicity, we'll create a single asset that represents the dataset.
        # In a real scenario, we might have multiple assets (dataset, model, etc.).
        # We'll focus on the dataset asset for this demo.

        # Asset ID: we'll use the dataset manifest hash as the asset ID
        asset_id = dataset_manifest.compute_hash()

        # Build payloads for each provider.
        # We'll create a dictionary mapping provider names to their asset payloads.
        # We'll also keep track of which providers we actually ran (for skipped ones).

        # First, let's instantiate the providers.
        dup_det = DuplicateDetector()
        mis_det = MislabelingDetector()
        ood_det = OODDetector()
        anno_det = AnnotationIntegrityDetector()
        id_det = ModelIdentityDetector()
        providers = {
            dup_det.detector_id: dup_det,
            mis_det.detector_id: mis_det,
            ood_det.detector_id: ood_det,
            anno_det.detector_id: anno_det,
            id_det.detector_id: id_det,
            # Behavioral and activation-based providers need more specific inputs.
            # We'll skip them for now or provide dummy inputs.
            # For the demo, we'll try to provide reasonable inputs.
        }

        # We'll also need to build the actual data for the providers.
        # Let's load the dataset images and annotations.

        # Since we don't have pycocotools installed, we'll parse the JSON ourselves.
        annotations_path = dataset_dir / "annotations" / "instances.json"
        coco_json = json.loads(annotations_path.read_text())
        # Build a mapping from image_id to annotations
        image_to_annotations = {}
        for ann in coco_json['annotations']:
            image_to_annotations.setdefault(ann['image_id'], []).append(ann)

        # Load images
        images = {}
        for img_info in coco_json['images']:
            img_path = dataset_dir / "images" / img_info['file_name']
            images[img_info['id']] = np.array(Image.open(img_path))

        # Now build payloads for each provider.

        # Duplicates: expects {"images": list[(name, PIL.Image)], "config_hash": str}
        # We'll convert our numpy arrays to PIL Images.
        duplicate_images = []
        for img_id, img_array in images.items():
            pil_img = Image.fromarray(img_array)
            duplicate_images.append((f"{img_id:04d}.png", pil_img))
        duplicate_payload = {
            "images": duplicate_images,
            "config_hash": pipeline_manifest.compute_hash()
        }

        # Mislabeling: expects {"samples": list[(name, features(list[float]), label)], "config_hash": str, "num_classes": int}
        # We'll use a simple feature: the mean RGB of the image.
        mislabeling_samples = []
        num_classes = 2  # we have two categories
        for img_id, img_array in images.items():
            # Features: mean RGB normalized to [0,1]
            features = img_array.mean(axis=(0,1)).astype(float) / 255.0
            label = image_to_annotations[img_id][0]['category_id'] - 1  # zero-index
            mislabeling_samples.append((f"{img_id:04d}.png", features.tolist(), label))
        mislabeling_payload = {
            "samples": mislabeling_samples,
            "config_hash": pipeline_manifest.compute_hash(),
            "num_classes": num_classes
        }

        # OOD: expects {"samples": list[(name, features(list[float]), label)], "config_hash": str}
        # We'll use the same features as mislabeling (mean RGB) but we need per-class centroids.
        # We'll just reuse the same samples; the OOD provider will compute centroids.
        ood_samples = []
        for img_id, img_array in images.items():
            features = img_array.mean(axis=(0,1)).astype(float) / 255.0
            label = image_to_annotations[img_id][0]['category_id'] - 1
            ood_samples.append((f"{img_id:04d}.png", features.tolist(), label))
        ood_payload = {
            "samples": ood_samples,
            "config_hash": pipeline_manifest.compute_hash(),
            "num_classes": num_classes
        }

        # Annotation integrity: expects {"annotations": list of dicts {image_id, boxes: list[{x, y, w, h}], width, height}, "config_hash": str}
        # We'll use the COCO annotations.
        annotation_integrity_payload = {
            "annotations": [],
            "config_hash": pipeline_manifest.compute_hash()
        }
        for img_id, img_array in images.items():
            h, w, _ = img_array.shape
            boxes = []
            for ann in image_to_annotations.get(img_id, []):
                bbox = ann['bbox']  # [x, y, width, height]
                boxes.append({"x": bbox[0], "y": bbox[1], "w": bbox[2], "h": bbox[3]})
            annotation_integrity_payload["annotations"].append({
                "image_id": img_id,
                "boxes": boxes,
                "width": w,
                "height": h
            })

        # Identity: expects {"reference_manifest_path": str or ModelReferenceManifest, "supplied_model_path": str, "config_hash": str}
        # We'll pass the model manifest and the model file.
        identity_payload = {
            "reference_manifest_path": model_manifest,  # we can pass the object? The identity_check expects a path or manifest.
            # Looking at identity.py, it expects a supplied_model_path and optionally a reference_manifest_path.
            # We'll pass the model file path and the manifest as a string? Actually, the identity_check in model_manifest.py
            # takes a supplied_model_path and compares it to the reference model stored in the manifest.
            # So we need to set the reference model in the manifest. We already did that when we built the model_manifest.
            # So we just need to pass the supplied_model_path.
            "supplied_model_path": str(model_dir / "model.npz"),
            "config_hash": pipeline_manifest.compute_hash()
        }

        # For the other providers, we'll skip them in this demo to keep it simple, but we should at least try to run them.
        # Let's add the behavioral and activation-based providers with dummy data.
        # We'll create a dummy prediction function and dummy images.

        # For behavioral (ReferenceBatteryProvider and WeightStatsProvider), we need a model that can predict.
        # We'll create a simple logistic model using the weights we saved.
        # We'll need to load the weights and define a predict function.
        try:
            # Load the model
            model_data = np.load(model_dir / "model.npz")
            W = model_data['W']
            b = model_data['b']

            def predict_fn(images: np.ndarray) -> np.ndarray:
                # images: shape (N, H, W, C)
                # Flatten
                flat = images.reshape((images.shape[0], -1))
                logits = flat @ W.T + b  # (N, 2)
                # Return probabilities (softmax)
                exp_logits = np.exp(logits - np.max(logits, axis=1, keepdims=True))
                probs = exp_logits / np.sum(exp_logits, axis=1, keepdims=True)
                return probs

            # We'll also need a activation function for the activation-based providers.
            # We'll assume the penultimate layer is the flattened layer.
            def activation_fn(images: np.ndarray) -> np.ndarray:
                return images.reshape((images.shape[0], -1))  # (N, 3072)

            # Now we can create the behavioral providers.
            # ReferenceBatteryProvider: needs a calibration set and reference outputs.
            # We'll use the first two images as calibration set.
            calibration_images = [images[i] for i in [0, 1]]  # red and green
            calibration_images_np = np.stack(calibration_images)
            # Get reference outputs from the model
            reference_outputs = predict_fn(calibration_images_np)
            reference_battery_payload = {
                "supplied_model_path": str(model_dir / "model.npz"),
                "calibration_images": [(f"{i:04d}.png", images[i]) for i in [0, 1]],
                "reference_outputs": reference_outputs.tolist(),  # we'll store as list
                "config_hash": pipeline_manifest.compute_hash()
            }

            # WeightStatsProvider: needs the same supplied_model_path and config_hash.
            weight_stats_payload = {
                "supplied_model_path": str(model_dir / "model.npz"),
                "config_hash": pipeline_manifest.compute_hash()
            }

            # Activation-based providers: need activations and labels.
            # We'll use all images for activations.
            all_images = np.stack([images[i] for i in sorted(images.keys())])
            activations = activation_fn(all_images)  # (N, 3072)
            labels = [image_to_annotations[i][0]['category_id'] - 1 for i in sorted(images.keys())]
            activation_payload = {
                "activations": {f"{i:04d}.png": activations[i].tolist() for i in sorted(images.keys())},
                "labels": {f"{i:04d}.png": labels[i] for i in sorted(images.keys())},
                "config_hash": pipeline_manifest.compute_hash()
            }

            # STRIP detector: needs predict_fn, images, backgrounds, config_hash, entropy_threshold.
            # We'll use the same images as inputs and use a subset as backgrounds.
            strip_images = [(f"{i:04d}.png", images[i] / 255.0) for i in sorted(images.keys())]
            strip_backgrounds = [images[i] / 255.0 for i in [0, 1, 2]]  # first three as backgrounds
            strip_payload = {
                "predict_fn": predict_fn,
                "images": strip_images,
                "backgrounds": strip_backgrounds,
                "config_hash": pipeline_manifest.compute_hash(),
                "entropy_threshold": 0.5
            }

            # Drift providers: we need reference and current images.
            # We'll use the first half as reference and the second half as current.
            # We'll also need to compute embeddings for the drift_vs_manipulation provider.
            # For simplicity, we'll use the activations as embeddings.
            sorted_ids = sorted(images.keys())
            split = len(sorted_ids) // 2
            ref_ids = sorted_ids[:split]
            curr_ids = sorted_ids[split:]
            ref_images = [(f"{i:04d}.png", images[i]) for i in ref_ids]
            curr_images = [(f"{i:04d}.png", images[i]) for i in curr_ids]
            # Embeddings: we'll use the activations (we'll need to compute them for each image)
            # We'll precompute activations for all images and then slice.
            all_activations = activation_fn(np.stack([images[i] for i in sorted_ids]))
            ref_embeddings = [all_activations[i].tolist() for i, img_id in enumerate(sorted_ids) if img_id in ref_ids]
            curr_embeddings = [all_activations[i].tolist() for i, img_id in enumerate(sorted_ids) if img_id in curr_ids]
            drift_vs_manipulation_payload = {
                "reference_images": ref_images,
                "current_images": curr_images,
                "reference_embeddings": ref_embeddings,
                "current_embeddings": curr_embeddings,
                "config_hash": pipeline_manifest.compute_hash()
            }

            # Unclassified anomaly provider: we'll just pass a list of (name, score) where score is random.
            # We'll skip it for now; it will only emit if score > threshold.

            # Contributor risk: we need findings and batch metadata.
            # We'll skip it for now; we'll run it after we have findings from the other providers.

            # Add these providers to the dict
            providers["reference_battery"] = ReferenceBatteryProvider()
            providers["weight_stats"] = WeightStatsProvider()
            providers["spectral_signature"] = SpectralSignatureProvider()
            providers["activation_clustering"] = ActivationClusteringProvider()
            providers["strip"] = STRIPDetector()
            providers["drift_vs_manipulation"] = DriftVsManipulationProvider()
            providers["unclassified"] = UnclassifiedAnomalyProvider()
            # We'll add the contributor risk provider later after we have findings.

            # Update payloads
            payloads = {
                "duplicates": duplicate_payload,
                "mislabeling": mislabeling_payload,
                "ood": ood_payload,
                "annotation_integrity": annotation_integrity_payload,
                "identity": identity_payload,
                "reference_battery": reference_battery_payload,
                "weight_stats": weight_stats_payload,
                "spectral_signature": activation_payload,  # Note: activation_payload is for both spectral and clustering
                "activation_clustering": activation_payload,
                "strip": strip_payload,
                "drift_vs_manipulation": drift_vs_manipulation_payload,
                "unclassified": {  # dummy payload
                    "anomalies": [(f"{i:04d}.png", np.random.rand()) for i in sorted(images.keys())],
                    "config_hash": pipeline_manifest.compute_hash()
                }
            }

            # Try to add trigger reconstruction and fine pruning
            try:
                from app.modules.model_integrity.trigger_reconstruction import TriggerReconstructionProvider
                from app.modules.model_integrity.fine_pruning import FinePruningProvider
                trigger_provider = TriggerReconstructionProvider()
                fine_provider = FinePruningProvider()
                providers[trigger_provider.detector_id] = trigger_provider
                providers[fine_provider.detector_id] = fine_provider
                # Payloads: we'll use the same as identity? They need the model and config.
                trigger_payload = {
                    "supplied_model_path": str(model_dir / "model.npz"),
                    "config_hash": pipeline_manifest.compute_hash()
                }
                fine_payload = {
                    "supplied_model_path": str(model_dir / "model.npz"),
                    "config_hash": pipeline_manifest.compute_hash()
                }
                payloads[trigger_provider.detector_id] = trigger_payload
                payloads[fine_provider.detector_id] = fine_payload
            except Exception as e:
                print(f"  Warning: Could not initialize trigger reconstruction or fine pruning: {e}")

        except Exception as e:
            print(f"  Warning: Could not initialize behavioral/activation providers: {e}")
            # We'll just run the basic providers.
            payloads = {
                "duplicates": duplicate_payload,
                "mislabeling": mislabeling_payload,
                "ood": ood_payload,
                "annotation_integrity": annotation_integrity_payload,
                "identity": identity_payload
            }

        print("DEBUG: After except block")
        # Now we have providers and payloads.
        # We need to run the assessment using tiered_computation.run_assessment.
        # But note: run_assessment expects a dictionary of provider_name -> asset_payload, and a list of providers.
        # We'll split providers into cheap and expensive.
        # According to spec, cheap tier: hash comparison, basic statistics, reference-battery.
        # Expensive tier: trigger reconstruction, fine-pruning, Merkle/zkML.
        # In our list, we'll consider:
        # Cheap: duplicates, mislabeling, ood, annotation_integrity, identity, reference_battery (reference battery is cheap? Actually, reference battery is considered cheap in the spec? It says: cheap-tier (hash comparison, basic statistics, reference-battery). So reference battery is cheap.
        # Expensive: trigger_reconstruction, fine_pruning, strip (STRIP is considered expensive? In spec, strip is in Phase 3's drift module, not sure. We'll follow the spec: expensive-tier (trigger reconstruction, fine-pruning, Merkle/zkML). So we'll put trigger_reconstruction and fine_pruning in expensive. We'll put strip in cheap? Actually, strip is in Phase 3's data_integrity, and it's a behavioral detector. The spec says expensive-tier includes trigger reconstruction, fine-pruning, Merkle/zkML. So we'll consider strip as cheap for now, but it might be considered expensive. We'll put it in cheap to be safe.
        # We'll also add the drift_vs_manipulation provider? It's in Phase 3's drift module. The spec doesn't mention it in tiered computation. We'll put it in cheap.

# Let's define:
        cheap_provider_names = [
            "duplicates", "mislabeling", "ood", "annotation_integrity", "identity",
            "reference_battery", "weight_stats", "spectral_signature", "activation_clustering",
            "strip", "drift_vs_manipulation"
        ]
        # expensive_provider_names = [
        #     "trigger_reconstruction", "fine_pruning"
        # ]
        expensive_provider_names = []
        print(f"DEBUG: cheap_provider_names = {cheap_provider_names}")
        # We don't have trigger_reconstruction and fine_pruning instantiated yet.
        # We'll add them if we can.
        try:
            from app.modules.model_integrity.trigger_reconstruction import TriggerReconstructionProvider
            from app.modules.model_integrity.fine_pruning import FinePruningProvider
            providers["trigger_reconstruction"] = TriggerReconstructionProvider()
            providers["fine_pruning"] = FinePruningProvider()
        except Exception as e:
            print(f"  Warning: Could not initialize trigger reconstruction or fine pruning: {e}")

        # Now, we need to filter the providers and payloads to only those we have.
        cheap_providers = [providers[name] for name in cheap_provider_names if name in providers]
        cheap_payloads = {name: payloads[name] for name in cheap_provider_names if name in payloads}
        expensive_providers = [providers[name] for name in expensive_provider_names if name in providers]
        expensive_payloads = {name: payloads[name] for name in expensive_provider_names if name in payloads}

        print(f"  Running {len(cheap_providers)} cheap providers and {len(expensive_providers)} expensive providers.")

        # Run the assessment
        start_time = time.time()
        assessment_result = run_assessment(
            assets=payloads,
            providers=cheap_providers,
            expensive_providers=expensive_providers,
            risk_threshold=0.4,
            clock=time.perf_counter
        )
        end_time = time.time()
        print(f"  Assessment completed in {end_time - start_time:.2f} seconds.")
        print(f"  Findings count: {len(assessment_result['findings'])}")
        print(f"  Tier logs: {assessment_result['tier_logs']}")

        # Now we have findings for the asset.
        # Let's collect all findings.
        all_findings = assessment_result['findings']

        # Step 4: Converge findings using correlation engine
        print("\n[4] Converging findings...")
        correlation_engine = CorrelationEngine()
        converged_findings = correlation_engine.converge(all_findings)
        print(f"  Converged to {len(converged_findings)} findings.")

        # Step 5: Risk decision matrix
        print("\n[5] Computing risk decisions...")
        decision_matrix = RiskDecisionMatrix()
        verdicts = decision_matrix.decide(converged_findings)
        print(f"  Verdicts: {[v['verdict'] for v in verdicts]}")

        # Step 6: Contributor risk and temporal change-point
        print("\n[6] Computing contributor risk...")
        # We need to build batch metadata for the contributor risk provider.
        # For simplicity, we'll assume each image is a batch, and the contributor is the same for all.
        # We'll create a dummy contributor ID.
        contributor_id = "demo_contributor"
        # We'll create batch metadata: list of dicts per batch with contributor_id and batch_id.
        # We'll use the image index as batch_id.
        batch_metadata = [
            {"contributor_id": contributor_id, "batch_id": str(i)}
            for i in range(len(images))
        ]
        # We also need the findings per sample. We'll use the converged findings and replicate them per sample? 
        # Actually, the contributor risk provider expects findings list (which are per-sample findings) and batch metadata.
        # We'll use the converged findings as the findings for each sample? That doesn't make sense.
        # Instead, we'll assume that each finding is associated with a specific sample (image) via the asset_id in the finding.
        # In our findings, the asset_id is the dataset hash, not the image hash. So we need to adjust.
        # For simplicity, we'll skip the contributor risk in this demo and just note that it would be computed.
        # We'll create a dummy contributor risk result.
        contributor_risk = {
            "contributor_id": contributor_id,
            "risk_score": 0.5,
            "temporal_change_point": None
        }

        # Step 7: Lineage and blast radius
        print("\n[7] Building lineage and computing blast radius...")
        lineage = IntegrityLineage()
        # We'll add the contributor, dataset, model, and inference records (we have the chain from earlier)
        # We'll use the chain we built earlier (chain2, the tampered one) for the inference records.
        # We'll add the contributor
        lineage.add_contributor(contributor_id)
        # Add the dataset
        lineage.add_dataset(dataset_manifest, contributor_id)
        # Add the model
        lineage.add_model(model_manifest)
        # Add the inference records from the chain (we'll use the untampered chain for simplicity)
        # We'll use the first chain (chain) which had three records.
        for record in chain.records:
            lineage.add_inference_record(record[0], model_manifest.compute_hash(), dataset_manifest.compute_hash())
        # Add the findings as nodes? The add_finding method expects a finding and an asset_id.
        # We'll add each converged finding to the lineage, attaching it to the dataset asset.
        for finding in converged_findings:
            lineage.add_finding(finding, asset_id)

        # Now compute blast radius on the dataset asset (or maybe on the model if we want to see impact)
        # Let's compute blast radius on the dataset asset.
        blast_radius_result = lineage.blast_radius(asset_id)
        print(f"  Blast radius on dataset: {blast_radius_result['total']} nodes affected.")
        print(f"    Models: {len(blast_radius_result['models'])}")
        print(f"    Inference records: {len(blast_radius_result['inference_records'])}")
        print(f"    Datasets: {len(blast_radius_result['datasets'])}")
        print(f"    Consumers: {sum(len(v) for v in blast_radius_result['consumers'].values())}")

        # Step 8: Generate passport
        print("\n[8] Generating passport...")
        passport = generate_passport(
            asset_id=asset_id,
            lineage=lineage,
            findings=converged_findings,
            decision_matrix=decision_matrix
        )
        passport_json = passport.to_json()
        passport_md = passport.render_markdown()
        # Verify the passport signature
        if passport.verify_signature():
            print("  Passport signature: VALID")
        else:
            print("  Passport signature: INVALID")

        # Step 9: Check staleness
        print("\n[9] Checking staleness...")
        # We'll check staleness against the manifests we built.
        # We'll pass the current manifests (which are the same as the ones we used to build the passport, so it should be fresh).
        staleness_report = check_staleness(
            passport,
            dataset_manifest=dataset_manifest,
            model_manifest=model_manifest,
            pipeline_manifest=pipeline_manifest
        )
        print(f"  Staleness: {'STALE' if staleness_report.stale else 'FRESH'}")
        if staleness_report.stale:
            print(f"  Reasons: {staleness_report.reasons}")

        # Step 10: Build coverage statement
        print("\n[10] Building coverage statement...")
        # We'll need assurance debt from the capability matrix.
        # We'll skip the capability matrix for now and just pass an empty list.
        coverage_statement = build_coverage_statement(
            assurance_debt=[],  # we'll skip for now
            ablation_results=None,
            adaptive_attacker_results=None
        )
        print(f"  Coverage statement version: {coverage_statement.get('version', 'unknown')}")

        # Step 11: Save artifacts
        print("\n[11] Saving artifacts to backend/artifacts/...")
        # Save passport JSON and markdown
        (artifacts_dir / "passport_example.json").write_text(json.dumps(passport_json, indent=2))
        (artifacts_dir / "passport_example.md").write_text(passport_md)
        # Save coverage statement
        (artifacts_dir / "coverage_statement.json").write_text(json.dumps(coverage_statement, indent=2))
        # Save staleness report
        (artifacts_dir / "staleness_report.json").write_text(json.dumps(staleness_report.__dict__, indent=2))
        # Save the assessment result (findings, tier logs, etc.)
        assessment_artifact = {
            "asset_id": asset_id,
            "findings": [f.__dict__ for f in all_findings],
            "converged_findings": [f.__dict__ for f in converged_findings],
            "verdicts": verdicts,
            "tier_logs": assessment_result['tier_logs'],
            "timings": assessment_result['timings'],
            "assessment_time": end_time - start_time
        }
        (artifacts_dir / "assessment_result.json").write_text(json.dumps(assessment_artifact, indent=2, default=str))
        # Save the lineage as a JSON representation
        lineage_data = {
            "nodes": [{"id": n, **lineage.graph.nodes[n]} for n in lineage.graph.nodes],
            "edges": [{"source": u, "target": v} for u, v in lineage.graph.edges()]
        }
        (artifacts_dir / "lineage.json").write_text(json.dumps(lineage_data, indent=2))
        # Save the blast radius result
        (artifacts_dir / "blast_radius.json").write_text(json.dumps(blast_radius_result, indent=2))

        print("  Artifacts saved.")

        # Step 12: Print summary
        print("\n=== Demo Summary ===")
        print(f"Asset ID (dataset hash): {asset_id}")
        print(f"Number of raw findings: {len(all_findings)}")
        print(f"Number of converged findings: {len(converged_findings)}")
        print(f"Risk verdicts: {', '.join([v['verdict'] for v in verdicts])}")
        print(f"Passport signature: {'VALID' if passport.verify_signature() else 'INVALID'}")
        print(f"Staleness: {'STALE' if staleness_report.stale else 'FRESH'}")
        print(f"Artifacts saved in: {artifacts_dir}")

if __name__ == "__main__":
    main()