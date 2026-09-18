import hashlib
import json
import os
from pathlib import Path
import random
import numpy as np
from PIL import Image, ImageDraw

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def build_demo_dataset(dataset_dir: Path, n_images: int = 8, seed: int = 0) -> dict:
    """Build a tiny synthetic COCO dataset with a duplicate, a flipped label, and an OOD sample."""
    random.seed(seed)
    np.random.seed(seed)
    dataset_dir.mkdir(parents=True, exist_ok=True)
    (dataset_dir / "images").mkdir(exist_ok=True)
    (dataset_dir / "annotations").mkdir(exist_ok=True)

    images = []
    annotations = []
    categories = [{"id": 1, "name": "object"}, {"id": 2, "name": "other"}]

    # We'll create 8 images: 6 normal, 1 duplicate of image 0, 1 with flipped label, 1 OOD (bright)
    # For simplicity, we'll use solid color images.
    # Normal images: index 0-5
    # Duplicate: index 6 is copy of index 0
    # Flipped label: index 7 has label flipped (if normally 1, then 2)
    # OOD: we'll make one of the normal images (say index 2) very bright (white) to be OOD

    # Actually, let's make:
    # 0: red
    # 1: green
    # 2: blue (normal)
    # 3: yellow
    # 4: purple
    # 5: cyan
    # 6: duplicate of 0 (red)
    # 7: bright white (OOD)

    colors = [
        (255, 0, 0),    # red
        (0, 255, 0),    # green
        (0, 0, 255),    # blue
        (255, 255, 0),  # yellow
        (255, 0, 255),  # purple
        (0, 255, 255),  # cyan
        (255, 0, 0),    # duplicate red
        (255, 255, 255) # white OOD
    ]

    for i in range(n_images):
        # Create image
        img = Image.new('RGB', (32, 32), color=colors[i])
        img_path = dataset_dir / "images" / f"{i:04d}.png"
        img.save(img_path)
        images.append({
            "id": i,
            "width": 32,
            "height": 32,
            "file_name": f"{i:04d}.png"
        })

        # Create annotation: each image has one box covering the whole image
        # Normally label 1 (object) for images 0-5 and 6 (duplicate), but for image 7 (OOD) we'll flip to label 2
        # For the flipped label, we'll flip image 1 (green) to label 2 instead of 1.
        # Actually, let's flip image 1's label.
        if i == 1:
            category_id = 2  # flipped
        else:
            category_id = 1  # normal

        # For the OOD image (index 2), we'll keep label 1 but note it's OOD by appearance.
        # The OOD detector should catch it by appearance.

        annotations.append({
            "id": i,
            "image_id": i,
            "category_id": category_id,
            "bbox": [0, 0, 32, 32],
            "area": 32*32,
            "iscrowd": 0
        })

    # Ground truth: which images are anomalous and why
    ground_truth = {
        "duplicate": [6],  # duplicate of 0
        "flipped_label": [1],  # image 1 has label flipped to 2
        "ood": [2]  # image 2 is bright white (OOD by appearance)
    }

    coco_data = {
        "images": images,
        "annotations": annotations,
        "categories": categories
    }

    (dataset_dir / "annotations" / "instances.json").write_text(json.dumps(coco_data, indent=2))

    return ground_truth

def build_demo_model(model_dir: Path, seed: int = 0) -> dict:
    """Build a tiny deterministic logistic model (weights and bias) and a reference manifest."""
    random.seed(seed)
    np.random.seed(seed)
    model_dir.mkdir(parents=True, exist_ok=True)

    # We'll create a simple 2-layer network? Actually, for simplicity, we'll just save a weight vector and bias.
    # The model will be a logistic regression on flattened 32x32x3 = 3072 features -> 2 classes.
    # We'll make the weights such that the red image (0) is classified as class 0, green (1) as class 1, etc.
    # But we don't need to train; we just need a file to hash and a reference manifest.

    # Let's create a weight matrix of shape (2, 3072) and bias of shape (2,)
    W = np.random.randn(2, 3072) * 0.01
    b = np.zeros(2)

    # Save as .onnx
    model_path = model_dir / "model.npz"
    print(f"Saving model to {model_path.absolute()}")
    try:
        np.savez(model_path, W=W, b=b)
        print(f"Model saved successfully")
    except Exception as e:
        print(f"Error saving model: {e}")
        raise
    if not model_path.exists():
        print(f"File does not exist after save")
        print(f"Directory {model_path.parent} exists: {model_path.parent.exists()}")
        print(f"Directory contents: {list(model_path.parent.iterdir())}")
        raise RuntimeError(f"Model file not saved: {model_path}")

    # We'll also create a reference manifest that expects this exact model.
    # Since we don't have a full ModelReferenceManifest implementation that loads .npz, we'll just note the hash.
    # The identity check in model_manifest.py compares the SHA-256 of the weight file.
    # So we'll just rely on that.

    ground_truth = {
        "model_path": str(model_path),
        "weight_hash": sha256_file(model_path)
    }

    return ground_truth

def build_manifests(dataset_dir: Path, model_dir: Path) -> dict:
    """Build dataset manifest, model manifest, and pipeline manifest using the existing classes."""
    from app.manifests.dataset_manifest import DatasetManifest
    from app.manifests.model_manifest import ModelReferenceManifest
    from app.manifests.pipeline_manifest import PipelineEnvironmentManifest

# Dataset manifest from COCO
    dataset_manifest = DatasetManifest.build_from_coco(str(dataset_dir))

    # Model manifest: we need a reference model. We'll use the model we just built.
    # The ModelReferenceManifest expects a path to a model file and optionally a reference battery.
    # We'll create a dummy reference battery: just an empty dict for now.
    model_path = model_dir / "model.npz"
    model_manifest = ModelReferenceManifest.build_from_file(
        path=str(model_path),
        architecture="logistic_regression",
        expected_metrics={"accuracy": 1.0},
        activation_statistics={},
        output_fingerprints={},
        reference_battery_id="dummy",
        calibration_set_id="dummy",
        model_format='onnx'
    )

    # Pipeline manifest: dummy values
    pipeline_manifest = PipelineEnvironmentManifest(
        preprocessing_parameters={"resize": [32, 32], "normalize": [0.5, 0.5, 0.5]},
        confidence_thresholds={"default": 0.5},
        nms_settings={"iou_threshold": 0.5},
        input_resolution=[32, 32],
        model_identifier="logistic_regression",
        framework_version="numpy-1.24.0",
        runtime_version="python-3.14.3",
        pipeline_version="1.0.0"
    )

    return {
        "dataset_manifest": dataset_manifest,
        "model_manifest": model_manifest,
        "pipeline_manifest": pipeline_manifest
    }

if __name__ == "__main__":
    # For testing
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        dataset_dir = Path(tmp) / "dataset"
        model_dir = Path(tmp) / "model"
        gt_dataset = build_demo_dataset(dataset_dir)
        gt_model = build_demo_model(model_dir)
        manifests = build_manifests(dataset_dir, model_dir)
        print("Dataset ground truth:", gt_dataset)
        print("Model ground truth:", gt_model)
        print("Dataset manifest hash:", manifests["dataset_manifest"].compute_hash())
        print("Model manifest hash:", manifests["model_manifest"].compute_hash())