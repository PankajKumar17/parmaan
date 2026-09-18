import math
from pathlib import Path, PurePosixPath, PureWindowsPath

from app.manifests._common import file_sha256, read_json
from app.provenance.canonical import canonical_serialization


COCO_LAYOUT = (
    "Supported COCO layouts: root/annotations.json or root/annotations/instances.json "
    "with image file_name paths relative to root or root/images; alternatively pass "
    "a JSON file whose parent contains images. Only one annotation file is selected."
)
YOLO_LAYOUT = (
    "Supported YOLO layout: root/classes.txt (one unique class name per line), "
    "root/images/<relative image> and root/labels/<same relative stem>.txt, including "
    "nested split directories. Each image needs a label file (empty for negatives). "
    "Labels must be detection rows: class_id x_center y_center width height, normalized "
    "to [0,1]. Optional root/metadata.json holds dataset_version, contributor_id, "
    "batch_id and samples keyed by images/... paths. YAML configs, image lists, "
    "segmentation and pose labels are not supported."
)
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "123456789¹²³"
}


def safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative:
        raise ValueError(f"Unsafe dataset path: {relative!r}")
    posix = PurePosixPath(relative)
    windows = PureWindowsPath(relative)
    if (
        posix.is_absolute() or windows.drive or windows.root
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or any(
            part.endswith((" ", ".")) or part.split(".", 1)[0].rstrip().upper() in RESERVED_NAMES
            or any(character in '<>:"|?*' or ord(character) < 32 for character in part)
            for part in posix.parts
        )
    ):
        raise ValueError(f"Unsafe dataset path: {relative!r}")
    root = root.resolve(strict=True)
    candidate = root.joinpath(*posix.parts)
    cursor = root
    for part in posix.parts:
        cursor = cursor / part
        if cursor.is_symlink() or (hasattr(cursor, "is_junction") and cursor.is_junction()):
            raise ValueError(f"Dataset links are not supported: {relative}")
    if not candidate.resolve().is_relative_to(root):
        raise ValueError(f"Dataset path escapes root: {relative}")
    return candidate


def _inventory(root: Path) -> dict[str, str]:
    result = {}

    def walk(directory):
        for entry in sorted(directory.iterdir()):
            relative = entry.relative_to(root).as_posix()
            entry = safe_path(root, relative)
            if entry.is_dir():
                walk(entry)
            elif entry.is_file():
                result[relative] = file_sha256(entry)
            else:
                raise ValueError(f"Unsupported dataset entry: {relative}")

    walk(root)
    return result


def _identifier(value, label):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _metadata(value, label):
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} must be a string or null")
    return value


def _number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    return value


def _ordered(items):
    return sorted(items, key=canonical_serialization)


def load_coco(path: str | Path) -> dict:
    try:
        return _load_coco(Path(path))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ValueError(f"Invalid COCO dataset: {exc}. {COCO_LAYOUT}") from exc


def _load_coco(path: Path) -> dict:
    if path.is_file():
        root = path.parent.resolve(strict=True)
        annotation_path = safe_path(root, path.name)
    else:
        root = path.resolve(strict=True)
        candidates = [safe_path(root, name) for name in ("annotations.json", "annotations/instances.json")]
        candidates = [candidate for candidate in candidates if candidate.is_file()]
        if len(candidates) != 1:
            raise ValueError("Expected exactly one supported annotation JSON file")
        annotation_path = candidates[0]
    inventory = _inventory(root)
    document = read_json(annotation_path)
    if not isinstance(document, dict):
        raise ValueError("Annotations must be an object")
    for key in ("images", "annotations", "categories"):
        if not isinstance(document.get(key), list):
            raise ValueError(f"{key} must be an array")
    classes = {}
    for category in document["categories"]:
        if not isinstance(category, dict):
            raise ValueError("Category must be an object")
        category_id = str(_identifier(category["id"], "category id"))
        if category_id in classes or not isinstance(category.get("name"), str) or not category["name"]:
            raise ValueError("Category IDs must be unique and names nonempty")
        classes[category_id] = category["name"]
    counts = dict.fromkeys(classes, 0)
    samples = {}
    image_ids = set()
    contributor = _metadata(document.get("contributor_id"), "contributor_id")
    batch = _metadata(document.get("batch_id"), "batch_id")
    for image in document["images"]:
        if not isinstance(image, dict):
            raise ValueError("Image must be an object")
        image_id = _identifier(image["id"], "image id")
        if image_id in image_ids:
            raise ValueError("Duplicate image id")
        image_ids.add(image_id)
        name = image["file_name"]
        direct = safe_path(root, name)
        nested = safe_path(root, f"images/{name}")
        candidates = [candidate for candidate in (direct, nested) if candidate.is_file()]
        if len(candidates) != 1:
            raise ValueError(f"Missing or ambiguous image: {name}")
        relative = candidates[0].relative_to(root).as_posix()
        if relative in samples:
            raise ValueError(f"Duplicate image path: {relative}")
        if relative == annotation_path.relative_to(root).as_posix():
            raise ValueError("Annotation source cannot also be an image")
        samples[relative] = {
            "sha256": inventory[relative],
            "contributor_id": _metadata(image.get("contributor_id", contributor), "contributor_id"),
            "batch_id": _metadata(image.get("batch_id", batch), "batch_id"),
        }
    annotation_ids = set()
    for annotation in document["annotations"]:
        if not isinstance(annotation, dict):
            raise ValueError("Annotation must be an object")
        annotation_id = _identifier(annotation["id"], "annotation id")
        image_id = _identifier(annotation["image_id"], "annotation image_id")
        category_id = str(_identifier(annotation["category_id"], "annotation category_id"))
        if annotation_id in annotation_ids or image_id not in image_ids or category_id not in classes:
            raise ValueError("Duplicate annotation id or unknown image/category reference")
        annotation_ids.add(annotation_id)
        if "bbox" in annotation:
            bbox = annotation["bbox"]
            if not isinstance(bbox, list) or len(bbox) != 4:
                raise ValueError("COCO bbox must be [x, y, width, height]")
            for value in bbox:
                _number(value, "bbox coordinate")
            if bbox[2] < 0 or bbox[3] < 0:
                raise ValueError("COCO bbox dimensions must be nonnegative")
        counts[category_id] += 1
    normalized = dict(document)
    for key in ("images", "annotations", "categories"):
        normalized[key] = _ordered(document[key])
    source = annotation_path.relative_to(root).as_posix()
    inventory.pop(source)
    return {
        "format": "coco", "dataset_version": document.get("dataset_version", document.get("version", "1")),
        "samples": dict(sorted(samples.items())), "annotations": normalized,
        "class_names": classes, "class_distribution": counts,
        "contributor_id": contributor, "batch_id": batch,
        "files": inventory, "sources": [source],
    }


def load_yolo(path: str | Path) -> dict:
    try:
        return _load_yolo(Path(path))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ValueError(f"Invalid YOLO dataset: {exc}. {YOLO_LAYOUT}") from exc


def _load_yolo(path: Path) -> dict:
    root = path.resolve(strict=True)
    inventory = _inventory(root)
    classes_path = safe_path(root, "classes.txt")
    names = classes_path.read_text(encoding="utf-8-sig").splitlines()
    names = [name.strip() for name in names]
    if not names or any(not name for name in names) or len(set(names)) != len(names):
        raise ValueError("classes.txt must contain unique, nonempty class names")
    classes = {str(index): name for index, name in enumerate(names)}
    counts = dict.fromkeys(classes, 0)
    metadata_path = safe_path(root, "metadata.json")
    metadata = read_json(metadata_path) if metadata_path.is_file() else {}
    if not isinstance(metadata, dict) or not isinstance(metadata.get("samples", {}), dict):
        raise ValueError("metadata.json and its samples must be objects")
    contributor = _metadata(metadata.get("contributor_id"), "contributor_id")
    batch = _metadata(metadata.get("batch_id"), "batch_id")
    for name in metadata.get("samples", {}):
        safe_path(root, name)
    if not safe_path(root, "images").is_dir() or not safe_path(root, "labels").is_dir():
        raise ValueError("Both images/ and labels/ directories are required")
    samples = {}
    annotations = {}
    sources = {"classes.txt"}
    if metadata_path.is_file():
        sources.add("metadata.json")
    labels_used = set()
    for name in sorted(inventory):
        relative = PurePosixPath(name)
        if relative.parts[0] != "images" or relative.suffix.lower() not in IMAGE_SUFFIXES:
            continue
        label = PurePosixPath("labels", *relative.parts[1:]).with_suffix(".txt").as_posix()
        if label in labels_used:
            raise ValueError(f"Multiple images share label file: {label}")
        labels_used.add(label)
        label_path = safe_path(root, label)
        rows = []
        for index, line in enumerate(label_path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            tokens = line.split()
            if len(tokens) != 5 or not tokens[0].isascii() or not tokens[0].isdigit():
                raise ValueError(f"Invalid detection row at {label}:{index}")
            category = str(int(tokens[0]))
            if category not in classes:
                raise ValueError(f"Unknown class at {label}:{index}")
            coordinates = [float(token) for token in tokens[1:]]
            if any(not math.isfinite(value) or not 0 <= value <= 1 for value in coordinates):
                raise ValueError(f"Coordinates must be finite and normalized at {label}:{index}")
            if coordinates[2] <= 0 or coordinates[3] <= 0:
                raise ValueError(f"Box dimensions must be positive at {label}:{index}")
            rows.append({"category_id": int(category), "bbox": coordinates})
            counts[category] += 1
        sample_metadata = metadata.get("samples", {}).get(name, {})
        if not isinstance(sample_metadata, dict):
            raise ValueError(f"Sample metadata must be an object: {name}")
        samples[name] = {
            "sha256": inventory[name],
            "contributor_id": _metadata(sample_metadata.get("contributor_id", contributor), "contributor_id"),
            "batch_id": _metadata(sample_metadata.get("batch_id", batch), "batch_id"),
        }
        annotations[name] = _ordered(rows)
        sources.add(label)
    if set(metadata.get("samples", {})) - set(samples):
        raise ValueError("Metadata references unknown images")
    if {name for name in inventory if name.startswith("labels/") and name.endswith(".txt")} != labels_used:
        raise ValueError("Orphan label files are not supported")
    for source in sources:
        inventory.pop(source)
    return {
        "format": "yolo", "dataset_version": metadata.get("dataset_version", "1"),
        "samples": samples,
        "annotations": {"labels": annotations, "classes": classes, "metadata": metadata},
        "class_names": classes, "class_distribution": counts,
        "contributor_id": contributor, "batch_id": batch,
        "files": inventory, "sources": sorted(sources),
    }
