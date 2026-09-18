import math
from collections import Counter, defaultdict
from statistics import median

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest


def covered_fraction(rectangles, width, height):
    xs = sorted({value for x1, _, x2, _ in rectangles for value in (x1, x2)})
    area = 0.0
    for left, right in zip(xs, xs[1:]):
        intervals = sorted((y1, y2) for x1, y1, x2, y2 in rectangles if x1 < right and x2 > left)
        end = 0.0
        length = 0.0
        for start, stop in intervals:
            length += max(0.0, stop - max(start, end))
            end = max(end, stop)
        area += (right - left) * length
    return area / (width * height)


class AnnotationIntegrityDetector(EvidenceProvider):
    def __init__(self, min_shift_boxes=3, shift_threshold=0.05, shift_tolerance=0.01,
                 uncovered_threshold=0.6, coverage_gap=0.4):
        super().__init__("annotation_integrity")
        if not isinstance(min_shift_boxes, int) or min_shift_boxes < 2:
            raise ValueError("min_shift_boxes must be at least 2")
        for value in (shift_threshold, shift_tolerance, uncovered_threshold, coverage_gap):
            if not math.isfinite(value) or not 0 < value <= 1:
                raise ValueError("Annotation thresholds must be in (0, 1]")
        self.min_shift_boxes = min_shift_boxes
        self.shift_threshold = shift_threshold
        self.shift_tolerance = shift_tolerance
        self.uncovered_threshold = uncovered_threshold
        self.coverage_gap = coverage_gap

    def analyze(self, dataset):
        annotations = dataset["annotations"]
        hashes = [digest(annotation) for annotation in annotations]
        provenance = self._create_provenance(hashes, dataset["config_hash"])
        names = [str(annotation["image_id"]) for annotation in annotations]
        if len(set(names)) != len(names):
            raise ValueError("image_id values must be unique")
        findings = []
        coverage = {}
        groups = defaultdict(list)
        layouts = {}

        def emit(index, kind, severity, confidence, evidence, limitation):
            findings.append(Finding(
                asset_id=names[index], finding_type=kind, severity=severity,
                confidence=confidence, evidence=evidence, modality=Modality.ANNOTATION,
                provenance=provenance, recommended_action="review", quarantine_scope="sample",
                access_assumptions="black_box", counter_evidence=[limitation],
            ))

        for index, annotation in enumerate(annotations):
            width, height = annotation["width"], annotation["height"]
            if any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(value) or value <= 0 for value in (width, height)):
                raise ValueError("Image dimensions must be finite and positive")
            rectangles = []
            normalized = []
            valid = True
            for box_index, box in enumerate(annotation["boxes"]):
                x, y, w, h = (box[key] for key in ("x", "y", "w", "h"))
                if any(isinstance(value, bool) or not isinstance(value, (int, float))
                       or not math.isfinite(value) for value in (x, y, w, h)):
                    raise ValueError("Box coordinates must be finite numbers")
                if w <= 0 or h <= 0:
                    valid = False
                    emit(index, "invalid_box_area", 0.8, 1.0,
                         [f"Box {box_index} has nonpositive extent: w={w}, h={h}."],
                         "Validation assumes top-left x/y and positive pixel w/h; a format mismatch "
                         "does not establish malicious editing.")
                    continue
                if x < 0 or y < 0 or x + w > width or y + h > height:
                    valid = False
                    emit(index, "box_out_of_bounds", 0.7, 1.0,
                         [f"Box {box_index}: {(x, y, w, h)} exceeds image bounds {(width, height)}."],
                         "Some datasets intentionally retain unclipped boxes for truncated objects; "
                         "out-of-bounds coordinates alone do not prove tampering.")
                left, top = max(0, x), max(0, y)
                right, bottom = min(width, x + w), min(height, y + h)
                if right > left and bottom > top:
                    rectangles.append((left, top, right, bottom))
                normalized.append((x / width, y / height, w / width, h / height))
            if valid:
                coverage[index] = covered_fraction(rectangles, width, height)
                groups[(width, height)].append(index)
                layouts[index] = sorted(normalized)

        for members in groups.values():
            for index in members:
                labeled_peers = [item for item in members if item != index and coverage[item] > 0]
                if len(labeled_peers) < 2:
                    continue
                reference_coverage = median(coverage[item] for item in labeled_peers)
                uncovered = 1 - coverage[index]
                if uncovered >= self.uncovered_threshold and reference_coverage - coverage[index] >= self.coverage_gap:
                    emit(index, "large_unlabeled_region", 0.6, 0.5,
                         [f"Uncovered image fraction={uncovered:.3f}; same-size labeled peer median "
                          f"coverage={reference_coverage:.3f}; peers={[names[item] for item in labeled_peers]}."],
                         "Only dimensions are available as a similarity proxy, not image content. "
                         "Background-only images and naturally sparse scenes can legitimately lack labels.")

            by_shape = defaultdict(list)
            for index in members:
                if layouts[index]:
                    shape = tuple((round(box[2], 4), round(box[3], 4)) for box in layouts[index])
                    by_shape[shape].append(index)
            for comparable in by_shape.values():
                signatures = {index: tuple((round(box[0], 4), round(box[1], 4))
                                           for box in layouts[index]) for index in comparable}
                baseline, count = Counter(signatures.values()).most_common(1)[0]
                if count < 2 or count <= len(comparable) / 2:
                    continue
                candidates = defaultdict(list)
                for index in comparable:
                    if signatures[index] == baseline:
                        continue
                    offsets = [(box[0] - ref[0], box[1] - ref[1])
                               for box, ref in zip(layouts[index], baseline)]
                    dx, dy = (median(offset[axis] for offset in offsets) for axis in (0, 1))
                    if max(abs(dx), abs(dy)) < self.shift_threshold:
                        continue
                    if any(max(abs(x - dx), abs(y - dy)) > self.shift_tolerance for x, y in offsets):
                        continue
                    bucket = (round(dx / self.shift_tolerance), round(dy / self.shift_tolerance))
                    candidates[bucket].append((index, dx, dy, len(offsets)))
                for shifted in candidates.values():
                    box_count = sum(item[3] for item in shifted)
                    if box_count < self.min_shift_boxes:
                        continue
                    for index, dx, dy, _ in shifted:
                        emit(index, "systematic_box_shift", 0.65, 0.6,
                             [f"Consistent normalized offset ({dx:.4f}, {dy:.4f}) relative to "
                              f"majority layout across {box_count} boxes; tolerance={self.shift_tolerance}."],
                             "Matching box sizes/order and a majority layout are weak reference proxies. "
                             "Camera motion or legitimate object translation can explain this offset; "
                             "a uniformly shifted batch without a reference cannot be detected.")
        return findings
