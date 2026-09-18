import numpy as np
from PIL import Image


def _features(image):
    if isinstance(image, tuple) and len(image) == 2:
        image = image[1]
    if isinstance(image, Image.Image):
        pixels = np.asarray(image.convert("RGB"), dtype=np.float64) / 255.0
    else:
        raw = np.asarray(image)
        pixels = raw.astype(np.float64)
        if np.issubdtype(raw.dtype, np.integer):
            pixels /= 255.0
        if pixels.ndim == 2:
            pixels = np.repeat(pixels[..., None], 3, axis=2)
    if pixels.ndim != 3 or pixels.shape[2] != 3 or min(pixels.shape[:2]) < 2:
        raise ValueError("Cause attribution requires RGB images at least 2 x 2")
    if not np.isfinite(pixels).all() or (pixels < 0).any() or (pixels > 1).any():
        raise ValueError("Images must be finite and normalized to [0, 1]")
    gray = pixels.mean(axis=2)
    brightness = float(gray.mean())
    channel_means = pixels.mean(axis=(0, 1))
    chroma = np.round(pixels - gray[..., None], decimals=12)
    histograms = np.concatenate([np.histogram(chroma[..., channel], bins=16, range=(-1, 1))[0]
                                 / gray.size for channel in range(3)])
    padded = np.pad(gray, 1, mode="reflect")
    laplacian = (padded[:-2, 1:-1] + padded[2:, 1:-1] + padded[1:-1, :-2]
                 + padded[1:-1, 2:] - 4 * gray)
    blur = float(np.var(laplacian))
    noise = float(np.median(np.abs(laplacian - np.median(laplacian))) / (0.67448975 * np.sqrt(20)))
    normalized = gray - brightness
    rows = np.array_split(normalized, min(4, normalized.shape[0]), axis=0)
    structure = np.array([part.mean() for row in rows for part in np.array_split(row, min(4, gray.shape[1]), axis=1)])
    structure = np.pad(structure, (0, 16 - len(structure)))
    return brightness, channel_means - brightness, histograms, blur, noise, structure


def classify_shift(reference_images, current_images):
    reference = [_features(image) for image in reference_images]
    current = [_features(image) for image in current_images]
    if not reference or not current:
        raise ValueError("Both image batches must be nonempty")
    ref = [np.mean([item[index] for item in reference], axis=0) for index in range(6)]
    cur = [np.mean([item[index] for item in current], axis=0) for index in range(6)]
    brightness_delta = float(abs(cur[0] - ref[0]))
    channel_delta = float(np.mean(np.abs(cur[1] - ref[1])))
    histogram_delta = float(np.abs(cur[2] - ref[2]).sum() / 6)
    blur_delta = float(abs(np.sqrt(cur[3]) - np.sqrt(ref[3])))
    noise_delta = float(abs(cur[4] - ref[4]))
    structural_delta = float(np.mean(np.abs(cur[5] - ref[5])))
    magnitudes = {
        "illumination": brightness_delta,
        "color": channel_delta + histogram_delta,
        "blur_noise": blur_delta + noise_delta,
        "structural": structural_delta,
    }
    magnitudes = {key: 0.0 if value < 1e-12 else value for key, value in magnitudes.items()}
    total = sum(magnitudes.values())
    shares = {key: value / total if total else 0.0 for key, value in magnitudes.items()}
    return {
        **shares,
        "magnitudes": magnitudes,
        "total_magnitude": total,
        "metrics": {"brightness_delta": brightness_delta, "channel_mean_delta": channel_delta,
                    "color_histogram_delta": histogram_delta, "laplacian_blur_delta": blur_delta,
                    "noise_delta": noise_delta, "structural_delta": structural_delta},
        "evidence": [
            f"Heuristic cause attribution: illumination share={shares['illumination']:.1%}, color share={shares['color']:.1%}, "
            f"blur_noise share={shares['blur_noise']:.1%}, structural share={shares['structural']:.1%}.",
            "Illumination maps to lighting/time-of-day; color to terrain/season; blur_noise to sensor; structural to terrain/viewpoint. "
            "These descriptive shares are not causal probabilities and cannot identify manipulation.",
        ],
    }
