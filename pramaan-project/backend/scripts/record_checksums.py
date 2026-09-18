import argparse
import json
import sys
from pathlib import Path
from typing import Optional


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.self_integrity import DEFAULT_ROOT, _paths, collect_checksums


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Explicitly record a reviewed, known-good application baseline.")
    parser.add_argument("--record", action="store_true", required=True)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--force", action="store_true", help="Explicitly replace an existing baseline")
    args = parser.parse_args(argv)
    try:
        root, output = _paths(args.root, args.output)
        checksums = collect_checksums(root, output)
        document = {"version": 1, "algorithm": "sha256", "files": checksums}
        encoded = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        with output.open("wb" if args.force else "xb") as stream:
            stream.write(encoded)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Cannot record baseline: {error}\n")
    print(f"Recorded {len(checksums)} checksums in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
