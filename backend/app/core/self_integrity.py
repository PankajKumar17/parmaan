import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Optional, Union


PathInput = Union[str, Path]
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BASELINE = Path("backend/checksums.json")
_EXCLUDED_DIRECTORIES = frozenset({
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "node_modules",
})
_EXCLUDED_TREES = frozenset({
    "frontend", "backend/artifacts", "backend/keys", "backend/tests",
    "backend/data", "backend/logs", "backend/uploads",
})
_SUFFIXES = frozenset({".py", ".sql", ".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".env", ".lock"})
_CONFIG_NAMES = frozenset({".env", "Dockerfile", "Procfile", "Pipfile", "poetry.lock", "uv.lock"})


@dataclass(frozen=True)
class IntegrityReport:
    verified: bool = False
    missing: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    errors: tuple[str, ...] = ("Self-integrity has not been checked",)

    @property
    def degraded(self) -> bool:
        return not self.verified

    @property
    def status(self) -> str:
        return "VERIFIED" if self.verified else "DEGRADED/UNVERIFIED"


class SelfIntegrityError(RuntimeError):
    def __init__(self, report: IntegrityReport):
        self.report = report
        super().__init__(f"Self-integrity check failed: {report}")


SELF_INTEGRITY_DEGRADED = True
SELF_INTEGRITY_VERIFIED = False
_report = IntegrityReport()


def get_integrity_status() -> IntegrityReport:
    return _report


def _paths(root: Optional[PathInput], baseline_path: Optional[PathInput]) -> tuple[Path, Path]:
    project = Path(root if root is not None else DEFAULT_ROOT).resolve(strict=True)
    if not project.is_dir():
        raise ValueError("Application root must be a directory")
    baseline = Path(baseline_path if baseline_path is not None else DEFAULT_BASELINE)
    if not baseline.is_absolute():
        baseline = project / baseline
    if baseline.is_symlink():
        raise ValueError("Baseline must not be a symbolic link")
    return project, baseline.resolve()


def _tracked(relative: str) -> bool:
    path = PurePosixPath(relative)
    if any(part in _EXCLUDED_DIRECTORIES for part in path.parts[:-1]):
        return False
    if any(relative == tree or relative.startswith(tree + "/") for tree in _EXCLUDED_TREES):
        return False
    return (
        path.suffix.lower() in _SUFFIXES
        or path.name in _CONFIG_NAMES
        or path.name.startswith(".env.")
        or (path.name.startswith("requirements") and path.suffix == ".txt")
    )


def _entry_path(root: Path, name: str) -> Path:
    if (
        not isinstance(name, str) or not name or "\\" in name or ":" in name
        or "\x00" in name or PureWindowsPath(name).is_absolute()
        or PurePosixPath(name).is_absolute()
        or any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in name.split("/"))
    ):
        raise ValueError("Invalid baseline path")
    candidate = root / name
    if not candidate.resolve().is_relative_to(root):
        raise ValueError("Baseline entry escapes application root")
    current = root
    for part in name.split("/"):
        current = current / part
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise ValueError("Symbolic links and junctions are not trusted")
    return candidate


def collect_checksums(
    root: Optional[PathInput] = None,
    baseline_path: Optional[PathInput] = None,
) -> dict[str, str]:
    project, baseline = _paths(root, baseline_path)
    checksums = {}

    def onerror(error: OSError) -> None:
        raise error

    for directory, directories, files in os.walk(project, onerror=onerror, followlinks=False):
        parent = Path(directory)
        retained = []
        for name in sorted(directories):
            child = parent / name
            relative = child.relative_to(project).as_posix()
            if name in _EXCLUDED_DIRECTORIES or relative in _EXCLUDED_TREES:
                continue
            _entry_path(project, relative)
            retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            child = parent / name
            relative = child.relative_to(project).as_posix()
            if child == baseline or not _tracked(relative):
                continue
            child = _entry_path(project, relative)
            if not child.is_file():
                raise ValueError(f"Not a regular application file: {relative}")
            digest = hashlib.sha256()
            with child.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            checksums[relative] = digest.hexdigest()
    if not checksums:
        raise ValueError("No application source, schema or configuration files found")
    if len({name.casefold() for name in checksums}) != len(checksums):
        raise ValueError("Ambiguous case-insensitive application paths")
    return dict(sorted(checksums.items()))


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate baseline JSON key")
        result[key] = value
    return result


def _load_baseline(project: Path, baseline: Path) -> dict[str, str]:
    with baseline.open("r", encoding="utf-8") as stream:
        document = json.load(stream, object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or set(document) != {"version", "algorithm", "files"}:
        raise ValueError("Invalid baseline structure")
    if type(document["version"]) is not int or document["version"] != 1 or document["algorithm"] != "sha256":
        raise ValueError("Unsupported baseline format")
    entries = document["files"]
    if not isinstance(entries, dict) or not entries:
        raise ValueError("Baseline files must be a nonempty mapping")
    seen = set()
    for name, digest in entries.items():
        candidate = _entry_path(project, name)
        if candidate == baseline or not _tracked(name) or name.casefold() in seen:
            raise ValueError("Invalid or ambiguous baseline entry")
        seen.add(name.casefold())
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("Invalid SHA-256 checksum")
    return entries


def check_self_integrity(
    root: Optional[PathInput] = None,
    baseline_path: Optional[PathInput] = None,
    require: Optional[bool] = None,
) -> IntegrityReport:
    global _report, SELF_INTEGRITY_DEGRADED, SELF_INTEGRITY_VERIFIED
    _report = IntegrityReport()
    SELF_INTEGRITY_DEGRADED = True
    SELF_INTEGRITY_VERIFIED = False
    required = True
    try:
        if require is None:
            value = os.environ.get("REQUIRE_SELF_INTEGRITY", "false").strip().lower()
            if value not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
                raise ValueError("Invalid REQUIRE_SELF_INTEGRITY boolean")
            required = value in {"true", "1", "yes", "on"}
        elif type(require) is bool:
            required = require
        else:
            raise ValueError("require must be a boolean or None")
        project, baseline = _paths(root, baseline_path)
        expected = _load_baseline(project, baseline)
        actual = collect_checksums(project, baseline)
        missing = tuple(sorted(expected.keys() - actual.keys()))
        added = tuple(sorted(actual.keys() - expected.keys()))
        changed = tuple(sorted(name for name in expected.keys() & actual.keys() if expected[name] != actual[name]))
        _report = IntegrityReport(not (missing or added or changed), missing, changed, added, ())
    except (OSError, ValueError, TypeError, RecursionError, RuntimeError) as error:
        _report = IntegrityReport(errors=(f"{type(error).__name__}: {error}",))
    SELF_INTEGRITY_DEGRADED = _report.degraded
    SELF_INTEGRITY_VERIFIED = _report.verified
    if required and _report.degraded:
        raise SelfIntegrityError(_report)
    return _report
