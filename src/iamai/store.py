"""Snapshot store.

Snapshot path: data/{alias}/{timestamp}/raw/{dataset}.json plus manifest.json.
Snapshots are immutable once the manifest is written. Collections are sorted
by id before writing so that diffs between consecutive collects are limited to
genuinely volatile fields.

Timestamps use ISO 8601 basic format (no colons) so paths are valid on Windows.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from pydantic import BaseModel, Field

MANIFEST_NAME = "manifest.json"

# Every alias-taking CLI command checks the alias against the operator's
# configured tenants before it reaches here, which is an effective whitelist
# -- except sanitize() was missing that check (AUTHZ-002). This is the
# backstop underneath it: alias_dir() rejects anything that is not a plain
# name, so the guarantee holds even for a future caller that forgets the
# whitelist too. A path separator or ".." lets an alias walk out of data/;
# on Windows, Path("data") / "C:\\Windows\\Temp\\x" discards "data" entirely
# because the right operand is absolute, which a separator-based check alone
# would miss without the drive-qualified case Path(alias).name also catches.
_UNSAFE_ALIAS_CHARS = ("/", "\\")


def _harden_data_tree(raw_dir: Path) -> None:
    """Restrict raw/, its snapshot dir, the alias dir and the data root to the
    owner on POSIX. Applied on every snapshot write, so a tree created before
    this hardening is tightened too, the same lesson as the private key
    (DEPLOY-2-004, SECRETS-2-001)."""
    if os.name == "nt":
        return
    # raw_dir -> snapshot dir -> alias dir -> data root.
    for path in (raw_dir, raw_dir.parent, raw_dir.parent.parent, raw_dir.parent.parent.parent):
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def _validate_alias(alias: str) -> None:
    if (
        not alias
        or alias in (".", "..")
        or any(char in alias for char in _UNSAFE_ALIAS_CHARS)
        or alias != Path(alias).name
    ):
        raise ValueError(
            f"{alias!r} is not a valid tenant alias. An alias must be a plain "
            "name with no path separators or parent directory references."
        )


class DatasetRecord(BaseModel):
    """Manifest entry for one collector run."""

    dataset: str
    endpoint: str
    apiVersion: str
    count: int
    durationSeconds: float
    complete: bool
    skipped: bool = False
    errors: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)


class Manifest(BaseModel):
    tenantId: str
    alias: str
    collectedAt: str
    tool: str
    complete: bool
    datasets: list[DatasetRecord]


def sort_collections(value):
    """Recursively sort lists of objects by id for stable snapshots."""
    if isinstance(value, dict):
        return {key: sort_collections(item) for key, item in value.items()}
    if isinstance(value, list):
        items = [sort_collections(item) for item in value]
        if items and all(isinstance(item, dict) and "id" in item for item in items):
            items.sort(key=lambda item: str(item["id"]))
        elif all(isinstance(item, str) for item in items):
            items = sorted(items)
        elif items and all(isinstance(item, dict) for item in items):
            # Object arrays without an id: assignedPlans, servicePlans,
            # provisionedPlans, verifiedDomains, rolePermissions and
            # certificateUserBindings all match neither rule above, and Graph
            # does not promise an order for them, so a server side reorder
            # produced a large spurious diff against the stability requirement
            # (BUGS.md item 32). Sorted by their own canonical JSON, which is
            # deterministic without needing to know the shape.
            items.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        return items
    return value


class SnapshotWriter:
    """Writes one snapshot. Refuses further writes once finalized."""

    def __init__(self, snapshot_dir: Path):
        self.snapshot_dir = snapshot_dir
        self.raw_dir = snapshot_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=False)
        # The private key is now owner-only, but the collected snapshots are
        # the other half of the exposure: raw UPNs, sign-in history, IPs and
        # (until sanitized) geolocation. mkdir(parents=True) creates the chain
        # at the default umask, world-readable on a stock POSIX system, so a
        # co-resident local user could read a client tenant's full roster.
        # Restrict the whole data tree to the owner (DEPLOY-2-004). The mode is
        # a no-op on Windows, where NTFS inheritance governs instead.
        _harden_data_tree(self.raw_dir)
        self._finalized = False

    def _check_open(self) -> None:
        if self._finalized:
            raise RuntimeError("Snapshot is finalized and immutable.")

    def write_dataset(self, name: str, data) -> Path:
        self._check_open()
        path = self.raw_dir / f"{name}.json"
        path.write_text(
            json.dumps(sort_collections(data), indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def raw_file_path(self, filename: str) -> Path:
        """Path for a collector that streams its own file (sign-in logs)."""
        self._check_open()
        return self.raw_dir / filename

    def finalize(self, manifest: Manifest) -> Path:
        self._check_open()
        manifest_path = self.snapshot_dir / MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(manifest.model_dump(), indent=2, sort_keys=True), encoding="utf-8"
        )
        self._finalized = True
        return manifest_path


class SnapshotStore:
    def __init__(self, data_dir: Path | None = None):
        from iamai.paths import data_dir as default_data_dir

        self.data_dir = data_dir or default_data_dir()

    def alias_dir(self, alias: str) -> Path:
        _validate_alias(alias)
        return self.data_dir / alias

    def new_snapshot(self, alias: str) -> SnapshotWriter:
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        snapshot_dir = self.alias_dir(alias) / timestamp
        suffix = 1
        while snapshot_dir.exists():
            snapshot_dir = self.alias_dir(alias) / f"{timestamp}-{suffix}"
            suffix += 1
        return SnapshotWriter(snapshot_dir)

    def snapshots(self, alias: str) -> list[Path]:
        """Completed snapshots (manifest present), oldest first."""
        alias_dir = self.alias_dir(alias)
        if not alias_dir.exists():
            return []
        return sorted(
            path for path in alias_dir.iterdir()
            if path.is_dir() and (path / MANIFEST_NAME).exists()
        )

    def latest_snapshot(self, alias: str) -> Path:
        snapshots = self.snapshots(alias)
        if not snapshots:
            raise FileNotFoundError(
                f"No completed snapshot for alias '{alias}'. Run 'iamai collect {alias}' first."
            )
        return snapshots[-1]

    def load_manifest(self, snapshot_dir: Path) -> Manifest:
        return Manifest.model_validate_json(
            (snapshot_dir / MANIFEST_NAME).read_text(encoding="utf-8")
        )

    def snapshots_to_purge(
        self,
        alias: str,
        *,
        older_than_days: float | None = None,
        keep_latest: int | None = None,
    ) -> list[Path]:
        """Which completed snapshots for alias would be removed, oldest
        first. Pure: this only decides, it never deletes anything. Every
        collect leaves a full copy of real names, sign-in history and
        location data on disk with nothing else in this tool ever removing
        it (RETENTION-001); this is what a purge command reasons from before
        touching the filesystem. Exactly one of older_than_days or
        keep_latest is expected -- the caller enforces that and decides what
        neither being given means (delete everything, for --all)."""
        snapshots = self.snapshots(alias)
        if keep_latest is not None:
            keep = set(snapshots[-keep_latest:]) if keep_latest > 0 else set()
            return [s for s in snapshots if s not in keep]
        if older_than_days is not None:
            cutoff = time.time() - older_than_days * 86400
            return [s for s in snapshots if self._collected_at_epoch(s) < cutoff]
        return list(snapshots)

    def _collected_at_epoch(self, snapshot_dir: Path) -> float:
        from datetime import datetime

        collected_at = self.load_manifest(snapshot_dir).collectedAt
        return datetime.fromisoformat(collected_at.replace("Z", "+00:00")).timestamp()


def load_snapshot_data(snapshot_dir: Path) -> tuple[dict, dict]:
    """Read a snapshot's raw JSON datasets and manifest into plain dicts.

    Sign-in jsonl.gz feeds are not loaded here; consumers stream them from
    the snapshot directory when needed. Accepts either a snapshot directory
    containing raw/ or a flat directory of dataset files (fixtures)."""
    raw_dir = snapshot_dir / "raw"
    if not raw_dir.exists():
        raw_dir = snapshot_dir
    data: dict = {}
    for raw_file in sorted(raw_dir.glob("*.json")):
        if raw_file.name == MANIFEST_NAME:
            continue
        data[raw_file.stem] = json.loads(raw_file.read_text(encoding="utf-8"))
    manifest_path = snapshot_dir / MANIFEST_NAME
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    )
    return data, manifest
