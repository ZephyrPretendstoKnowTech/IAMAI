import json

import pytest

from iamai.store import Manifest, SnapshotStore, sort_collections

pytestmark = pytest.mark.m0


def _manifest(alias="golden"):
    return Manifest(
        tenantId="11111111-1111-1111-1111-111111111111",
        alias=alias,
        collectedAt="2026-06-10T00:00:00Z",
        tool="0.1.0",
        complete=True,
        datasets=[],
    )


def test_sort_collections_orders_by_id_recursively():
    data = {
        "value": [
            {"id": "b", "nested": [{"id": "2"}, {"id": "1"}]},
            {"id": "a", "tags": ["z", "a"]},
        ]
    }
    sorted_data = sort_collections(data)
    assert [item["id"] for item in sorted_data["value"]] == ["a", "b"]
    assert [item["id"] for item in sorted_data["value"][1]["nested"]] == ["1", "2"]
    assert sorted_data["value"][0]["tags"] == ["a", "z"]


def test_dataset_files_are_byte_stable_across_input_order(tmp_path):
    store = SnapshotStore(tmp_path)
    writer1 = store.new_snapshot("golden")
    writer1.write_dataset("things", [{"id": "b", "x": 1}, {"id": "a", "x": 2}])
    writer1.finalize(_manifest())

    writer2 = store.new_snapshot("golden")
    writer2.write_dataset("things", [{"id": "a", "x": 2}, {"id": "b", "x": 1}])
    writer2.finalize(_manifest())

    first = (writer1.raw_dir / "things.json").read_bytes()
    second = (writer2.raw_dir / "things.json").read_bytes()
    assert first == second


def test_snapshot_tree_is_owner_only_on_posix(tmp_path):
    """Collected snapshots hold raw tenant PII; the data tree is restricted to
    the owner so a co-resident local user cannot read it (DEPLOY-2-004)."""
    import os
    import stat

    data_dir = tmp_path / "data"
    writer = SnapshotStore(data_dir).new_snapshot("golden")
    writer.write_dataset("things", [])
    if os.name == "nt":
        pytest.skip("POSIX mode bits do not apply on Windows")
    for path in (writer.raw_dir, writer.snapshot_dir, data_dir / "golden", data_dir):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, f"{path} not owner-only"


def test_snapshot_immutable_after_finalize(tmp_path):
    writer = SnapshotStore(tmp_path).new_snapshot("golden")
    writer.write_dataset("things", [])
    writer.finalize(_manifest())
    with pytest.raises(RuntimeError, match="immutable"):
        writer.write_dataset("more", [])
    with pytest.raises(RuntimeError, match="immutable"):
        writer.raw_file_path("more.jsonl.gz")


def test_latest_snapshot_requires_manifest(tmp_path):
    store = SnapshotStore(tmp_path)
    incomplete = store.new_snapshot("golden")
    incomplete.write_dataset("things", [])
    with pytest.raises(FileNotFoundError, match="iamai collect"):
        store.latest_snapshot("golden")

    done = store.new_snapshot("golden")
    done.write_dataset("things", [])
    done.finalize(_manifest())
    assert store.latest_snapshot("golden") == done.snapshot_dir


def test_manifest_roundtrip(tmp_path):
    store = SnapshotStore(tmp_path)
    writer = store.new_snapshot("golden")
    writer.finalize(_manifest())
    loaded = store.load_manifest(writer.snapshot_dir)
    assert loaded.alias == "golden"
    assert loaded.complete is True
    raw = json.loads((writer.snapshot_dir / "manifest.json").read_text())
    assert raw["tenantId"] == "11111111-1111-1111-1111-111111111111"


@pytest.mark.parametrize("alias", [
    "../outside",
    "..",
    ".",
    "",
    "sub/dir",
    "sub\\dir",
    "C:\\Windows\\Temp\\x",
    "C:",
])
def test_alias_dir_rejects_anything_that_is_not_a_plain_name(tmp_path, alias):
    """alias_dir() used to do an unvalidated self.data_dir / alias. On
    Windows, Path("data") / an absolute right operand discards "data"
    entirely rather than raising, so a crafted alias could name a location
    outside data/ with no error at all (AUTHZ-002). This is the backstop
    underneath the whitelist check every alias-taking command performs, so
    the guarantee holds even for a future caller that forgets it."""
    store = SnapshotStore(tmp_path)
    with pytest.raises(ValueError, match="not a valid tenant alias"):
        store.alias_dir(alias)


@pytest.mark.parametrize("alias", ["golden", "Target", "client-42", "a_b.c"])
def test_alias_dir_accepts_ordinary_names(tmp_path, alias):
    store = SnapshotStore(tmp_path)
    assert store.alias_dir(alias) == tmp_path / alias


def _snapshot_at(store, alias, collected_at):
    writer = store.new_snapshot(alias)
    writer.write_dataset("things", [])
    writer.snapshot_dir.joinpath("manifest.json").write_text(
        json.dumps({
            "tenantId": "11111111-1111-1111-1111-111111111111",
            "alias": alias,
            "collectedAt": collected_at,
            "tool": "0.1.0",
            "complete": True,
            "datasets": [],
        }),
        encoding="utf-8",
    )
    return writer.snapshot_dir


def test_snapshots_to_purge_keep_latest_counts_from_the_newest(tmp_path):
    """RETENTION-001: nothing else in this tool ever removes a collected
    snapshot, so this is the tool's one deletion decision and it needs to be
    exactly right rather than approximately right."""
    store = SnapshotStore(tmp_path)
    old = _snapshot_at(store, "golden", "2026-01-01T00:00:00Z")
    mid = _snapshot_at(store, "golden", "2026-02-01T00:00:00Z")
    new = _snapshot_at(store, "golden", "2026-03-01T00:00:00Z")

    assert store.snapshots_to_purge("golden", keep_latest=2) == [old]
    assert store.snapshots_to_purge("golden", keep_latest=1) == [old, mid]
    assert store.snapshots_to_purge("golden", keep_latest=0) == [old, mid, new]
    assert store.snapshots_to_purge("golden", keep_latest=99) == []


def test_snapshots_to_purge_older_than_reads_the_manifest_not_the_folder_name(tmp_path):
    import time

    store = SnapshotStore(tmp_path)
    long_ago = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 400 * 86400))
    recent = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1 * 86400))
    old = _snapshot_at(store, "golden", long_ago)
    new = _snapshot_at(store, "golden", recent)

    assert store.snapshots_to_purge("golden", older_than_days=30) == [old]
    assert store.snapshots_to_purge("golden", older_than_days=1000) == []
    assert new not in store.snapshots_to_purge("golden", older_than_days=30)


def test_snapshots_to_purge_with_neither_argument_means_everything(tmp_path):
    """The CLI never calls this without a mode selected; a caller that does
    gets --all's meaning rather than an exception, which is the one the
    purge command's --all uses."""
    store = SnapshotStore(tmp_path)
    a = _snapshot_at(store, "golden", "2026-01-01T00:00:00Z")
    b = _snapshot_at(store, "golden", "2026-02-01T00:00:00Z")
    assert store.snapshots_to_purge("golden") == [a, b]
