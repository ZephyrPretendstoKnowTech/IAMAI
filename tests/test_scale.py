"""Pipeline-at-scale guard.

`collect` is decoupled from `assess`/`report`/`sanitize`, so a manufactured
heavy snapshot exercises the whole downstream pipeline at a volume a small or
already-configured test tenant cannot provide. This is the regression guard for
a shipped-blocker the heavy-snapshot scale run found: `iamai sanitize` used to
raise the moment a snapshot held more than 508 distinct IPv4 addresses, which a
real 30-day sign-in feed passes easily, so sharing a report crashed on virtually
every real tenant.

The check runs the real `sanitize_snapshot` over the real gz feeds, so it guards
the integration, not just the `map_ip` unit. It stays small enough to run in the
normal suite while still crossing the 508-address boundary.
"""

import gzip
import json
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.m0

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from synth_snapshot import build  # noqa: E402

PACK = json.loads((ROOT / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8"))


def _distinct_ips(feed: Path) -> set[str]:
    with gzip.open(feed, "rt", encoding="utf-8") as handle:
        return {json.loads(line)["ipAddress"] for line in handle}


def test_full_pipeline_survives_a_heavy_snapshot(tmp_path):
    from iamai.grade import assess_snapshot
    from iamai.report import render_assessment
    from iamai.sanitize import sanitize_snapshot
    from iamai.store import load_snapshot_data

    snap = build(tmp_path / "heavy", n_users=400, n_signins=2000, n_sps=60, n_groups=30)

    # Precondition: the feed really does exceed the old 508-address ceiling, or
    # this would not be testing the boundary at all.
    raw = snap / "raw"
    distinct = _distinct_ips(raw / "signins_interactive.jsonl.gz") | _distinct_ips(
        raw / "signins_noninteractive.jsonl.gz"
    )
    assert len(distinct) > 508, f"only {len(distinct)} distinct IPs; not crossing the boundary"

    # assess + render must handle the volume and produce a real graded result.
    data, manifest = load_snapshot_data(snap)
    assessment = assess_snapshot(
        PACK, data, manifest, tenant_id="heavy-t", alias="heavy", snapshot_dir=snap
    )
    assert assessment["controls"], "no controls graded"
    assert sum(assessment["gradeCounts"].values()) == len(assessment["controls"])
    html = render_assessment(assessment, manifest)
    assert 'class="brandbar"' in html

    # The blocker: sanitize must complete over a feed with >508 distinct IPs.
    out = sanitize_snapshot(snap, tmp_path / "pseudo_map.json")

    # And it must stay honest: distinct real IPs map to distinct tokens (no
    # collision), overflowing past the documentation ranges into 198.18.0.0/15.
    sanitized = _distinct_ips(out / "signins_interactive.jsonl.gz") | _distinct_ips(
        out / "signins_noninteractive.jsonl.gz"
    )
    assert len(sanitized) == len(distinct), "pseudonymised IPs collided"
    assert any(ip.startswith(("198.18.", "198.19.")) for ip in sanitized), "overflow range unused"
    assert all(
        ip.startswith(("203.0.113.", "198.51.100.", "198.18.", "198.19.")) for ip in sanitized
    )
