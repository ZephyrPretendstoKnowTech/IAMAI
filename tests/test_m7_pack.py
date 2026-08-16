"""M7 (V2-M2): the standard pack schema, validation, and import.

Covers the schemaVersion 2 fields (profile, citations), the validate_pack
static checks, and the 'iamai baseline import' contract. Pack content authoring
and the compliance crosswalk are exercised in their own suites.
"""

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.canon import validate_pack
from iamai.config import Config, save_config
from iamai.store import load_snapshot_data

from conftest import APP_ID, TENANT_ID
from test_m1_canon import make_artifact

pytestmark = pytest.mark.m7

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"
runner = CliRunner()


@pytest.fixture(scope="module")
def golden():
    data, _ = load_snapshot_data(FIXTURES)
    return data


def make_pack(data):
    """A tenant-free pack derived from the proven golden canonical shapes:
    slots stay declared but unbound, and every control gets a citation."""
    artifact = make_artifact(data)
    for parameter in artifact["parameters"]:
        parameter["boundGuids"] = []
    for control in artifact["controls"]:
        control["citations"] = [{"source": "CIS Microsoft 365 Foundations", "item": "1.1.1"}]
        control["profile"] = "baseline"
    artifact["builtFrom"] = {"pack": "test-standard", "tool": "test"}
    return artifact


# --- Schema fields ------------------------------------------------------------


def test_build_artifact_is_schema_version_2_with_profile_and_citation_defaults(golden):
    artifact = make_artifact(golden)
    assert artifact["schemaVersion"] == 2
    for control in artifact["controls"]:
        assert control["profile"] == "baseline"
        assert control["citations"] == []


# --- validate_pack accepts a clean pack ---------------------------------------


def test_validate_pack_accepts_a_clean_pack(golden):
    assert validate_pack(make_pack(golden)) == []


# --- validate_pack rejects each defect ----------------------------------------


def test_rejects_wrong_schema_version(golden):
    pack = make_pack(golden)
    pack["schemaVersion"] = 1
    errors = validate_pack(pack)
    assert any("schemaVersion" in e for e in errors)


def test_rejects_missing_citations(golden):
    pack = make_pack(golden)
    pack["controls"][0]["citations"] = []
    errors = validate_pack(pack)
    assert any("citation" in e for e in errors)


def test_rejects_citation_missing_source_or_item(golden):
    pack = make_pack(golden)
    pack["controls"][0]["citations"] = [{"source": "CIS", "item": ""}]
    errors = validate_pack(pack)
    assert any("source and item" in e for e in errors)


def test_rejects_unknown_profile(golden):
    pack = make_pack(golden)
    pack["controls"][0]["profile"] = "hardened"
    errors = validate_pack(pack)
    assert any("profile" in e for e in errors)


def test_rejects_bound_tenant_guids(golden):
    pack = make_pack(golden)
    pack["parameters"][0]["boundGuids"] = ["11111111-1111-1111-1111-111111111111"]
    errors = validate_pack(pack)
    assert any("tenant free" in e for e in errors)


def test_rejects_unknown_slot(golden):
    pack = make_pack(golden)
    pack["parameters"].append({"slot": "madeUpSlot", "boundGuids": []})
    errors = validate_pack(pack)
    assert any("Unknown parameter slot" in e for e in errors)


def test_rejects_tenant_group_token_in_canonical(golden):
    pack = make_pack(golden)
    # A tenant object id smuggled into a canonical form must be caught.
    control = pack["controls"][0]
    control["canonical"] = copy.deepcopy(control["canonical"])
    control["canonical"]["leak"] = "group:99999999-9999-9999-9999-999999999999"
    errors = validate_pack(pack)
    assert any("tenant group" in e for e in errors)


def test_rejects_raw_cidr_ranges_in_canonical(golden):
    pack = make_pack(golden)
    control = pack["controls"][0]
    control["canonical"] = copy.deepcopy(control["canonical"])
    control["canonical"]["content"] = {"cidrs": ["203.0.113.0/24"], "isTrusted": True}
    errors = validate_pack(pack)
    assert any("raw IP ranges" in e for e in errors)


def test_universal_constants_and_role_ids_are_allowed(golden):
    pack = make_pack(golden)
    control = pack["controls"][0]
    control["canonical"] = copy.deepcopy(control["canonical"])
    # A built-in strength id and a directory role template id are universal.
    control["canonical"]["strengthRef"] = "00000000-0000-0000-0000-000000000004"
    control["canonical"]["roleRef"] = "role:62e90394-69f5-4237-9190-012177145e10"
    assert validate_pack(pack) == []


# --- CLI: iamai baseline import -----------------------------------------------


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    save_config(
        Config(
            appId=APP_ID,
            homeTenantId=TENANT_ID,
            certPath="certs/iamai.pem",
            goldenTenantId=TENANT_ID,
            tenants={"golden": TENANT_ID, "target": TENANT_ID},
        ),
        tmp_path / "config.yaml",
    )
    return tmp_path


def _write_pack(workspace, pack):
    packs = workspace / "packs"
    packs.mkdir(exist_ok=True)
    path = packs / "standard-test.json"
    path.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    return path


def test_import_valid_pack_freezes_active_baseline(workspace, golden):
    path = _write_pack(workspace, make_pack(golden))
    result = runner.invoke(cli.app, ["baseline", "import", str(path)])
    assert result.exit_code == 0, result.output
    frozen = workspace / "baselines" / "baseline-v1.json"
    assert frozen.exists()
    artifact = json.loads(frozen.read_text(encoding="utf-8"))
    assert artifact["schemaVersion"] == 2
    assert "baseline" in result.output


def test_import_invalid_pack_is_rejected_and_freezes_nothing(workspace, golden):
    pack = make_pack(golden)
    pack["controls"][0]["citations"] = []
    path = _write_pack(workspace, pack)
    result = runner.invoke(cli.app, ["baseline", "import", str(path)])
    assert result.exit_code == 1
    assert not (workspace / "baselines").exists() or not list(
        (workspace / "baselines").glob("*.json")
    )


def test_import_missing_file_exits_nonzero(workspace):
    result = runner.invoke(cli.app, ["baseline", "import", "packs/nope.json"])
    assert result.exit_code == 1


# --- The committed standard pack: proven-deployable checkpoint proxy ----------

REPO_PACK = Path(__file__).resolve().parents[1] / "packs" / "standard-v1.json"


def test_committed_standard_pack_validates():
    pack = json.loads(REPO_PACK.read_text(encoding="utf-8"))
    assert validate_pack(pack) == []
    assert all(c["profile"] == "baseline" for c in pack["controls"])


def test_committed_standard_pack_grades_the_golden_fixtures_all_full(golden):
    from iamai.grade import assess_snapshot

    data, manifest = load_snapshot_data(FIXTURES)
    pack = json.loads(REPO_PACK.read_text(encoding="utf-8"))
    guids = []
    for cap in data["conditional_access_policies"]:
        users = (cap.get("conditions") or {}).get("users") or {}
        guids += (users.get("excludeGroups") or []) + (users.get("excludeUsers") or [])
    assessment = assess_snapshot(
        pack, data, manifest, tenant_id="lab", alias="lab",
        snapshot_dir=FIXTURES, answer_bindings={"breakGlassAccounts": sorted(set(guids))},
    )
    grades = {r["grade"] for r in assessment["controls"]}
    assert grades == {"FULL"}, [
        (r["controlId"], r["grade"]) for r in assessment["controls"] if r["grade"] != "FULL"
    ]
    assert assessment["gradeCounts"].get("UNKNOWN", 0) == 0
    assert assessment["surplus"] == []


# --- Compliance crosswalk -----------------------------------------------------


def test_crosswalk_status_is_conservative():
    from iamai.report import _crosswalk_status

    assert _crosswalk_status({"FULL"}) == "meets"
    assert _crosswalk_status({"FULL", "FUNCTIONAL"}) == "meets"
    assert _crosswalk_status({"FULL", "PARTIAL"}) == "partially meets"
    assert _crosswalk_status({"FULL", "UNKNOWN"}) == "not assessed"
    assert _crosswalk_status({"MISSING", "UNKNOWN"}) == "misses"


def test_crosswalk_groups_by_source_and_counts_statuses():
    from iamai.report import _compliance_crosswalk

    controls = [
        {"grade": "FULL", "citations": [{"source": "CIS", "item": "1.1"}]},
        {"grade": "MISSING", "citations": [{"source": "CIS", "item": "1.2"}]},
        {"grade": "PARTIAL", "citations": [{"source": "SCuBA", "item": "MS.AAD.1"}]},
        {"grade": "FULL", "citations": [{"source": "CIS", "item": "1.1"}]},
    ]
    crosswalk = _compliance_crosswalk(controls)
    by_source = {row["source"]: row for row in crosswalk}
    assert by_source["CIS"]["counts"]["meets"] == 1
    assert by_source["CIS"]["counts"]["misses"] == 1
    assert by_source["SCuBA"]["counts"]["partially meets"] == 1
    # Same item cited by two FULL controls collapses to one meets row.
    items = [row["item"] for row in by_source["CIS"]["rows"]]
    assert items == ["1.1", "1.2"]


def test_report_renders_the_crosswalk_section():
    from iamai.grade import assess_snapshot
    from iamai.report import render_assessment

    data, manifest = load_snapshot_data(FIXTURES)
    pack = json.loads(REPO_PACK.read_text(encoding="utf-8"))
    guids = []
    for cap in data["conditional_access_policies"]:
        users = (cap.get("conditions") or {}).get("users") or {}
        guids += (users.get("excludeGroups") or []) + (users.get("excludeUsers") or [])
    assessment = assess_snapshot(
        pack, data, manifest, tenant_id="lab", alias="lab",
        snapshot_dir=FIXTURES, answer_bindings={"breakGlassAccounts": sorted(set(guids))},
    )
    html = render_assessment(assessment, manifest)
    assert "Compliance crosswalk" in html
    # The committed pack uses PLACEHOLDER-sourced citations for now.
    assert "PLACEHOLDER" in html
    assert "meets" in html
