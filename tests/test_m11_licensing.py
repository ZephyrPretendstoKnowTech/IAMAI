"""PUB-M1: licensing aware grading (SPEC-PUBLIC section 6).

A tenant is never graded against a control its licensing cannot support, and
absence of a licence is only ever concluded from data that proves it.
"""

import copy
from pathlib import Path

import pytest

from iamai.grade import FULL, assess_snapshot, detected_licensing
from iamai.store import load_snapshot_data
from test_m1_canon import make_artifact

pytestmark = pytest.mark.m11

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


def run(artifact, data, manifest):
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )


def set_service_plans(data, names):
    data["org_licenses"] = {
        "subscribedSkus": [
            {
                "skuPartNumber": "TEST",
                "servicePlans": [{"servicePlanName": name} for name in names],
            }
        ]
    }


def test_a_control_the_tenant_cannot_license_is_not_graded(golden):
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    for control in artifact["controls"]:
        control["licenseRequirement"] = "P2"
    set_service_plans(data, ["AAD_PREMIUM"])  # P1 only

    assessment = run(artifact, data, manifest)
    assert assessment["controls"] == []
    assert sum(assessment["gradeCounts"].values()) == 0
    assert len(assessment["outOfReach"]) == len(artifact["controls"])


def test_out_of_reach_entries_say_what_is_needed_and_blame_nobody(golden):
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    artifact["controls"][0]["licenseRequirement"] = "P2"
    set_service_plans(data, ["AAD_PREMIUM"])

    entry = run(artifact, data, manifest)["outOfReach"][0]
    assert entry["requires"] == "P2"
    assert "Entra ID P2" in entry["note"]
    # SPEC-PUBLIC section 6: the report never implies the tenant is insecure
    # for lacking a licence it was never told it needed.
    assert "not counted in the grades" in entry["note"]
    assert "failing" in entry["note"]


def test_a_licensed_control_is_still_graded(golden):
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    set_service_plans(data, ["AAD_PREMIUM", "AAD_PREMIUM_P2"])

    assessment = run(artifact, data, manifest)
    assert assessment["outOfReach"] == []
    assert {r["grade"] for r in assessment["controls"]} == {FULL}


def test_a_mitigation_is_offered_only_when_the_pack_authored_one(golden):
    """A licensed alternative is real advice, so it comes from the pack rather
    than being invented at grading time. Where none is authored the report
    says so instead of implying one exists (SPEC-PUBLIC section 6 point 5)."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    artifact["controls"][0]["licenseRequirement"] = "P2"
    artifact["controls"][1]["licenseRequirement"] = "P2"
    artifact["controls"][1]["mitigation"] = "Require a second step for everyone, always."
    set_service_plans(data, ["AAD_PREMIUM"])

    by_id = {e["controlId"]: e for e in run(artifact, data, manifest)["outOfReach"]}
    assert by_id[artifact["controls"][0]["id"]]["mitigation"] == ""
    assert "second step" in by_id[artifact["controls"][1]["id"]]["mitigation"]


def test_absence_of_licence_data_never_excuses_a_control(golden):
    """Excluding a control because the licence pull is missing would quietly
    raise the score. Absence has to be proven, not assumed."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    for control in artifact["controls"]:
        control["licenseRequirement"] = "P2"
    data["org_licenses"] = {}

    assessment = run(artifact, data, manifest)
    assert assessment["outOfReach"] == []
    assert assessment["controls"], "controls must still be graded"
    assert detected_licensing(data)["known"] is False
