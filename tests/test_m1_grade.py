"""M1: the parity engine mutation suite (SPEC section 11).

Programmatic mutations of the sanitized golden fixtures with expected grades,
at least two per grade. This suite is the permanent regression test.
"""

import copy
import json
import random
from pathlib import Path

import pytest

from iamai.grade import FULL, FUNCTIONAL, MISSING, PARTIAL, SURPLUS, UNKNOWN, assess_snapshot
from iamai.store import load_snapshot_data
from test_m1_canon import make_artifact

pytestmark = pytest.mark.m1

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"

ADMIN_MFA = "Core - Allow - MFA for Admins"
USER_MFA = "Core - Allow - MFA for Internal Users"
BLOCK_LEGACY = "Core - Block - Legacy Authentication"
BLOCK_DEVICE_CODE = "Core - Block - Device Code Flow"
TOKEN_PROTECTION = "Core - Require - Token Protection (Windows)"

# The built-in MFA strength allows every ordinary MFA combination: strictly
# weaker than the phishing-resistant set the golden MFA policies require.
WEAK_COMBOS_SOURCE = "Multifactor authentication"


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


def cap_named(data, name):
    return next(c for c in data["conditional_access_policies"] if c["displayName"] == name)


def control_for_cap(artifact, name):
    return next(
        c for c in artifact["controls"]
        if c["surface"] == "conditionalAccess" and c["sourceName"] == name
    )


def run(artifact, data, manifest, **kwargs):
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target",
        snapshot_dir=kwargs.pop("snapshot_dir", FIXTURES),
        **kwargs,
    )


def grades_by_control(assessment):
    return {r["controlId"]: r for r in assessment["controls"]}


# --- Acceptance anchor: golden against its own artifact -----------------------


def test_golden_self_assessment_is_all_full_zero_unknown_zero_noise(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    assessment = run(artifact, data, manifest)
    grades = {r["grade"] for r in assessment["controls"]}
    assert grades == {FULL}, [
        (r["controlId"], r["grade"], r["coverageGaps"], r["notes"])
        for r in assessment["controls"] if r["grade"] != FULL
    ]
    assert assessment["gradeCounts"].get(UNKNOWN, 0) == 0
    assert assessment["surplus"] == []
    assert all(r["tenantId"] == "target-tenant" for r in assessment["controls"])


# --- FULL stays FULL ----------------------------------------------------------


def test_rename_only_stays_full(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    for index, cap in enumerate(data["conditional_access_policies"]):
        cap["displayName"] = f"Totally Different Name {index}"
    for index, strength in enumerate(data["auth_strengths"]):
        strength["displayName"] = f"Renamed Strength {index}"
    assessment = run(artifact, data, manifest)
    assert {r["grade"] for r in assessment["controls"]} == {FULL}


def test_reordering_arrays_stays_full(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    rng = random.Random(42)
    rng.shuffle(data["conditional_access_policies"])
    for cap in data["conditional_access_policies"]:
        users = cap["conditions"]["users"]
        if users.get("includeRoles"):
            rng.shuffle(users["includeRoles"])
        strength = (cap.get("grantControls") or {}).get("authenticationStrength")
        if strength and strength.get("allowedCombinations"):
            rng.shuffle(strength["allowedCombinations"])
    assessment = run(artifact, data, manifest)
    assert {r["grade"] for r in assessment["controls"]} == {FULL}


# --- FUNCTIONAL ----------------------------------------------------------------


def test_equivalent_split_grades_functional(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    original = cap_named(data, ADMIN_MFA)
    roles = original["conditions"]["users"]["includeRoles"]
    half = len(roles) // 2
    first, second = copy.deepcopy(original), copy.deepcopy(original)
    first["id"], first["displayName"] = "split-a", "Split A"
    first["conditions"]["users"]["includeRoles"] = roles[:half]
    second["id"], second["displayName"] = "split-b", "Split B"
    second["conditions"]["users"]["includeRoles"] = roles[half:]
    data["conditional_access_policies"] = [
        c for c in data["conditional_access_policies"] if c["displayName"] != ADMIN_MFA
    ] + [first, second]

    result = grades_by_control(run(artifact, data, manifest))[
        control_for_cap(artifact, ADMIN_MFA)["id"]
    ]
    assert result["grade"] == FUNCTIONAL
    assert len(result["matchedPolicies"]) == 2
    # PUB-M0: construction differences are structural findings on their own
    # axis, never gaps and never notes (SPEC-PUBLIC section 2).
    assert any("policies working together" in s for s in result["structural"])
    assert result["coverageGaps"] == []


def test_strict_superset_scope_grades_functional(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    cap = cap_named(data, ADMIN_MFA)
    cap["conditions"]["users"]["includeRoles"] = []
    cap["conditions"]["users"]["includeUsers"] = ["All"]

    result = grades_by_control(run(artifact, data, manifest))[
        control_for_cap(artifact, ADMIN_MFA)["id"]
    ]
    assert result["grade"] == FUNCTIONAL
    assert any("wider group of people" in s for s in result["structural"])
    assert result["coverageGaps"] == []


# --- PARTIAL --------------------------------------------------------------------


def test_unsanctioned_exclusion_grades_partial(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    cap = cap_named(data, USER_MFA)
    cap["conditions"]["users"]["excludeUsers"] = ["99999999-9999-9999-9999-999999999999"]

    result = grades_by_control(run(artifact, data, manifest))[
        control_for_cap(artifact, USER_MFA)["id"]
    ]
    assert result["grade"] == PARTIAL
    assert any("Unsanctioned exclusions" in g for g in result["coverageGaps"])


def test_weakened_strength_grades_partial(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    weak = next(
        s["allowedCombinations"] for s in data["auth_strengths"]
        if s["displayName"] == WEAK_COMBOS_SOURCE
    )
    cap = cap_named(data, ADMIN_MFA)
    cap["grantControls"]["authenticationStrength"]["allowedCombinations"] = list(weak)

    result = grades_by_control(run(artifact, data, manifest))[
        control_for_cap(artifact, ADMIN_MFA)["id"]
    ]
    assert result["grade"] == PARTIAL
    assert any("weaker" in g.lower() for g in result["coverageGaps"] + result["notes"])


def test_report_only_where_baseline_enforces_grades_partial(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    control = control_for_cap(artifact, USER_MFA)
    control["requiredState"] = "enabled"  # the standard enforces

    result = grades_by_control(run(artifact, data, manifest))[control["id"]]
    assert result["grade"] == PARTIAL
    assert any("report-only" in g for g in result["coverageGaps"])


def test_weakened_method_state_grades_partial(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    methods = data["auth_methods_policy"]["authenticationMethodConfigurations"]
    sms = next(m for m in methods if m["id"] == "Sms")
    assert sms["state"] == "disabled"
    sms["state"] = "enabled"

    result = grades_by_control(run(artifact, data, manifest))["method-Sms"]
    assert result["grade"] == PARTIAL
    assert any("Sms" in g for g in result["coverageGaps"])


# --- MISSING --------------------------------------------------------------------


def test_deleted_block_policy_grades_missing(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    data["conditional_access_policies"] = [
        c for c in data["conditional_access_policies"] if c["displayName"] != BLOCK_LEGACY
    ]
    result = grades_by_control(run(artifact, data, manifest))[
        control_for_cap(artifact, BLOCK_LEGACY)["id"]
    ]
    assert result["grade"] == MISSING


def test_deleted_session_policy_grades_missing(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    data["conditional_access_policies"] = [
        c for c in data["conditional_access_policies"] if c["displayName"] != TOKEN_PROTECTION
    ]
    result = grades_by_control(run(artifact, data, manifest))[
        control_for_cap(artifact, TOKEN_PROTECTION)["id"]
    ]
    assert result["grade"] == MISSING


# --- UNKNOWN --------------------------------------------------------------------


def test_truncated_cap_pull_grades_unknown(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    for record in manifest["datasets"]:
        if record["dataset"] == "conditional_access_policies":
            record["complete"] = False
    assessment = run(artifact, data, manifest)
    cap_grades = {
        r["grade"] for r in assessment["controls"] if r["surface"] == "conditionalAccess"
    }
    assert cap_grades == {UNKNOWN}
    assert any("incomplete" in u for u in assessment["unknowns"])


def test_missing_strengths_dataset_grades_unknown(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    data["auth_strengths"] = None
    strength_grades = {
        r["grade"] for r in run(artifact, data, manifest)["controls"]
        if r["surface"] == "authenticationStrength"
    }
    assert strength_grades == {UNKNOWN}


# --- SURPLUS --------------------------------------------------------------------


def test_extra_policy_is_listed_as_surplus_never_penalized(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    extra = copy.deepcopy(cap_named(data, BLOCK_LEGACY))
    extra["id"] = "extra-0001"
    extra["displayName"] = "Extra - Block One App"
    extra["conditions"]["applications"]["includeApplications"] = [
        "00000002-0000-0ff1-ce00-000000000000"
    ]
    data["conditional_access_policies"].append(extra)

    assessment = run(artifact, data, manifest)
    baseline_grades = {r["grade"] for r in assessment["controls"]}
    assert baseline_grades == {FULL}
    assert any(s["id"] == "extra-0001" for s in assessment["surplus"])
    assert all("penal" not in json.dumps(s).lower() or "Not penalized" in s["note"] for s in assessment["surplus"])


def test_extra_custom_strength_is_listed_as_surplus(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    data["auth_strengths"].append({
        "id": "aaaa1111-0000-0000-0000-000000000001",
        "displayName": "Custom Weak Strength",
        "policyType": "custom",
        "allowedCombinations": ["password,sms"],
    })
    assessment = run(artifact, data, manifest)
    assert {r["grade"] for r in assessment["controls"]} == {FULL}
    surplus_types = {s["type"] for s in assessment["surplus"]}
    assert "authenticationStrength" in surplus_types
