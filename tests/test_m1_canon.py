"""M1: canonicalization, description parsing, artifact construction."""

import json
from pathlib import Path

import pytest

from iamai.canon import (
    SlotResolver,
    build_artifact,
    canonical_cap,
    combos_set,
    control_signature,
    parse_description,
    required_state,
    strength_at_least_as_strong,
)
from iamai.store import load_snapshot_data

pytestmark = pytest.mark.m1

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"


@pytest.fixture(scope="module")
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return data, manifest


def _bindings(data) -> dict:
    guids = []
    for cap in data["conditional_access_policies"]:
        users = (cap.get("conditions") or {}).get("users") or {}
        guids.extend(users.get("excludeGroups") or [])
        guids.extend(users.get("excludeUsers") or [])
    return {"breakGlassAccounts": sorted(set(guids))}


def make_artifact(data, **overrides):
    kwargs = dict(
        tenant_id="tenant-under-test",
        snapshot="fixture",
        tool_version="0.1.0",
        slot_bindings=_bindings(data),
    )
    kwargs.update(overrides)
    return build_artifact(data, **kwargs)


def test_description_convention_parses_and_strips_forbidden_lines():
    text = (
        "Tag: BL-CORE\n"
        "Version: 3\n"
        "Date: 2026-05-01\n"
        "Purpose: Require strong sign in for administrators.\n"
        "Scope: All admin role holders.\n"
        "Rationale: Admin accounts are the highest value target.\n"
        "Owner: Identity Team\n"
    )
    parsed = parse_description(text)
    assert parsed["parsed"] is True
    assert parsed["intent"] == "Require strong sign in for administrators."
    assert parsed["rationale"] == "Admin accounts are the highest value target."
    blob = json.dumps(parsed)
    assert "BL-CORE" not in blob
    assert "Identity Team" not in blob


def test_unparseable_description_falls_back():
    assert parse_description(None)["parsed"] is False
    assert parse_description("free text with no convention")["parsed"] is False


def test_combination_sets_normalize_order():
    assert combos_set(["sms,password", "fido2"]) == ["fido2", "password,sms"]
    assert strength_at_least_as_strong(["fido2"], ["fido2", "password,sms"])
    assert not strength_at_least_as_strong(["fido2", "password,sms"], ["fido2"])


def test_canonical_cap_drops_names_and_resolves_slots(golden):
    data, _ = golden
    cap = next(
        c for c in data["conditional_access_policies"]
        if c["displayName"] == "Core - Allow - MFA for Internal Users"
    )
    resolver = SlotResolver(_bindings(data))
    canonical = canonical_cap(
        cap, resolver, data["named_locations"], data["auth_strengths"]
    )
    blob = json.dumps(canonical)
    assert cap["id"] not in blob
    assert "Core - Allow" not in blob
    assert any(t == "slot:breakGlassAccounts" for t in canonical["users"]["exclude"])
    assert canonical["users"]["include"] == ["All"]
    assert canonical["category"] == "require"
    assert canonical["grant"]["strengthCombos"]


def test_unbound_guid_stays_flagged_not_slotted(golden):
    data, _ = golden
    cap = next(
        c for c in data["conditional_access_policies"]
        if c["displayName"] == "Core - Allow - MFA for Internal Users"
    )
    canonical = canonical_cap(cap, SlotResolver({}), [], data["auth_strengths"])
    excludes = canonical["users"]["exclude"]
    # With no bindings the tenant GUID stays a flagged raw token, never a slot.
    assert not any(t.startswith("slot:") for t in excludes)
    assert any(t.startswith("group:") for t in excludes)


def test_required_state_mapping():
    assert required_state("enabled") == "enabled"
    assert required_state("enabledForReportingButNotEnforced") == "enabledOrReportOnly"


def test_artifact_shape_and_catalog_coverage(golden):
    data, _ = golden
    artifact = make_artifact(data)
    assert artifact["schemaVersion"] == 2
    slots = {p["slot"] for p in artifact["parameters"]}
    assert slots == {
        "breakGlassAccounts",
        "trustedLocations",
        "serviceAccounts",
        "pilotGroups",
        "onboardingGroups",
    }

    by_surface: dict[str, int] = {}
    for control in artifact["controls"]:
        by_surface[control["surface"]] = by_surface.get(control["surface"], 0) + 1
    assert by_surface["conditionalAccess"] == 6
    assert by_surface["authenticationStrength"] == 3
    assert by_surface["registrationCampaign"] == 1
    assert by_surface["authMethods"] >= 8

    caps = [c for c in artifact["controls"] if c["surface"] == "conditionalAccess"]
    # Empty golden descriptions: the static intent catalog must cover all six
    # shapes so nothing is flagged for manual intent text.
    assert all(not c["needsIntentText"] for c in caps)
    assert all(c["intent"] for c in caps)
    assert all(c["requiredState"] == "enabledOrReportOnly" for c in caps)
    signatures = {control_signature(c["canonical"]) for c in caps}
    assert signatures == {
        "cap:admin-mfa", "cap:user-mfa", "cap:block-legacy-auth",
        "cap:block-device-code", "cap:block-auth-transfer", "cap:token-protection",
    }
    assert "IAMAI" not in json.dumps(artifact)


def test_curation_exclusion_drops_controls(golden):
    data, _ = golden
    full = make_artifact(data)
    drop = full["controls"][0]["id"]
    curated = make_artifact(data, exclude_control_ids={drop})
    ids = {c["id"] for c in curated["controls"]}
    assert drop not in ids
    assert len(curated["controls"]) == len(full["controls"]) - 1
