"""M6 (V2-M1): parameterized named locations.

A trusted IP named location must grade by the trustedLocations parameter slot,
not by raw range comparison, so a target tenant with its own trusted networks
matches the baseline even though the addresses differ. The golden tenant has no
named locations, so these cases build synthetic snapshots.
"""

import json

import pytest

from iamai.canon import SlotResolver, build_artifact, canonical_cap, canonical_location
from iamai.grade import FULL, MISSING, assess_snapshot
from iamai.plan import generate_plan
from iamai.questions import Answer, AnswersFile

pytestmark = pytest.mark.m6

GOLDEN_LOC = "11111111-1111-1111-1111-111111111111"
TARGET_LOC = "22222222-2222-2222-2222-222222222222"
COUNTRY_LOC = "33333333-3333-3333-3333-333333333333"


def ip_location(guid, cidrs, *, trusted=True, name="Office network"):
    return {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "id": guid,
        "displayName": name,
        "isTrusted": trusted,
        "ipRanges": [
            {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": c}
            for c in cidrs
        ],
    }


def country_location(guid, countries, *, name="Allowed countries"):
    return {
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "id": guid,
        "displayName": name,
        "countriesAndRegions": countries,
        "includeUnknownCountriesAndRegions": False,
    }


def snapshot(named_locations, caps=None):
    return {
        "conditional_access_policies": caps or [],
        "named_locations": named_locations,
        "auth_strengths": [],
        "auth_methods_policy": {},
    }


def build_golden(named_locations, caps=None):
    return build_artifact(
        snapshot(named_locations, caps),
        tenant_id="golden",
        snapshot="fixture",
        tool_version="0.1.0",
    )


def grade(artifact, data, **kwargs):
    return assess_snapshot(
        artifact, data, None,
        tenant_id="target-tenant", alias="target",
        **kwargs,
    )


def location_result(assessment):
    return next(
        r for r in assessment["controls"] if r["controlId"].startswith("location-")
    )


# --- Canonicalization ---------------------------------------------------------


def test_bound_trusted_location_canonicalizes_to_slot_not_ranges():
    loc = ip_location(GOLDEN_LOC, ["203.0.113.0/24"])
    resolver = SlotResolver({"trustedLocations": [GOLDEN_LOC]})
    assert canonical_location(loc, resolver) == {"slot": "trustedLocations"}


def test_unbound_ip_location_keeps_raw_ranges():
    loc = ip_location(GOLDEN_LOC, ["203.0.113.0/24"])
    content = canonical_location(loc, SlotResolver({}))
    assert content == {"cidrs": ["203.0.113.0/24"], "isTrusted": True}


def test_country_location_stays_content_compared_even_when_a_slot_exists():
    # Country membership is universal, so it never routes through the slot.
    loc = country_location(COUNTRY_LOC, ["US", "AU"])
    resolver = SlotResolver({"trustedLocations": [COUNTRY_LOC]})
    assert canonical_location(loc, resolver) == {
        "countries": ["AU", "US"],
        "includeUnknown": False,
    }


# --- Build side ---------------------------------------------------------------


def test_build_auto_binds_golden_trusted_location_and_hides_ranges():
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"])])
    control = next(c for c in artifact["controls"] if c["surface"] == "namedLocation")
    assert control["canonical"]["content"] == {"slot": "trustedLocations"}
    params = {p["slot"]: p["boundGuids"] for p in artifact["parameters"]}
    assert params["trustedLocations"] == [GOLDEN_LOC]
    assert "203.0.113.0/24" not in json.dumps(artifact)


def test_build_leaves_untrusted_ip_location_as_ranges():
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"], trusted=False)])
    control = next(c for c in artifact["controls"] if c["surface"] == "namedLocation")
    assert control["canonical"]["content"] == {
        "cidrs": ["203.0.113.0/24"],
        "isTrusted": False,
    }
    params = {p["slot"]: p["boundGuids"] for p in artifact["parameters"]}
    assert params["trustedLocations"] == []


# --- Grading: the core cross-tenant case --------------------------------------


def test_target_trusted_location_with_different_ranges_grades_full():
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"])])
    target = snapshot([ip_location(TARGET_LOC, ["198.51.100.0/22", "10.0.0.0/8"])])
    assessment = grade(artifact, target, answer_bindings={"trustedLocations": [TARGET_LOC]})
    assert location_result(assessment)["grade"] == FULL


def test_target_trusted_location_without_the_answer_stays_missing():
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"])])
    target = snapshot([ip_location(TARGET_LOC, ["198.51.100.0/22"])])
    # No trustedLocations answer: the ranges differ and nothing binds them.
    assessment = grade(artifact, target)
    assert location_result(assessment)["grade"] == MISSING


def test_target_with_no_locations_at_all_is_missing_not_matched():
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"])])
    assessment = grade(artifact, snapshot([]), answer_bindings={"trustedLocations": [TARGET_LOC]})
    assert location_result(assessment)["grade"] == MISSING


# --- Grading: a CAP condition that references the trusted location ------------


def cap_with_trusted_location(guid, loc_guid):
    return {
        "id": guid,
        "displayName": "Require compliant device from untrusted networks",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": []},
            "applications": {"includeApplications": ["All"]},
            "locations": {"includeLocations": ["All"], "excludeLocations": [loc_guid]},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["compliantDevice"]},
    }


def test_cap_location_condition_matches_across_tenants_by_slot():
    golden_cap = cap_with_trusted_location("cap-g", GOLDEN_LOC)
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"])], caps=[golden_cap])

    target_cap = cap_with_trusted_location("cap-t", TARGET_LOC)
    target = snapshot([ip_location(TARGET_LOC, ["198.51.100.0/22"])], caps=[target_cap])
    assessment = grade(artifact, target, answer_bindings={"trustedLocations": [TARGET_LOC]})
    cap_result = next(
        r for r in assessment["controls"] if r["controlId"].startswith("cap-")
    )
    assert cap_result["grade"] == FULL


def test_cap_location_reference_canonicalizes_to_slot():
    cap = cap_with_trusted_location("cap-g", GOLDEN_LOC)
    resolver = SlotResolver({"trustedLocations": [GOLDEN_LOC]})
    canonical = canonical_cap(cap, resolver, [ip_location(GOLDEN_LOC, ["203.0.113.0/24"])], [])
    assert canonical["locations"]["exclude"] == [{"slot": "trustedLocations"}]
    assert "203.0.113.0/24" not in json.dumps(canonical)


# --- Plan: the create-location step reflects slot matching --------------------


def _answers_with_trusted(cidr):
    return AnswersFile(
        tenantId="target-tenant",
        alias="target",
        answers={
            "q-trusted": Answer(
                questionId="q-trusted",
                answerType="selectLocations",
                bindsTo="trustedLocations",
                value=[cidr],
                answeredAt="2026-07-24T00:00:00Z",
            )
        },
    )


def test_plan_location_step_marks_trusted_and_drops_the_stale_never_match_note():
    artifact = build_golden([ip_location(GOLDEN_LOC, ["203.0.113.0/24"])])
    # Target lacks the location, so the control is MISSING and a step is built.
    assessment = grade(artifact, snapshot([]))
    plan = generate_plan(
        assessment, _answers_with_trusted("198.51.100.0/24"), artifact, snapshot([]),
        tenant_id="target-tenant", alias="target",
    )
    step = next(
        s for s in plan["steps"] if str(s.get("controlId", "")).startswith("location-")
    )
    actions = " ".join(step["actions"])
    assert "Mark as trusted location" in actions
    watch = " ".join(step["watchFor"])
    assert "can differ from the standard's ranges" not in watch
    assert "trusted role" in watch
