"""PUB-M0: effect based grading (SPEC-PUBLIC sections 2 to 5).

Permanent regression suite for the three defects the V2-M2 live checkpoint
found on 2026-08-14, each proven against real tenant data. Each defect made
a correctly configured tenant look non-compliant, so each one gets a test that
fails if the old behavior returns.
"""

import copy
from pathlib import Path

import pytest

from iamai.grade import FULL, FUNCTIONAL, MISSING, PARTIAL, assess_snapshot
from iamai.store import load_snapshot_data
from test_m1_canon import make_artifact

pytestmark = pytest.mark.m10

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"

ADMIN_MFA = "Core - Allow - MFA for Admins"
USER_MFA = "Core - Allow - MFA for Internal Users"
TOKEN_PROTECTION = "Core - Require - Token Protection (Windows)"
WEAK_STRENGTH = "Multifactor authentication"

# An opaque group id the snapshot cannot resolve, standing in for the break
# glass exclusion every real tenant carries.
BREAK_GLASS_GROUP = "11111111-2222-3333-4444-555555555555"


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


def run(artifact, data, manifest):
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )


def result_for(artifact, data, manifest, name):
    assessment = run(artifact, data, manifest)
    control_id = control_for_cap(artifact, name)["id"]
    return assessment, next(r for r in assessment["controls"] if r["controlId"] == control_id)


def weak_strength(data):
    """The built-in MFA strength: allows every ordinary combination, so it is
    strictly weaker than the phishing-resistant set the golden policies use."""
    return next(s for s in data["auth_strengths"] if s["displayName"] == WEAK_STRENGTH)


def broaden_population(cap):
    """Break the exact structural match so stage 2 does the grading."""
    cap["conditions"]["users"]["includeRoles"] = []
    cap["conditions"]["users"]["includeUsers"] = ["All"]


# --- Defect 1: Conditional Access is additive ---------------------------------


def test_weak_overlapping_policy_does_not_drag_down_a_strong_one(golden):
    """The checkpoint defect. Entra requires every applicable policy to be
    satisfied, so a broader requirement alongside a narrower one cannot weaken
    the outcome. The tenant is protected; the grade must say so."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap = cap_named(data, ADMIN_MFA)
    # An opaque group exclusion, exactly how a real tenant carves out its break
    # glass accounts. It keeps the control off a clean pass, which is the state
    # in which the old engine surfaced the spurious weakness.
    cap["conditions"]["users"]["excludeGroups"] = [BREAK_GLASS_GROUP]

    weak = copy.deepcopy(cap)
    weak["id"] = "weak-overlap-0001"
    weak["displayName"] = "Some other MFA policy"
    weak["grantControls"]["authenticationStrength"] = weak_strength(data)
    data["conditional_access_policies"].append(weak)

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] == PARTIAL
    assert any("nsanctioned" in g for g in result["coverageGaps"]), result["coverageGaps"]
    assert not any("weaker" in g.lower() for g in result["coverageGaps"]), result["coverageGaps"]


def test_several_weak_overlapping_policies_still_do_not_accumulate_gaps(golden):
    """Before the fix each overlapping policy appended its own gap, so the
    report got noisier the more policies a tenant had."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap = cap_named(data, ADMIN_MFA)
    cap["conditions"]["users"]["excludeGroups"] = [BREAK_GLASS_GROUP]

    for index in range(3):
        weak = copy.deepcopy(cap)
        weak["id"] = f"weak-overlap-{index:04d}"
        weak["displayName"] = f"Other MFA policy {index}"
        weak["grantControls"]["authenticationStrength"] = weak_strength(data)
        data["conditional_access_policies"].append(weak)

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    # One finding, the exclusion. Not one per overlapping policy: the old engine
    # got noisier the more policies a tenant had.
    assert result["coverageGaps"] == [
        g for g in result["coverageGaps"] if "nsanctioned" in g
    ], result["coverageGaps"]


def test_a_weak_policy_alone_is_still_reported_as_weak(golden):
    """The diagnostic must survive the fix. With nothing stronger covering the
    population, the weak requirement is the finding."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap_named(data, ADMIN_MFA)["grantControls"]["authenticationStrength"] = weak_strength(data)

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] in (PARTIAL, MISSING)
    assert any(
        "weaker" in text.lower() for text in result["coverageGaps"] + result["notes"]
    )


# --- Defect 2: scope is coverage, not disqualification ------------------------


def test_partial_application_scope_contributes_instead_of_vanishing(golden):
    """The cap-006 defect. A policy reaching some of the required applications
    is still protection: it must contribute, name what it misses, and never be
    reported as a missing control."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap = cap_named(data, TOKEN_PROTECTION)
    apps = cap["conditions"]["applications"]["includeApplications"]
    assert len(apps) >= 2, "fixture needs at least two applications to drop one"
    dropped = apps.pop()

    assessment, result = result_for(artifact, data, manifest, TOKEN_PROTECTION)
    assert result["grade"] == PARTIAL, result["grade"]
    assert any(dropped in g for g in result["coverageGaps"]), result["coverageGaps"]
    assert str(cap["id"]) in {m["id"] for m in result["matchedPolicies"]}


def test_a_contributing_policy_is_never_also_surplus(golden):
    """The same policy appeared as a missing control and as an unrecognized
    extra on one page. SPEC-PUBLIC section 4 rule 5 forbids it."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap = cap_named(data, TOKEN_PROTECTION)
    cap["conditions"]["applications"]["includeApplications"].pop()

    assessment, result = result_for(artifact, data, manifest, TOKEN_PROTECTION)
    matched_anywhere = {
        m["id"] for control in assessment["controls"] for m in control["matchedPolicies"]
    }
    surplus_ids = {s["id"] for s in assessment["surplus"]}
    assert not (matched_anywhere & surplus_ids)
    assert str(cap["id"]) not in surplus_ids


def test_broader_application_scope_is_not_penalised(golden):
    """Reaching more than the standard asks for is not a gap."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap = cap_named(data, TOKEN_PROTECTION)
    cap["conditions"]["applications"]["includeApplications"].append("00000000-0000-0000-0000-00000000beef")

    _, result = result_for(artifact, data, manifest, TOKEN_PROTECTION)
    assert result["grade"] in (FULL, FUNCTIONAL), result["coverageGaps"]
    assert not any("not covered" in g.lower() for g in result["coverageGaps"])


def test_a_class_one_policy_carves_out_can_be_covered_by_another(golden):
    """Coverage splits on the population axis too. A class carved out of the
    broad policy is only uncovered when nothing else reaches it."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap = cap_named(data, USER_MFA)
    users = cap["conditions"]["users"]
    already_excluded = set(users.get("excludeRoles") or [])
    carved = next(
        r["id"] for r in data["roles"]["roleDefinitions"] if r["id"] not in already_excluded
    )
    users.setdefault("excludeRoles", []).append(carved)

    # A second policy, same requirement, covering exactly the carved out class.
    second = copy.deepcopy(cap)
    second["id"] = "carve-cover-0001"
    second["displayName"] = "The same requirement for the carved out role"
    second["conditions"]["users"] = {
        "includeUsers": [],
        "includeRoles": [carved],
        "includeGroups": [],
        "excludeUsers": [],
        "excludeRoles": [],
        "excludeGroups": [],
    }
    data["conditional_access_policies"].append(second)

    _, result = result_for(artifact, data, manifest, USER_MFA)
    assert not any(carved in g for g in result["coverageGaps"]), result["coverageGaps"]


def test_an_onboarding_exclusion_is_sanctioned_once_classified(golden):
    """Operator ruling of 2026-08-14. A group people sit in only
    while they enroll on a new sign in method is a recognised purpose, so
    classifying it sanctions the exclusion. It stays a real weakening while it
    exists, so the plan carries it on the watch list for removal."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap_named(data, ADMIN_MFA)["conditions"]["users"]["excludeGroups"] = [BREAK_GLASS_GROUP]
    control_id = control_for_cap(artifact, ADMIN_MFA)["id"]

    unclassified = run(artifact, data, manifest)
    before = next(r for r in unclassified["controls"] if r["controlId"] == control_id)
    assert any("nsanctioned" in g for g in before["coverageGaps"])

    classified = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
        answer_bindings={"onboardingGroups": [BREAK_GLASS_GROUP]},
    )
    after = next(r for r in classified["controls"] if r["controlId"] == control_id)
    assert not any("nsanctioned" in g for g in after["coverageGaps"]), after["coverageGaps"]


# --- Conservative backstops (BUGS.md items 4 and 5) ---------------------------


def test_a_required_session_control_is_not_dropped(golden):
    """A control carrying both a grant and a session control kept only the
    grant, because the category comes from the grant. A tenant with no sign in
    frequency at all graded FUNCTIONAL with no gaps (BUGS.md item 4)."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    control = control_for_cap(artifact, ADMIN_MFA)
    control["canonical"]["session"] = {
        "signInFrequency": {"type": "timeBased", "value": 14, "unit": "days"}
    }

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] not in (FULL, FUNCTIONAL), result["grade"]


def test_an_axis_nobody_compares_fails_closed(golden):
    """A device filter narrows who a policy reaches and was compared nowhere,
    so a policy scoped to compliant devices only graded as covering everyone.
    The backstop must make any uncompared axis fail closed, so that adding an
    axis to canonical_cap cannot silently grade a tenant up (BUGS.md item 5)."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap_named(data, ADMIN_MFA)["conditions"]["devices"] = {
        "deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq True"}
    }

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] not in (FULL, FUNCTIONAL), result["grade"]


def test_a_disabled_policy_is_not_evidence(golden):
    """A disabled policy protects nobody. It used to land in the report-only
    bucket, turning MISSING into PARTIAL and producing a gap telling the
    reader to enforce a policy that is not running (BUGS.md item 7)."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    cap_named(data, ADMIN_MFA)["state"] = "disabled"

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] == MISSING, result["grade"]
    assert not any("report-only" in g for g in result["coverageGaps"])


def test_application_coverage_is_joined_to_population(golden):
    """The two axes were computed independently, so one policy per role, each
    on a different application, graded as full coverage while each role was
    unprotected on the other application (BUGS.md item 6)."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    control = control_for_cap(artifact, ADMIN_MFA)
    control["knownOptionalDeviations"] = []

    base = cap_named(data, ADMIN_MFA)
    role_a, role_b = base["conditions"]["users"]["includeRoles"][:2]
    control["canonical"]["users"]["include"] = [f"role:{role_a}", f"role:{role_b}"]
    control["canonical"]["apps"] = {"include": ["app-one", "app-two"], "exclude": []}

    base["conditions"]["users"]["includeRoles"] = [role_a]
    base["conditions"]["applications"]["includeApplications"] = ["app-one"]
    second = copy.deepcopy(base)
    second["id"] = "cross-axis-0001"
    second["displayName"] = "The same requirement for the other role"
    second["conditions"]["users"]["includeRoles"] = [role_b]
    second["conditions"]["applications"]["includeApplications"] = ["app-two"]
    data["conditional_access_policies"].append(second)

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] not in (FULL, FUNCTIONAL), result["grade"]
    assert any("not covered" in g.lower() for g in result["coverageGaps"])


# --- Structural conformance is its own axis -----------------------------------


def test_construction_difference_is_structural_and_never_a_gap(golden):
    """A secure but differently shaped tenant scores as secure. The difference
    is recorded on the structural axis so it can still drive a tidy up item."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    broaden_population(cap_named(data, ADMIN_MFA))

    _, result = result_for(artifact, data, manifest, ADMIN_MFA)
    assert result["grade"] == FUNCTIONAL
    assert result["coverageGaps"] == []
    assert result["structural"], "a shape difference should be recorded"
    # SPEC-PUBLIC section 2: where the only reason to align is consistency, the
    # finding must say so rather than implying the tenant is less secure.
    assert any(
        "not a weakness" in s.lower() or "only" in s.lower()
        for s in result["structural"]
    ), result["structural"]


def test_report_renders_structural_findings_apart_from_gaps(golden):
    from iamai.report import render_assessment

    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    broaden_population(cap_named(data, ADMIN_MFA))

    html = render_assessment(run(artifact, data, manifest), manifest)
    assert "How your setup is organized" in html
    assert "wider group of people" in html
    assert "not a weakness" in html


def test_structural_findings_do_not_change_the_grade_counts(golden):
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    broaden_population(cap_named(data, ADMIN_MFA))

    assessment = run(artifact, data, manifest)
    graded = sum(assessment["gradeCounts"].values())
    assert graded == len(assessment["controls"])


# --- Defect 3: identifiers resolve to names, and names never grade ------------


def test_assessment_ships_a_display_name_index(golden):
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    assessment = run(artifact, data, manifest)

    groups = data.get("groups") or {}
    groups = groups.get("groups", []) if isinstance(groups, dict) else groups
    assert groups, "fixture needs at least one group"
    identifier = str(groups[0]["id"]).lower()
    assert assessment["names"].get(identifier) == groups[0]["displayName"]


def test_display_names_never_change_a_grade(golden):
    """The CLAUDE.md engine rule, held as a test: comparison is on canonical
    forms only. Renaming every policy must not move a single grade."""
    data, manifest = golden
    artifact = make_artifact(copy.deepcopy(data))
    before = {r["controlId"]: r["grade"] for r in run(artifact, data, manifest)["controls"]}

    for index, cap in enumerate(data["conditional_access_policies"]):
        cap["displayName"] = f"Renamed policy {index}"

    after = {r["controlId"]: r["grade"] for r in run(artifact, data, manifest)["controls"]}
    assert before == after
