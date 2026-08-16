"""PUB-M2: the basics pack (SPEC-PUBLIC section 7).

Controls authored against the Graph shapes verified in ASSUMPTIONS.md note 25.
Where a control describes a quantity rather than a value, a stricter tenant
must satisfy it: grading a tenant down for exceeding the standard would be the
conservative rule inverted.
"""

import pytest

from iamai.grade import _session_cover

pytestmark = pytest.mark.m12


def sif(unit, value, interval="timeBased"):
    return {
        "signInFrequency": {
            "isEnabled": True,
            "type": unit,
            "value": value,
            "frequencyInterval": interval,
        }
    }


REQUIRED_14_DAYS = sif("days", 14)


@pytest.mark.parametrize(
    "candidate, covers",
    [
        (sif("days", 14), True),    # exactly the standard
        (sif("days", 7), True),     # stricter by days
        (sif("hours", 4), True),    # stricter by unit
        (sif("days", 0, "everyTime"), True),  # strictest possible
        (sif("days", 90), False),   # weaker
        (sif("hours", 400), False),  # weaker, expressed in hours
        ({}, False),                 # no requirement at all
    ],
)
def test_sign_in_frequency_is_compared_as_a_quantity(candidate, covers):
    assert _session_cover(candidate, REQUIRED_14_DAYS) is covers


def test_an_unreadable_frequency_grades_down_rather_than_guessing():
    """A shape the canonicaliser could not read must never be treated as
    covering, per the conservative rule in CLAUDE.md."""
    unreadable = {"signInFrequency": {"isEnabled": True, "type": None, "value": None}}
    assert _session_cover(unreadable, REQUIRED_14_DAYS) is False


def test_other_session_controls_still_compare_exactly():
    """Only sign in frequency has a defined order. Everything else has no
    meaningful "stricter", so it is matched rather than ranked."""
    required = {"secureSignInSession": {"isEnabled": True}}
    assert _session_cover({"secureSignInSession": {"isEnabled": True}}, required) is True
    assert _session_cover({}, required) is False


# --- Conditional controls (SPEC-PUBLIC section 7.2b) --------------------------

import copy
import json
from pathlib import Path

from iamai.grade import FULL, PARTIAL, assess_snapshot
from iamai.store import load_snapshot_data

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"
ANDROID = "de1e552d-db1d-4423-a619-566b625cdc84"
IOS = "90a3ccdf-635c-4729-a248-9b709135078f"

AAGUID_CONTROL = json.loads(
    (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
)
AAGUID_CONTROL = next(
    c for c in AAGUID_CONTROL["controls"] if c["id"] == "method-Fido2-aaguid"
)


def assess_with_restrictions(restrictions):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    policy = data.get("auth_methods_policy") or {}
    if isinstance(policy, list):
        policy = policy[0]
    for config in policy.get("authenticationMethodConfigurations") or []:
        if config.get("id") == "Fido2":
            config["keyRestrictions"] = restrictions
            break
    artifact = {"schemaVersion": 2, "controls": [copy.deepcopy(AAGUID_CONTROL)], "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )


def test_an_allow_list_missing_the_authenticator_is_caught():
    """The trap: security keys keep working, phone enrollment silently fails."""
    result = assess_with_restrictions(
        {"isEnforced": True, "enforcementType": "allow", "aaGuids": ["00000000-0000-0000-0000-0000000000aa"]}
    )
    graded = result["controls"][0]
    assert graded["grade"] == PARTIAL
    assert "Authenticator" in graded["coverageGaps"][0]
    assert result["notApplicable"] == []


def test_an_allow_list_including_the_authenticator_passes():
    graded = assess_with_restrictions(
        {"isEnforced": True, "enforcementType": "allow", "aaGuids": [ANDROID, IOS]}
    )["controls"][0]
    assert graded["grade"] == FULL


def test_no_restriction_means_the_check_does_not_apply():
    """Nothing is wrong until the condition holds, so it is recorded rather
    than graded and never counts against the tenant."""
    result = assess_with_restrictions(
        {"isEnforced": False, "enforcementType": "block", "aaGuids": []}
    )
    assert result["controls"] == []
    assert sum(result["gradeCounts"].values()) == 0
    assert result["notApplicable"][0]["controlId"] == "method-Fido2-aaguid"


def test_a_block_list_is_a_different_thing_and_does_not_apply():
    """enforcementType block excludes named devices rather than permitting
    only them, so leaving the Authenticator out of it is not the same trap."""
    result = assess_with_restrictions(
        {"isEnforced": True, "enforcementType": "block", "aaGuids": ["00000000-0000-0000-0000-0000000000aa"]}
    )
    assert result["controls"] == []
    assert result["notApplicable"][0]["controlId"] == "method-Fido2-aaguid"


# --- Security Defaults (SPEC-PUBLIC section 7 item 11) ------------------------

SECDEFAULTS_CONTROL = next(
    c for c in json.loads(
        (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
    )["controls"] if c["id"] == "secdefaults-001"
)


def assess_with_security_defaults(enabled, controls):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    data["security_defaults"] = {"isEnabled": enabled}
    artifact = {"schemaVersion": 2, "controls": copy.deepcopy(controls), "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )


def test_security_defaults_tenant_is_not_failed_on_every_policy_control():
    """Entra will not run Conditional Access and Security Defaults together,
    so a tenant on Security Defaults cannot satisfy a policy control. Grading
    it down for that would report a pile of failures for something it
    structurally cannot do."""
    cap_controls = [
        c for c in json.loads(
            (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
        )["controls"] if c["surface"] == "conditionalAccess"
    ]
    assert cap_controls, "fixture pack must carry policy controls"

    result = assess_with_security_defaults(True, cap_controls)
    assert result["controls"] == []
    assert sum(result["gradeCounts"].values()) == 0
    # Every policy control is accounted for without being graded. A control the
    # tenant also cannot license is reported as out of reach instead, because
    # the licence is the more fundamental blocker and telling a tenant that
    # Conditional Access would make a P2 control possible would be wrong.
    excused = {c["controlId"] for c in result["notApplicable"]} | {
        c["controlId"] for c in result["outOfReach"]
    }
    assert excused == {c["id"] for c in cap_controls}
    assert result["notApplicable"], "the Security Defaults reason must be used"
    note = result["notApplicable"][0]["note"]
    assert "cannot be combined" in note
    assert "not a gap" in note


def test_a_tenant_without_security_defaults_is_graded_normally():
    cap_controls = [
        c for c in json.loads(
            (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
        )["controls"] if c["surface"] == "conditionalAccess"
    ]
    result = assess_with_security_defaults(False, cap_controls)
    assert result["controls"], "policy controls must still be graded"
    assert result["notApplicable"] == []


def test_security_defaults_control_reports_only_when_it_is_in_use():
    on = assess_with_security_defaults(True, [SECDEFAULTS_CONTROL])
    assert on["controls"][0]["grade"] == FULL

    off = assess_with_security_defaults(False, [SECDEFAULTS_CONTROL])
    assert off["controls"] == []
    assert "free to use Conditional Access" in off["notApplicable"][0]["note"]


# --- Standing privileged access (SPEC-PUBLIC section 7 item 15) ---------------

from iamai.grade import GA_ROLE_TEMPLATE_ID, _privileged_access_summary

BREAK_GLASS_ID = "11111111-1111-1111-1111-111111111111"
ADMIN_ID = "33333333-3333-3333-3333-333333333333"


def schedule(principal, assignment_type, expiry="noExpiration", role=GA_ROLE_TEMPLATE_ID):
    return {
        "principalId": principal,
        "roleDefinitionId": role,
        "assignmentType": assignment_type,
        "scheduleInfo": {"expiration": {"type": expiry}},
    }


def summary(schedules, break_glass=(BREAK_GLASS_ID,)):
    return _privileged_access_summary(
        {"roles": {"roleAssignmentSchedules": schedules}},
        {"breakGlassAccounts": list(break_glass)},
    )


def test_a_pim_activation_in_flight_is_not_standing_access():
    """roleAssignments cannot tell these apart, so counting from it reported
    inflated numbers to the tenants managing privilege best (BUGS.md note on
    SPEC-PUBLIC item 15)."""
    result = summary([schedule(ADMIN_ID, "Activated", "afterDateTime")])
    assert result["standingAssignments"] == 0
    assert result["standingGlobalAdminsBesidesBreakGlass"] == 0


def test_a_time_limited_permanent_assignment_is_not_standing_either():
    result = summary([schedule(ADMIN_ID, "Assigned", "afterDateTime")])
    assert result["standingAssignments"] == 0


def test_break_glass_accounts_are_the_deliberate_exception():
    """They exist to always work, so holding the role permanently is the
    point rather than a finding."""
    result = summary([schedule(BREAK_GLASS_ID, "Assigned")])
    assert result["standingAssignments"] == 1
    assert result["standingGlobalAdminsBesidesBreakGlass"] == 0


def test_anyone_else_holding_it_permanently_is_counted():
    result = summary([schedule(BREAK_GLASS_ID, "Assigned"), schedule(ADMIN_ID, "Assigned")])
    assert result["standingAssignments"] == 2
    assert result["standingGlobalAdminsBesidesBreakGlass"] == 1


def test_a_standing_non_global_admin_role_is_not_a_global_admin_finding():
    other_role = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    result = summary([schedule(ADMIN_ID, "Assigned", role=other_role)])
    assert result["standingAssignments"] == 1
    assert result["standingGlobalAdminsBesidesBreakGlass"] == 0


def test_an_unreadable_schedules_feed_yields_nothing_rather_than_zero():
    """A tenant whose feed could not be read must not be reported as having no
    standing access, which would be the conservative rule inverted."""
    assert _privileged_access_summary({"roles": {"roleAssignmentSchedules": None}}, {}) is None


# --- Method settings compared as quantities (SPEC-PUBLIC section 3) -----------

from iamai.grade import FUNCTIONAL, _method_settings_cover

TAP_STANDARD = {
    "minimumLifetimeInMinutes": 60,
    "maximumLifetimeInMinutes": 480,
    "defaultLifetimeInMinutes": 60,
    "defaultLength": 8,
    "isUsableOnce": False,
}


def tap(**overrides):
    return {**TAP_STANDARD, **overrides}


@pytest.mark.parametrize(
    "candidate, covers",
    [
        (tap(), True),
        (tap(maximumLifetimeInMinutes=240), True),   # a shorter window
        (tap(defaultLength=16), True),               # a harder pass to guess
        (tap(isUsableOnce=True), True),              # cannot be replayed
        (tap(minimumLifetimeInMinutes=10), True),    # bounds no attacker, not graded
        (tap(maximumLifetimeInMinutes=1440), False),  # a day long pass
        (tap(defaultLength=6), False),
    ],
)
def test_a_stricter_temporary_access_pass_is_not_a_finding(candidate, covers):
    """The old engine compared these exactly, so a tenant that had tightened
    the pass beyond the standard was reported as failing to meet it."""
    assert _method_settings_cover(candidate, TAP_STANDARD, "TemporaryAccessPass") is covers


def test_a_missing_setting_is_not_treated_as_meeting_the_standard():
    partial = {k: v for k, v in TAP_STANDARD.items() if k != "defaultLength"}
    assert _method_settings_cover(partial, TAP_STANDARD, "TemporaryAccessPass") is False


def test_a_setting_with_no_agreed_direction_is_compared_exactly():
    """Nothing is stricter until someone decides which way stricter runs, so an
    unrecognised setting fails closed rather than passing by being unknown."""
    required = {**TAP_STANDARD, "someNewKnob": 5}
    assert _method_settings_cover({**tap(), "someNewKnob": 5}, required, "TemporaryAccessPass") is True
    assert _method_settings_cover({**tap(), "someNewKnob": 9}, required, "TemporaryAccessPass") is False
    # And a method nobody has reasoned about at all gets no leeway.
    assert _method_settings_cover(tap(maximumLifetimeInMinutes=1), TAP_STANDARD, "Fido2") is False


# --- Registration campaign (SPEC-PUBLIC section 7 item 16) --------------------

CAMPAIGN_CONTROL = next(
    c for c in json.loads(
        (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
    )["controls"] if c["id"] == "campaign-001"
)


def assess_with_campaign(**overrides):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    policy = data.get("auth_methods_policy") or {}
    if isinstance(policy, list):
        policy = policy[0]
    campaign = {
        "state": "enabled",
        "snoozeDurationInDays": 1,
        "includeTargets": [{"id": "all_users", "targetType": "group",
                            "targetedAuthenticationMethod": "microsoftAuthenticator"}],
        "excludeTargets": [],
    }
    campaign.update(overrides)
    policy["registrationEnforcement"] = {
        "authenticationMethodsRegistrationCampaign": campaign
    }
    artifact = {"schemaVersion": 2, "controls": [copy.deepcopy(CAMPAIGN_CONTROL)], "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )["controls"][0]


def test_leaving_the_campaign_for_microsoft_to_manage_is_not_a_finding():
    """Microsoft managed reports as default and Microsoft currently manages it
    to on, so failing this would be a false finding against a tenant following
    Microsoft's own recommendation. It is not FULL because the tenant is not
    the one holding it on."""
    graded = assess_with_campaign(state="default")
    assert graded["grade"] == FUNCTIONAL
    assert graded["coverageGaps"] == []


def test_a_switched_off_campaign_is_still_a_finding():
    graded = assess_with_campaign(state="disabled")
    assert graded["grade"] == PARTIAL
    assert graded["coverageGaps"]


def test_not_excluding_the_emergency_accounts_never_moves_the_grade():
    """Nobody is less protected because the emergency accounts get nudged, so
    it is said out loud on the structural axis and not scored."""
    graded = assess_with_campaign()
    assert graded["grade"] == FULL
    assert graded["coverageGaps"] == []
    assert any("emergency accounts" in s for s in graded["structural"])


# --- QR code sign in is scoped, not banned (SPEC-PUBLIC section 7.2b) ---------

QR_CONTROL = next(
    c for c in json.loads(
        (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
    )["controls"] if c["id"] == "method-QRCodePin"
)
FRONTLINE_GROUP = "44444444-4444-4444-4444-444444444444"


def assess_qr(state, target_ids):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    policy = data.get("auth_methods_policy") or {}
    if isinstance(policy, list):
        policy = policy[0]
    configs = policy.setdefault("authenticationMethodConfigurations", [])
    config = next((c for c in configs if c.get("id") == "QRCodePin"), None)
    if config is None:
        config = {"id": "QRCodePin"}
        configs.append(config)
    config["state"] = state
    config["includeTargets"] = [
        {"id": i, "targetType": "group", "isRegistrationRequired": False} for i in target_ids
    ]
    artifact = {"schemaVersion": 2, "controls": [copy.deepcopy(QR_CONTROL)], "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )


def test_qr_sign_in_left_on_for_everyone_is_a_finding():
    """It only proves possession of a printed code plus a PIN, so tenant wide
    it is a weaker way in than everything else here asks for."""
    result = assess_qr("enabled", ["all_users"])
    assert result["controls"][0]["grade"] == PARTIAL


def test_qr_sign_in_scoped_to_the_people_who_need_it_is_not_a_finding():
    """Microsoft's guidance is to scope it to frontline workers, not to turn it
    off. The old control required it off and failed a correct deployment."""
    result = assess_qr("enabled", [FRONTLINE_GROUP])
    assert result["controls"][0]["grade"] == FULL
    assert result["controls"][0]["coverageGaps"] == []


def test_qr_sign_in_switched_off_is_nothing_to_grade():
    result = assess_qr("disabled", [])
    assert result["controls"] == []
    assert result["notApplicable"][0]["controlId"] == "method-QRCodePin"


# --- The pack no longer carries controls no source supports ------------------

PACK = json.loads(
    (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
)


def test_certificate_based_authentication_is_not_required_off():
    """It is phishing resistant, Microsoft and CISA both name it as such, and
    this pack's own strength-002 and strength-003 grant on it. Requiring the
    method off contradicted the pack's own definition of a strong sign in."""
    ids = {c["id"] for c in PACK["controls"]}
    assert "method-X509Certificate" not in ids
    granting = [c for c in PACK["controls"] if "x509CertificateMultiFactor"
                in (c.get("canonical", {}).get("combos") or [])]
    assert granting, "the strengths that grant on certificates must still exist"


def test_no_control_ships_a_placeholder_citation():
    """A citation is a claim that a control covers a published item. A
    placeholder is not a claim, so it must never reach a customer report."""
    for control in PACK["controls"]:
        sources = {str(c.get("source", "")) for c in control.get("citations") or []}
        assert sources, control["id"]
        assert "PLACEHOLDER" not in sources, control["id"]


def test_every_licensed_control_says_what_to_do_without_the_licence():
    """A control the tenant cannot buy is listed so the choice is visible. A
    list of protections with no alternative beside them reads as a sales
    sheet, which is the opposite of what it is for (SPEC-PUBLIC section 6)."""
    for control in PACK["controls"]:
        if str(control.get("licenseRequirement", "none")) != "none":
            assert control.get("mitigation"), control["id"]


def test_no_pack_text_uses_an_em_dash():
    """Operator's house style, and it survives into customer facing reports."""
    raw = (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
    assert "—" not in raw
    assert "–" not in raw
