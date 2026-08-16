"""PUB-M2b: guest, consent and default user permission controls.

Authored against the sources recorded in ASSUMPTIONS.md note 30. Several of
these encode a distinction the published baselines get wrong or leave out, and
those cases are called out in the test names rather than left implicit.
"""

import copy
import json
from pathlib import Path

import pytest

from iamai.grade import FULL, PARTIAL, UNKNOWN, assess_snapshot
from iamai.store import load_snapshot_data

pytestmark = pytest.mark.m12

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"
PACK = json.loads(
    (Path(__file__).parents[1] / "packs" / "basics-v1.json").read_text(encoding="utf-8")
)

MEMBER_EQUIVALENT = "a0b1b346-4d3e-4e8b-98f8-753987be4970"
LIMITED = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b"
SELF = "ManagePermissionGrantsForSelf."
OWNED = "ManagePermissionGrantsForOwnedResource."


def control(control_id):
    return next(c for c in PACK["controls"] if c["id"] == control_id)


def assess(control_id, authorization_policy=None, admin_consent=None):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    if authorization_policy is not None:
        data["authorization_policy"] = authorization_policy
    if admin_consent is not None:
        data["admin_consent_request_policy"] = admin_consent
    artifact = {"schemaVersion": 2, "controls": [copy.deepcopy(control(control_id))],
                "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )


def grade_of(result):
    if result["controls"]:
        return result["controls"][0]["grade"]
    return "NOT APPLICABLE"


def authz(**overrides):
    policy = {
        "allowInvitesFrom": "adminsAndGuestInviters",
        "guestUserRoleId": RESTRICTED,
        "allowUserConsentForRiskyApps": False,
        "defaultUserRolePermissions": {
            "allowedToCreateApps": False,
            "allowedToCreateTenants": False,
            "allowedToReadBitlockerKeysForOwnedDevice": False,
            "allowedToReadOtherUsers": True,
            "permissionGrantPoliciesAssigned": [],
        },
    }
    permissions = overrides.pop("defaultUserRolePermissions", None)
    policy.update(overrides)
    if permissions:
        policy["defaultUserRolePermissions"].update(permissions)
    return policy


# --- Guests -------------------------------------------------------------------


@pytest.mark.parametrize(
    "role_id, grade",
    [
        (RESTRICTED, FULL),
        (LIMITED, FULL),
        (MEMBER_EQUIVALENT, PARTIAL),
    ],
)
def test_only_member_equivalent_guest_access_is_a_finding(role_id, grade):
    """Restricted is the better setting but it stops working with some
    services, so requiring it would fail tenants that made a reasonable call.
    The bar is that a guest is not simply treated as staff."""
    assert grade_of(assess("guest-001", authz(guestUserRoleId=role_id))) == grade


@pytest.mark.parametrize(
    "value, grade",
    [
        ("adminsAndGuestInviters", FULL),
        ("none", FULL),
        ("everyone", PARTIAL),
        ("adminsGuestInvitersAndAllMembers", PARTIAL),
    ],
)
def test_turning_invitations_off_entirely_is_not_a_finding(value, grade):
    """The published baseline's own check fails any value other than
    adminsAndGuestInviters, so a tenant on the strictest possible setting fails
    it. Grading a tenant down for exceeding the standard is the conservative
    rule inverted, so that logic is deliberately not copied."""
    assert grade_of(assess("guest-002", authz(allowInvitesFrom=value))) == grade


# --- Consent ------------------------------------------------------------------


@pytest.mark.parametrize(
    "assigned, grade",
    [
        ([], FULL),
        ([SELF + "microsoft-user-default-low"], FULL),
        ([SELF + "microsoft-user-default-legacy"], PARTIAL),
        # Only entries about consenting for yourself are the user consent
        # setting. Teams manages its own chat and team scoped grants through
        # the owned resource entries, which are a different thing.
        ([OWNED + "microsoft-dynamically-managed-permissions-for-chat"], FULL),
    ],
)
def test_user_consent_is_graded_on_what_it_allows(assigned, grade):
    policy = authz(defaultUserRolePermissions={"permissionGrantPoliciesAssigned": assigned})
    assert grade_of(assess("consent-001", policy)) == grade


def test_the_setting_microsoft_manages_for_you_is_still_user_consent():
    """The live lab tenant carries these two. They are the default for tenants
    created recently, and they are permissive: users may consent to any user
    consentable delegated permission except a list Microsoft maintains, and the
    second policy hands part of that list back for six named mail clients. A
    deny list of the two documented bad ids passed this tenant silently, which
    is the same false negative the published baseline's own checker has
    (ASSUMPTIONS.md note 32), so the check is an allow list instead."""
    policy = authz(defaultUserRolePermissions={"permissionGrantPoliciesAssigned": [
        OWNED + "microsoft-dynamically-managed-permissions-for-chat",
        SELF + "microsoft-user-default-allow-consent-apps",
        SELF + "microsoft-user-default-recommended",
    ]})
    assert grade_of(assess("consent-001", policy)) == PARTIAL


@pytest.mark.parametrize(
    "assigned, grade",
    [
        ([], FULL),
        ([OWNED + "microsoft-dynamically-managed-permissions-for-team"], FULL),
        ([SELF + "microsoft-user-default-low"], PARTIAL),
    ],
)
def test_the_strict_control_allows_no_user_consent_at_all(assigned, grade):
    """The stricter reading, and the one the published baseline requires. It
    fails the verified publisher setting that Microsoft itself recommends,
    which is why it is not the baseline control."""
    policy = authz(defaultUserRolePermissions={"permissionGrantPoliciesAssigned": assigned})
    assert grade_of(assess("consent-002", policy)) == grade


def test_the_risky_app_step_up_does_not_apply_when_it_was_never_touched():
    """Graph returns null for a tenant that never changed it, and null means
    running on the default, which is the safe one. Reading null as false would
    invent a finding on most tenants alive."""
    result = assess("riskyapps-001", authz(allowUserConsentForRiskyApps=None))
    assert result["controls"] == []
    assert "default" in result["notApplicable"][0]["note"]


def test_turning_the_risky_app_step_up_off_is_a_finding():
    assert grade_of(assess("riskyapps-001", authz(allowUserConsentForRiskyApps=True))) == PARTIAL


# --- Admin consent workflow ---------------------------------------------------


def test_a_workflow_with_reviewers_passes():
    policy = {"isEnabled": True, "reviewers": [{"query": "/v1.0/roleManagement", "queryType": "MicrosoftGraph"}]}
    assert grade_of(assess("consent-003", admin_consent=policy)) == FULL


def test_a_workflow_nobody_receives_is_a_finding():
    policy = {"isEnabled": True, "reviewers": None}
    assert grade_of(assess("consent-003", admin_consent=policy)) == PARTIAL


def test_a_workflow_that_could_not_be_read_is_not_reported_as_absent():
    """A tenant whose policy could not be read is not a tenant without one."""
    result = assess("consent-003", admin_consent=None)
    assert result["controls"][0]["grade"] == UNKNOWN


# --- Default user permissions -------------------------------------------------


@pytest.mark.parametrize("control_id, key", [
    ("apps-001", "allowedToCreateApps"),
    ("tenants-001", "allowedToCreateTenants"),
    ("bitlocker-001", "allowedToReadBitlockerKeysForOwnedDevice"),
])
def test_default_user_permissions_are_graded_on_the_setting(control_id, key):
    assert grade_of(assess(control_id, authz(defaultUserRolePermissions={key: False}))) == FULL
    assert grade_of(assess(control_id, authz(defaultUserRolePermissions={key: True}))) == PARTIAL


def test_reading_other_users_is_never_graded():
    """Microsoft's own reference says in bold not to set this to false, and
    that doing so can stop Teams reading user information. A hardening control
    that breaks the thing it protects is not hardening."""
    ids = {c["id"] for c in PACK["controls"]}
    assert not any("readOtherUsers" in i or "otherusers" in i.lower() for i in ids)
    blob = json.dumps(PACK)
    assert "allowedToReadOtherUsers" not in blob


# --- Standing privileged access without Privileged Identity Management --------

from iamai.grade import GA_ROLE_TEMPLATE_ID, _privileged_access_summary

BREAK_GLASS = "11111111-1111-1111-1111-111111111111"
ADMIN = "33333333-3333-3333-3333-333333333333"
P1_ONLY = {"known": True, "entraP1": True, "entraP2": False}
P2 = {"known": True, "entraP1": True, "entraP2": True}
UNKNOWN_LICENSING = {"known": False, "entraP1": False, "entraP2": False}


def roles_without_schedules(assignments):
    return {"roles": {"roleAssignmentSchedules": None, "roleAssignments": assignments}}


def test_a_tenant_without_p2_is_answered_from_the_plain_assignments():
    """The schedules feed is a Privileged Identity Management endpoint and
    returns AadPremiumLicenseRequired without P2. A tenant that cannot license
    PIM cannot be running it, so no assignment can be an activation in flight
    and the plain list is exact. Returning unknown here would leave most small
    tenants, which are the ones this pack is for, with no answer at all."""
    result = _privileged_access_summary(
        roles_without_schedules([
            {"principalId": BREAK_GLASS, "roleDefinitionId": GA_ROLE_TEMPLATE_ID},
            {"principalId": ADMIN, "roleDefinitionId": GA_ROLE_TEMPLATE_ID},
        ]),
        {"breakGlassAccounts": [BREAK_GLASS]},
        P1_ONLY,
    )
    assert result["standingAssignments"] == 2
    assert result["standingGlobalAdminsBesidesBreakGlass"] == 1


def test_a_p2_tenant_whose_feed_failed_is_still_unknown():
    """Here the feed should have worked, so its absence is a real gap and the
    plain list could contain activations that are not standing access."""
    assert _privileged_access_summary(
        roles_without_schedules([{"principalId": ADMIN, "roleDefinitionId": GA_ROLE_TEMPLATE_ID}]),
        {"breakGlassAccounts": [BREAK_GLASS]},
        P2,
    ) is None


def test_unknown_licensing_does_not_get_the_benefit_of_the_doubt():
    assert _privileged_access_summary(
        roles_without_schedules([{"principalId": ADMIN, "roleDefinitionId": GA_ROLE_TEMPLATE_ID}]),
        {"breakGlassAccounts": [BREAK_GLASS]},
        UNKNOWN_LICENSING,
    ) is None


# --- Every one of these findings has somewhere to go --------------------------

from iamai.plan import _SETTING_STEPS, _SUPERSEDES


def test_every_tenant_setting_control_has_a_step():
    """These controls are graded from a single tenant wide switch, so nothing
    else in the plan will pick them up. A finding with no step is a dead end,
    and a report that names a problem and then goes quiet about it is worse
    than one that never raised it."""
    graded = {c["id"] for c in PACK["controls"]
              if c["surface"] in ("authorizationPolicy", "adminConsentRequestPolicy")}
    assert graded, "the pack must carry tenant setting controls"
    assert graded == set(_SETTING_STEPS), graded ^ set(_SETTING_STEPS)


def test_each_step_says_what_the_change_will_cost():
    """Somebody has to live with each of these tomorrow. A step that hides its
    cost gets reverted in a hurry by whoever it surprised."""
    for control_id, (title, actions, cost) in _SETTING_STEPS.items():
        assert title and actions and cost, control_id
        assert len(cost) > 60, control_id


def test_the_superseded_control_is_the_looser_one():
    """Dropping the stricter step would quietly lower what the plan asks for."""
    for loose, strict in _SUPERSEDES.items():
        profiles = {c["id"]: c.get("profile") for c in PACK["controls"]}
        assert profiles[loose] == "baseline"
        assert profiles[strict] == "strict"


# --- The sanitizer must not let the tenant name out --------------------------

import tempfile

from iamai.sanitize import Pseudonymizer, sanitize_node


def test_the_tenant_name_on_a_licence_record_is_redacted():
    """Every subscribedSkus record carries the tenant's own name in
    accountName. The displayName rule never reached it, because a licence
    record does not look like an organization object, so the name survived
    into a committed test fixture and was only found by running a secret
    scanner over the full history before publishing."""
    pseudo = Pseudonymizer(Path(tempfile.mkdtemp()) / "pseudo_map.json")
    node = {"subscribedSkus": [
        {"accountName": "AcmeCorpTenant", "skuPartNumber": "AAD_PREMIUM_P2",
         "accountId": "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000"},
    ]}
    out = sanitize_node(pseudo, node)
    blob = json.dumps(out)
    assert "AcmeCorpTenant" not in blob
    assert out["subscribedSkus"][0]["accountName"] == "redacted"
    # The part number is product structure, not tenant identity, and the
    # report needs it to say which licence a control requires.
    assert out["subscribedSkus"][0]["skuPartNumber"] == "AAD_PREMIUM_P2"


def test_no_committed_fixture_names_a_real_tenant():
    """The fixtures are recorded Graph responses. A real tenant name in one of
    them publishes with the repository and cannot be taken back."""
    root = Path(__file__).parents[1] / "tests" / "fixtures"
    for path in root.rglob("*.json"):
        blob = path.read_text(encoding="utf-8")
        for banned in ("onmicrosoft.com",):
            for line in blob.splitlines():
                if banned in line and "contoso" not in line.lower():
                    raise AssertionError(f"{path.name}: {line.strip()[:80]}")
