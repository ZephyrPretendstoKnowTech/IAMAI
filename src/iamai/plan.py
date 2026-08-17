"""Plan generator (SPEC section 10).

Input: assessment + answers, plus the baseline artifact and the latest
snapshot data for the preflight checks. Output: a plan record (written by the
CLI as plan.json and rendered to plan.html).

The frame is a 14 day skeleton with measured checkpoints, not dates alone.
Every checkpoint is a machine checkable statement against fresh collector
data, and the extension rule is stated plainly: an unmet checkpoint slips the
dependent phases and the operator re-runs collect and assess to recheck.
User facing output says "checkpoint"; the schema field names (gateId, gates)
stay for compatibility (SPEC-V2 section 2).

V2-M0 output rules: the plan carries a start date and renders real calendar
dates; no action string exceeds 300 characters; no list renders more than 8
items inline (longer lists become a ListDetail: a count, a summary, and the
full list rendered collapsed).

Fixed sequencing rules: day 1 is always break glass and nothing else ships
before it; a service principal preflight runs on any step deploying a policy
that targets specific applications; registration before enforcement;
report-only before enforced; legacy auth inventory before any block; the MFA
cohort split (registered people are enforced quickly, unregistered people
register with a Temporary Access Pass and migrate in, and the straggler tail
runs past day 14 by design); and the weakest method is never codified: when
the dominant registered method is text message codes, immediate enforcement
uses a standard multifactor requirement and the stronger strength requirement
becomes its own staged step.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, Field

from iamai.canon import control_signature
from iamai.questions import CHOSEN_SLOT, AnswersFile, parameters

PARTIAL = "PARTIAL"
MISSING = "MISSING"
UNKNOWN = "UNKNOWN"

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Application tokens in canonical app lists that are not appIds and never
# need a service principal.
_APP_TOKENS = {"All", "Office365", "None", "MicrosoftAdminPortals"}

# Which license requirements each confirmed tier can support.
_TIER_ALLOWS: dict[str, set[str]] = {
    "P2": {"none", "P1", "P2"},
    "P1": {"none", "P1"},
    "BusinessPremium": {"none", "P1"},
    "none": {"none"},
}

_PORTAL = "Open the Entra admin center at entra.microsoft.com and sign in as an administrator."

_CLIENT_APP_LABELS = {
    "browser": "Browser",
    "mobileAppsAndDesktopClients": "Mobile apps and desktop clients",
    "exchangeActiveSync": "Exchange ActiveSync clients",
    "other": "Other clients",
}

_GRANT_CONTROL_LABELS = {
    "mfa": "Require multifactor authentication",
    "compliantDevice": "Require device to be marked as compliant",
    "domainJoinedDevice": "Require Microsoft Entra hybrid joined device",
    "approvedApplication": "Require approved client app",
    "compliantApplication": "Require app protection policy",
    "passwordChange": "Require password change",
}

_DEVICE_POSTURE_WARNING = (
    "Device posture is not assessed by this tool in this version. Verify the "
    "device compliance or hybrid join side of this policy by hand before "
    "relying on it."
)

_LOCKOUT_WARNING = (
    "A person who has not registered a second sign in method can be locked "
    "out by enforcement. The registration checkpoint exists to prevent this; "
    "do not skip it."
)

# The long list rule (SPEC-V2 section 2): more items than this never render
# inline, and no single action string may exceed the character limit.
_INLINE_LIMIT = 8
_ACTION_LIMIT = 300

# Locale independent date words, so rendered dates never depend on the
# machine's locale settings.
_DAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
              "Saturday", "Sunday")
_MONTH_NAMES = ("January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November",
                "December")


def _fmt_date(d: date) -> str:
    return f"{_DAY_NAMES[d.weekday()]} {d.day} {_MONTH_NAMES[d.month - 1]} {d.year}"


def _plan_day(start: date, day: int) -> date:
    """Day 1 of the rollout is the start date itself."""
    return start + timedelta(days=day - 1)


# --- Schema (every step card field is mandatory, SPEC 10) ----------------------


class Affected(BaseModel):
    count: int
    samples: list[str]


class Precondition(BaseModel):
    """Machine checkable statement, auto evaluated from the latest snapshot
    where possible; unverified means it can only be checked at execution
    time."""

    statement: str
    query: str
    result: Literal["pass", "fail", "unverified"]


class Verification(BaseModel):
    """Status becomes verified-done only when the query passes on a fresh
    collect. Generation always writes pending."""

    query: str
    expected: str
    status: str = "pending"


class Gate(BaseModel):
    """A measured checkpoint. The class and field names stay "gate" for
    schema compatibility; every user facing string says "checkpoint"."""

    id: str
    statement: str
    query: str
    extensionRule: str


class ListDetail(BaseModel):
    """A list too long to render inline (the long list rule, SPEC-V2
    section 2): the action carries the count and a pointer, the summary
    names the first few items, and the full list renders collapsed."""

    id: str
    title: str
    summary: str
    items: list[str] = Field(min_length=1)


class StepCard(BaseModel):
    id: str
    phase: int
    title: str
    riskClass: Literal["high", "medium", "low"]
    affected: Affected
    preconditions: list[Precondition] = Field(min_length=1)
    actions: list[str] = Field(min_length=1)
    verification: Verification
    rollback: list[str] = Field(min_length=1)
    watchFor: list[str] = Field(min_length=1)
    controlId: str = ""
    lists: list[ListDetail] = Field(default_factory=list)


class Phase(BaseModel):
    number: int
    name: str
    days: str
    dates: str = ""
    purpose: str
    gateId: str


class WatchItem(BaseModel):
    item: str
    kind: Literal["account", "application"]
    reason: str


class Plan(BaseModel):
    schemaVersion: int = 2
    tenantId: str
    alias: str
    generatedAt: str
    basedOnAssessment: str
    startDate: str = ""
    licenseTier: str
    phases: list[Phase]
    gates: list[Gate]
    steps: list[StepCard]
    watchList: list[WatchItem]
    notIncluded: list[dict]
    # Stated plainly rather than implied by an absence. This plan is the
    # strongest posture the tenant's own licensing can reach, and a reader
    # should know that is what they are holding (SPEC-PUBLIC section 6).
    bestEffortNote: str = ""
    unknowns: list[str]
    comms: dict[str, str]
    scopeNote: str


# --- Snapshot readers ------------------------------------------------------------


def _users_list(data: dict) -> list[dict]:
    users = data.get("users") or []
    return users if isinstance(users, list) else users.get("value", [])


def _registration_rows(data: dict) -> list[dict]:
    rows = data.get("registration_details") or []
    return rows if isinstance(rows, list) else rows.get("value", [])


def _service_principals(data: dict) -> dict[str, str]:
    sps = data.get("service_principals") or []
    if isinstance(sps, dict):
        sps = sps.get("value", [])
    return {
        str(sp.get("appId", "")).lower(): str(sp.get("displayName", ""))
        for sp in sps
    }


def _role_names(data: dict) -> dict[str, str]:
    roles = data.get("roles") or {}
    return {
        str(r.get("id", "")).lower(): str(r.get("displayName", ""))
        for r in roles.get("roleDefinitions") or []
    }


def _cohort(data: dict) -> tuple[list[str], list[str]]:
    """(registered, unregistered) UPNs for the enforcement cohort: enabled
    member accounts, split by second factor registration."""
    registered_ids = {
        str(r.get("id", "")).lower()
        for r in _registration_rows(data)
        if r.get("isMfaRegistered")
    }
    registered: list[str] = []
    unregistered: list[str] = []
    for user in _users_list(data):
        if not user.get("accountEnabled", True):
            continue
        if str(user.get("userType", "Member")).lower() == "guest":
            continue
        upn = str(user.get("userPrincipalName", ""))
        if str(user.get("id", "")).lower() in registered_ids:
            registered.append(upn)
        else:
            unregistered.append(upn)
    return sorted(registered), sorted(unregistered)


def _list_action(
    stem: str,
    items: list[str],
    *,
    title: str,
    unit: str,
    lists: list[ListDetail],
    tail: str = "",
) -> str:
    """One action string honoring the long list rule: inline when the list
    is short, otherwise a count plus a pointer to a collapsed full list
    carried on the step."""
    suffix = f" {tail}" if tail else ""
    inline = f"{stem}: {', '.join(items)}.{suffix}"
    if len(items) <= _INLINE_LIMIT and len(inline) <= _ACTION_LIMIT:
        return inline
    preview = ", ".join(items[:3])
    lists.append(ListDetail(
        id=f"list-{len(lists) + 1:02d}",
        title=title,
        summary=f"{len(items)} {unit}, including {preview}, and {len(items) - 3} more.",
        items=list(items),
    ))
    return (
        f"{stem}: all {len(items)} {unit} in the list '{title}' at the end "
        f"of this step.{suffix}"
    )


def resolve_role_tokens(text: str, role_names: dict[str, str]) -> str:
    """Rewrite role:<template id> tokens to the role's display name, the way
    plan actions already name roles (SPEC-V2 section 2). Unknown ids stay
    as they are; never guessed."""
    def _sub(match: re.Match) -> str:
        name = role_names.get(match.group(1).lower())
        return f"the {name} role" if name else match.group(0)

    return re.sub(
        r"role:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        _sub,
        text,
    )


def _dominant_method_is_sms(data: dict) -> bool:
    """True when the most common registered second factor is text message
    codes. The plan then avoids codifying the weakest method (SPEC 10)."""
    prefs = [
        str(r.get("userPreferredMethodForSecondaryAuthentication", "")).lower()
        for r in _registration_rows(data)
        if r.get("isMfaRegistered")
    ]
    prefs = [p for p in prefs if p]
    if not prefs:
        return False
    dominant, _ = Counter(prefs).most_common(1)[0]
    return "sms" in dominant


# --- Break glass (day 1, always first) --------------------------------------------


def _break_glass_answer(
    answers: AnswersFile, assessment: dict | None = None
) -> tuple[list[str], list[str]]:
    """Break glass accounts from every question that can establish one.

    The regrade honours both the break glass question and an exclusion
    classified as a break glass account, so reading only the first made the
    plan disagree with the grade: it told the operator to create a new Global
    Administrator that already existed, failed the day one precondition, and
    left the real account off the exclusion list (BUGS.md item 23)."""
    names = (assessment or {}).get("names") or {}
    guids: list[str] = []
    labels: list[str] = []
    answer = answers.answers.get("break-glass")
    if answer is not None and isinstance(answer.value, list):
        guids = [str(v) for v in answer.value if _GUID_RE.match(str(v))]
        labels = list(answer.labels) or [str(v) for v in answer.value]
    for other in answers.answers.values():
        if other.bindsTo == CHOSEN_SLOT and other.value == "breakGlassAccounts":
            subject = str(other.subject or "")
            if not subject or subject in guids:
                continue
            guids.append(subject)
            labels.append(names.get(subject.lower()) or subject)
    return guids, labels


def _break_glass_step(answers: AnswersFile, assessment: dict | None = None) -> StepCard:
    guids, labels = _break_glass_answer(answers, assessment)
    accounts = ", ".join(labels) if labels else "none confirmed yet"
    if labels:
        title = "Verify the break glass accounts"
        first_actions = [
            _PORTAL,
            f"Under Users, confirm each break glass account exists and is enabled: {accounts}.",
            "Test each break glass account by signing in with it in a private browser window.",
        ]
    else:
        title = "Create a break glass account"
        first_actions = [
            _PORTAL,
            "Under Users, create one new cloud only account named for emergency access, for example emergency-access-01.",
            "Give the account the Global Administrator role.",
            "Set a long random password of at least 24 characters.",
            "Test the account by signing in with it in a private browser window.",
        ]
    return StepCard(
        id="pending",
        phase=1,
        title=title,
        riskClass="high",
        affected=Affected(count=len(labels), samples=labels[:5]),
        preconditions=[
            Precondition(
                statement="The questionnaire confirmed the break glass account list.",
                query="answers.json: the break-glass answer is present",
                result="pass" if guids or labels else "fail",
            ),
        ],
        actions=first_actions + [
            "Store each break glass password in a sealed envelope or an offline company password vault that at least two people can reach.",
            "Write down where the credentials are stored and who can reach them.",
            "Check that every policy this plan deploys lists every break glass account under Exclude before it is turned on.",
        ],
        verification=Verification(
            query=(
                "users and conditional_access_policies datasets from a fresh "
                "'iamai collect': each break glass account is present and "
                "enabled, and every policy this plan deploys excludes it"
            ),
            expected="Every break glass account exists, is enabled, and is excluded from every deployed policy.",
        ),
        rollback=[
            "This step changes no policy. If an account was created by mistake, disable it under Users in the Entra admin center.",
        ],
        watchFor=[
            "A break glass account that shows routine day to day sign ins is being used as a normal account. Investigate immediately.",
            "Nothing else in this plan starts until this step is done.",
        ],
    )


# --- Service principal preflight (SPEC 10) ------------------------------------------


def _targeted_app_ids(control: dict) -> list[str]:
    apps = (control.get("canonical") or {}).get("apps") or {}
    ids = []
    for entry in list(apps.get("include") or []) + list(apps.get("exclude") or []):
        if entry not in _APP_TOKENS and _GUID_RE.match(str(entry)):
            ids.append(str(entry).lower())
    return sorted(set(ids))


def _sp_preflight(control: dict, data: dict) -> tuple[Precondition, list[str], list[str]] | None:
    """(precondition, provisioning actions, missing appIds) for an app
    targeted policy, or None when the policy targets no specific
    application."""
    app_ids = _targeted_app_ids(control)
    if not app_ids:
        return None
    sps = _service_principals(data)
    missing = [app_id for app_id in app_ids if app_id not in sps]
    precondition = Precondition(
        statement=(
            "Every application this policy targets exists in the tenant "
            f"({len(app_ids)} application id{'s' if len(app_ids) != 1 else ''} checked)."
        ),
        query=(
            "service_principals dataset: an entry with a matching appId exists "
            "for each of: " + ", ".join(app_ids)
        ),
        result="fail" if missing else "pass",
    )
    provisioning: list[str] = []
    if missing:
        provisioning.append(
            "Before creating the policy, add the missing application to the tenant. "
            "Open a PowerShell window and run: Connect-MgGraph -Scopes \"Application.ReadWrite.All\"."
        )
        for app_id in missing:
            provisioning.append(
                f"Run: New-MgServicePrincipal -AppId \"{app_id}\". This registers the application so the policy can target it."
            )
        provisioning.append(
            "Run 'iamai collect' and confirm the application now appears before continuing."
        )
    return precondition, provisioning, missing


# --- Conditional Access step construction --------------------------------------------


def _strength_names(artifact: dict, data: dict) -> dict[tuple, str]:
    names: dict[tuple, str] = {}
    for control in artifact.get("controls", []):
        if control.get("surface") == "authenticationStrength":
            names[tuple(control["canonical"]["combos"])] = str(control.get("sourceName", ""))
    for strength in data.get("auth_strengths") or []:
        from iamai.canon import canonical_strength

        combos = tuple(canonical_strength(strength)["combos"])
        names.setdefault(combos, str(strength.get("displayName", "")))
    return names


def _population_actions(
    control: dict, data: dict, break_glass_labels: list[str], lists: list[ListDetail]
) -> list[str]:
    tokens = (control.get("canonical") or {}).get("users") or {}
    include = list(tokens.get("include") or [])
    actions: list[str] = []
    role_names = _role_names(data)
    roles = sorted(
        role_names.get(t.split(":", 1)[1], t.split(":", 1)[1])
        for t in include if t.startswith("role:")
    )
    if "All" in include:
        actions.append("Under Users, select All users.")
    if roles:
        actions.append(_list_action(
            "Under Users, select Directory roles and pick", roles,
            title="Directory roles this policy covers",
            unit="directory roles", lists=lists,
        ))
    if any(t.startswith("guests:") for t in include):
        actions.append("Under Users, include guest and external users.")
    if not actions:
        actions.append("Under Users, select the accounts and groups the standard scopes this policy to.")
    if break_glass_labels:
        actions.append(_list_action(
            "Under Exclude, select Users and groups and add the break glass accounts",
            break_glass_labels,
            title="Break glass accounts to exclude",
            unit="break glass accounts", lists=lists,
        ))
    else:
        actions.append("Under Exclude, select Users and groups and add every break glass account.")
    return actions


def _apps_actions(control: dict, data: dict, lists: list[ListDetail]) -> list[str]:
    apps = (control.get("canonical") or {}).get("apps") or {}
    include = list(apps.get("include") or [])
    sps = _service_principals(data)
    if include == ["All"]:
        return ["Under Target resources, select All resources."]
    if include == ["Office365"]:
        return ["Under Target resources, select Office 365."]
    if apps.get("userActions"):
        return ["Under Target resources, choose User actions and select: " + ", ".join(apps["userActions"]) + "."]
    named = [f"{sps.get(app_id, 'application')} ({app_id})" for app_id in include if app_id not in _APP_TOKENS]
    if named:
        return [_list_action(
            "Under Target resources, select Select resources and add", named,
            title="Applications this policy targets",
            unit="applications", lists=lists,
        )]
    return ["Under Target resources, match the standard's application scope."]


def _conditions_actions(control: dict) -> list[str]:
    canonical = control.get("canonical") or {}
    actions: list[str] = []
    client_apps = [t for t in canonical.get("clientAppTypes") or [] if t != "all"]
    if client_apps:
        labels = ", ".join(_CLIENT_APP_LABELS.get(t, t) for t in client_apps)
        actions.append(f"Under Conditions, select Client apps and tick: {labels}.")
    flows = canonical.get("authFlows") or []
    if "deviceCodeFlow" in flows:
        actions.append("Under Conditions, select Authentication flows and tick Device code flow.")
    if "authenticationTransfer" in flows:
        actions.append("Under Conditions, select Authentication flows and tick Authentication transfer.")
    risk = canonical.get("risk") or {}
    if risk.get("signIn"):
        actions.append("Under Conditions, set Sign-in risk to: " + ", ".join(risk["signIn"]) + ".")
    if risk.get("user"):
        actions.append("Under Conditions, set User risk to: " + ", ".join(risk["user"]) + ".")
    platforms = canonical.get("platforms")
    if platforms:
        actions.append(
            "Under Conditions, select Device platforms and include: "
            + ", ".join(platforms.get("include") or ["all platforms"]) + "."
        )
    if canonical.get("locations"):
        actions.append("Under Conditions, select Locations and match the standard's location scope, including the trusted location created earlier in this plan.")
    return actions


def _grant_actions(control: dict, strength_names: dict[tuple, str], *, downgrade_strength: bool) -> list[str]:
    canonical = control.get("canonical") or {}
    if canonical.get("category") == "block":
        return ["Under Grant, select Block access."]
    grant = canonical.get("grant") or {}
    actions: list[str] = []
    combos = grant.get("strengthCombos")
    if combos and downgrade_strength:
        actions.append("Under Grant, select Grant access and tick Require multifactor authentication.")
    elif combos:
        name = strength_names.get(tuple(combos), "the sign in strength the standard defines")
        actions.append(f"Under Grant, select Grant access, then Require authentication strength, and choose '{name}'.")
    for item in grant.get("controls") or []:
        actions.append(f"Under Grant, tick {_GRANT_CONTROL_LABELS.get(item, item)}.")
    if not actions:
        actions.append("Under Grant, select Grant access with the controls the standard defines.")
    if grant.get("operator") == "AND" and (len(grant.get("controls") or []) + (1 if combos else 0)) > 1:
        actions.append("Under Grant, set For multiple controls to Require all the selected controls.")
    return actions


def _session_actions(control: dict) -> list[str]:
    session = (control.get("canonical") or {}).get("session") or {}
    actions: list[str] = []
    sif = session.get("signInFrequency")
    if sif:
        if sif.get("frequencyInterval") == "everyTime":
            actions.append("Under Session, select Sign-in frequency and choose Every time.")
        else:
            actions.append(f"Under Session, select Sign-in frequency and set it to {sif.get('value')} {sif.get('type')}.")
    if session.get("persistentBrowser"):
        actions.append(f"Under Session, set Persistent browser session to {session['persistentBrowser'].get('mode')}.")
    if session.get("secureSignInSession"):
        actions.append("Under Session, tick Require token protection for sign-in sessions.")
    cae = session.get("continuousAccessEvaluation")
    if cae:
        actions.append(f"Under Session, set Customize continuous access evaluation to {cae.get('mode')}.")
    if session.get("disableResilienceDefaults"):
        actions.append("Under Session, tick Disable resilience defaults.")
    if session.get("applicationEnforcedRestrictions"):
        actions.append("Under Session, tick Use app enforced restrictions.")
    return actions


def _cap_watch_for(control: dict, unknowns: list[str]) -> list[str]:
    canonical = control.get("canonical") or {}
    watch: list[str] = []
    grant_controls = set((canonical.get("grant") or {}).get("controls") or [])
    if canonical.get("devices") or grant_controls & {"compliantDevice", "domainJoinedDevice"}:
        watch.append(_DEVICE_POSTURE_WARNING)
    if control_signature(canonical) == "cap:block-legacy-auth":
        watch.append(
            "Sign in analysis covers a 30 day window. A monthly job that uses "
            "legacy authentication can hide outside the window; a longer "
            "report-only period is the mitigation."
        )
    if canonical.get("category") == "require":
        watch.append(_LOCKOUT_WARNING)
    apps = (canonical.get("apps") or {})
    if _GUID_RE.match(str((apps.get("include") or [""])[0] or "")):
        watch.append(
            "Windows Cloud Login can be silently absent from application "
            "lists. Its absence is a known optional deviation and does not "
            "mean the policy is wrong."
        )
    for item in unknowns:
        if "incomplete" in item or "skipped" in item:
            watch.append(f"Known data gap while this step runs: {item}")
    if not watch:
        watch.append("Watch the sign in logs for unexpected blocks in the first hours after any change.")
    return watch


def _cap_deploy_step(
    control: dict,
    result: dict,
    data: dict,
    strength_names: dict[tuple, str],
    break_glass_labels: list[str],
    unknowns: list[str],
    *,
    downgrade_strength: bool,
) -> StepCard:
    from iamai.grade import _names_index, _with_names

    name = str(control.get("sourceName") or result["controlId"])
    role_names = _role_names(data)
    names = _names_index(data)
    enforcing = _already_enforced(result, data)
    lists: list[ListDetail] = []
    preflight = _sp_preflight(control, data)
    preconditions = [
        Precondition(
            statement="The break glass step (day 1) is complete.",
            query="This plan's day 1 verification has passed on a fresh collect.",
            result="unverified",
        ),
    ]
    provisioning: list[str] = []
    if preflight:
        precondition, provisioning, _missing = preflight
        preconditions.insert(0, precondition)
    if result["grade"] == MISSING:
        create = [
            _PORTAL,
            "Go to Protection, then Conditional Access, then Policies, then New policy.",
            f"Name the policy '{name}'.",
        ]
    else:
        existing = (result.get("matchedPolicies") or [{}])[0].get("displayName") or name
        create = [
            _PORTAL,
            f"Go to Protection, then Conditional Access, then Policies, and open the existing policy '{existing}'.",
            "Fix each difference listed below so the policy matches the standard.",
        ]
        # The state gap is handled by the phase 4 step; report-only is the
        # correct state for this phase.
        gaps = [g for g in result.get("coverageGaps") or [] if "report-only" not in g]
        for gap in gaps[:_INLINE_LIMIT]:
            resolved = _with_names(resolve_role_tokens(gap, role_names), names, set())
            action = f"Close this gap: {resolved}"
            if len(action) > _ACTION_LIMIT:
                pointer = f" The assessment report states this difference in full for control {result['controlId']}."
                action = action[: _ACTION_LIMIT - len(pointer) - 3] + "..." + pointer
            create.append(action)
        if len(gaps) > _INLINE_LIMIT:
            create.append(
                f"Close the remaining {len(gaps) - _INLINE_LIMIT} differences the same way; "
                "the assessment report lists every one."
            )
    actions = (
        provisioning
        + create
        + _population_actions(control, data, break_glass_labels, lists)
        + _apps_actions(control, data, lists)
        + _conditions_actions(control)
        + _grant_actions(control, strength_names, downgrade_strength=downgrade_strength)
        + _session_actions(control)
        + (
            [
                "Leave Enable policy set to On. This policy is already enforcing, so do "
                "not switch it to report-only: that would remove a protection the tenant "
                "already has.",
                "Select Save.",
            ]
            if enforcing
            else [
                "Set Enable policy to Report-only.",
                "Select Create, or Save if you edited an existing policy.",
            ]
        )
    )
    if result["grade"] == MISSING:
        title = f"Deploy '{name}' in report-only mode"
    elif enforcing:
        title = f"Align '{name}' with the standard, keeping it enforced"
    else:
        title = f"Align '{name}' with the standard, in report-only mode"
    return StepCard(
        id="pending",
        phase=3,
        title=title,
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(
            count=int((result.get("affected") or {}).get("count", 0)),
            samples=list((result.get("affected") or {}).get("sampleUPNs", [])),
        ),
        preconditions=preconditions,
        actions=actions,
        verification=Verification(
            query=(
                "conditional_access_policies dataset from a fresh 'iamai collect', "
                f"then 'iamai assess': control {result['controlId']}"
            ),
            expected=(
                f"Control {result['controlId']} grades FULL or FUNCTIONAL, with the policy "
                "in report-only state, and the report-only checkpoint shows no unexpected failures."
            ),
        ),
        rollback=[
            "Open the policy in the Entra admin center.",
            "Set Enable policy to Off.",
            "Select Save.",
        ],
        watchFor=_cap_watch_for(control, unknowns),
        controlId=result["controlId"],
        lists=lists,
    )


def _cap_enable_step(
    control: dict,
    result: dict,
    unknowns: list[str],
    *,
    legacy_inventory_planned: bool,
    cohort_split: bool,
    registered_count: int,
) -> StepCard:
    name = str(control.get("sourceName") or result["controlId"])
    canonical = control.get("canonical") or {}
    preconditions = [
        Precondition(
            statement="Checkpoint G3 passed: 7 consecutive days of report-only operation with zero unexpected failures.",
            query=(
                "sign in logs from a fresh 'iamai collect': "
                "appliedConditionalAccessPolicies entries for this policy show no "
                "unexpected reportOnlyFailure results"
            ),
            result="unverified",
        ),
        Precondition(
            statement="Checkpoint G2 passed: registration coverage is at least 95 percent for the enforcement cohort.",
            query="registration_details dataset from a fresh 'iamai collect': isMfaRegistered is true for at least 95 percent of enabled member accounts",
            result="unverified",
        ),
    ]
    if canonical.get("category") == "block" and legacy_inventory_planned:
        preconditions.append(
            Precondition(
                statement="The legacy authentication inventory step is complete and every affected account has a replacement or a documented exception.",
                query="This plan's legacy authentication inventory step shows verification passed.",
                result="unverified",
            )
        )
    actions = [
        _PORTAL,
        f"Go to Protection, then Conditional Access, then Policies, and open '{name}'.",
        "Confirm every break glass account is still listed under Exclude.",
    ]
    if cohort_split:
        actions.extend([
            f"Under Users, scope the policy to the enforcement group of registered people first ({registered_count} accounts). Unregistered people stay in the registration campaign and move in as they register.",
        ])
    actions.extend([
        "Set Enable policy to On.",
        "Select Save.",
        "Watch the sign in logs for the next two hours for unexpected blocks.",
    ])
    return StepCard(
        id="pending",
        phase=4,
        title=f"Turn on '{name}'",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(
            count=int((result.get("affected") or {}).get("count", 0)),
            samples=list((result.get("affected") or {}).get("sampleUPNs", [])),
        ),
        preconditions=preconditions,
        actions=actions,
        verification=Verification(
            query=(
                "conditional_access_policies dataset from a fresh 'iamai collect', "
                f"then 'iamai assess': control {result['controlId']}"
            ),
            expected=f"Control {result['controlId']} grades FULL or FUNCTIONAL with the policy state enabled.",
        ),
        rollback=[
            "Open the policy in the Entra admin center.",
            "Set Enable policy to Report-only.",
            "Select Save.",
            "Investigate what failed before trying again.",
        ],
        watchFor=_cap_watch_for(control, unknowns),
        controlId=result["controlId"],
    )


# --- Non policy surface steps ---------------------------------------------------------


def _method_step(control: dict, result: dict) -> StepCard:
    canonical = control.get("canonical") or {}
    method = str(canonical.get("method", ""))
    state = "On" if canonical.get("state") == "enabled" else "Off"
    actions = [
        _PORTAL,
        "Go to Protection, then Authentication methods, then Policies.",
        f"Open the {method} method.",
        f"Set Enable to {state}.",
    ]
    targets = canonical.get("includeTargets") or []
    if any(t.get("target") == "all_users" for t in targets):
        actions.append("Set Target to All users.")
    for key, value in (canonical.get("settings") or {}).items():
        actions.append(f"Set {key} to {value}.")
    for key, value in (canonical.get("features") or {}).items():
        actions.append(f"Set {key} to {value}.")
    actions.append("Select Save.")
    return StepCard(
        id="pending",
        phase=2,
        title=f"Configure the {method} sign in method",
        riskClass=str(result.get("riskClass", "low")),
        affected=Affected(
            count=int((result.get("affected") or {}).get("count", 0)),
            samples=list((result.get("affected") or {}).get("sampleUPNs", [])),
        ),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=actions,
        verification=Verification(
            query=f"auth_methods_policy dataset from a fresh 'iamai collect', then 'iamai assess': control {result['controlId']}",
            expected=f"Control {result['controlId']} grades FULL.",
        ),
        rollback=[
            "Open the method again in the Entra admin center.",
            "Put back the previous setting recorded in the latest snapshot.",
            "Select Save.",
        ],
        watchFor=[
            f"Turning a sign in method {state.lower()} affects everyone at once. If people report sign in problems, roll back first and investigate second.",
        ],
        controlId=result["controlId"],
    )


def _campaign_step(control: dict, result: dict, unregistered: list[str]) -> StepCard:
    canonical = control.get("canonical") or {}
    snooze = canonical.get("snoozeDurationInDays")
    actions = [
        _PORTAL,
        "Go to Protection, then Authentication methods, then Registration campaign.",
        f"Set State to {'Enabled' if canonical.get('state') == 'enabled' else 'Disabled'}.",
    ]
    if snooze is not None:
        actions.append(f"Set Days allowed to snooze to {snooze}.")
    actions.extend([
        "Set the target to All users.",
        "Select Save.",
    ])
    return StepCard(
        id="pending",
        phase=2,
        title="Turn on the registration campaign",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(count=len(unregistered), samples=unregistered[:5]),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=actions,
        verification=Verification(
            query=f"auth_methods_policy dataset from a fresh 'iamai collect', then 'iamai assess': control {result['controlId']}",
            expected=f"Control {result['controlId']} grades FULL and registration coverage climbs toward the 95 percent checkpoint.",
        ),
        rollback=[
            "Open the registration campaign settings again.",
            "Set State back to its previous value.",
            "Select Save.",
        ],
        watchFor=[
            "People can snooze the prompt. Coverage climbs over days, not hours; the registration checkpoint measures it.",
        ],
        controlId=result["controlId"],
    )


# Where each tenant wide setting lives, and what it costs to change. These are
# one switch each rather than a policy rollout, so they carry no report only
# stage and no watch period: the change is immediate and the rollback is the
# same switch. The cost column is what someone will actually notice tomorrow,
# because a step that hides its cost gets reverted in a hurry by whoever it
# surprised.
_SETTING_STEPS = {
    "guest-001": (
        "Limit what guests can see of the directory",
        ["Go to Identity, then External Identities, then External collaboration settings.",
         "Under Guest user access, choose the limited or restricted option rather than the "
         "one that gives guests the same access as members.",
         "Select Save."],
        "Guests lose the ability to browse your staff list. The restricted option also stops "
        "working with Forms, Project, Viva Engage and Planner in SharePoint, so choose limited "
        "if you use those.",
    ),
    "guest-002": (
        "Limit who can invite guests",
        ["Go to Identity, then External Identities, then External collaboration settings.",
         "Under Guest invite settings, choose the option that allows only administrators and "
         "the guest inviter role to invite.",
         "Select Save."],
        "People who used to invite outside collaborators themselves now have to ask. Decide who "
        "holds the guest inviter role before you make the change, or the requests have nowhere "
        "to go.",
    ),
    "apps-001": (
        "Stop everyone being able to register applications",
        ["Go to Identity, then Users, then User settings.",
         "Set Users can register applications to No.",
         "Select Save.",
         "Assign the application developer role to anyone who genuinely needs it, by name."],
        "Developers and anyone wiring up an integration will hit a wall. The application "
        "developer role gives it back to named people, so identify them first.",
    ),
    "consent-001": (
        "Stop people approving applications for themselves",
        ["Go to Identity, then Applications, then Enterprise applications, then Consent and "
         "permissions, then User consent settings.",
         "Choose either that user consent is not allowed, or that it is allowed only for apps "
         "from verified publishers for permissions you have classified as low impact.",
         "Select Save."],
        "This is the one people notice. Anyone signing into a new tool will be told to ask an "
        "administrator instead of clicking through. Turn on the request workflow in the same "
        "visit or you have replaced a risk with a dead end.",
    ),
    "consent-002": (
        "Stop people approving applications for themselves",
        ["Go to Identity, then Applications, then Enterprise applications, then Consent and "
         "permissions, then User consent settings.",
         "Set user consent to Do not allow user consent.",
         "Select Save."],
        "Every application approval now goes to an administrator. Turn on the request workflow "
        "in the same visit or you have replaced a risk with a dead end.",
    ),
    "consent-003": (
        "Give people a way to request an application",
        ["Go to Identity, then Applications, then Enterprise applications, then Admin consent "
         "settings.",
         "Set Users can request admin consent to apps they are unable to consent to, to Yes.",
         "Add the reviewers who should receive the requests, and confirm they are notified.",
         "Select Save."],
        "Somebody now has a queue to work. Agree who watches it and how quickly they answer "
        "before you switch it on, because a request nobody answers is worse than no request.",
    ),
    "riskyapps-001": (
        "Send risky application requests to an administrator",
        ["Go to Identity, then Applications, then Enterprise applications, then Consent and "
         "permissions, then User consent settings.",
         "Turn the risk based step up back on, so a consent request that looks risky is sent "
         "for administrator approval instead of being approved by the person who was asked.",
         "Select Save."],
        "Somebody turned this off deliberately at some point, so find out why before turning it "
        "back on. It only bites where user consent is allowed at all, and it sends the riskiest "
        "requests to an administrator rather than blocking them.",
    ),
    "tenants-001": (
        "Stop everyone being able to create tenants",
        ["Go to Identity, then Users, then User settings.",
         "Set Restrict non-admin users from creating tenants to Yes.",
         "Select Save.",
         "Assign the tenant creator role to anyone who genuinely needs it, by name."],
        "Almost nobody notices this one. Anyone running trials or test directories will need "
        "the tenant creator role.",
    ),
    "bitlocker-001": (
        "Stop people retrieving their own disk recovery keys",
        ["Go to Identity, then Devices, then Device settings.",
         "Set Restrict users from recovering the BitLocker keys for their owned devices to Yes.",
         "Select Save."],
        "Recovery now goes through whoever runs your help desk. Make sure they can retrieve a "
        "key and know they are expected to, before you switch it off for everyone else.",
    ),
}


# Controls that describe the same switch at two strengths. Key is the looser
# one, value is the stricter one that makes it redundant.
_SUPERSEDES = {"consent-001": "consent-002"}


def _standing_access_step(result: dict) -> StepCard:
    """Take Global Administrator off the accounts that hold it around the clock.

    This one is deliberately not a switch. Which accounts should keep the role
    is a judgement about who does what, and getting it wrong locks somebody out
    of their own tenant, so the step asks for a decision and a rehearsal rather
    than describing a toggle.
    """
    return StepCard(
        id="pending",
        phase=2,
        title="Take permanent Global Administrator off everyday accounts",
        riskClass=str(result.get("riskClass", "high")),
        affected=Affected(count=0, samples=[]),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete, and the emergency "
                          "accounts have been signed into successfully.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=[
            _PORTAL,
            "Go to Identity, then Roles and administrators, then Global Administrator, and "
            "list every account holding it permanently.",
            "Decide which of those are emergency accounts. Those keep the role permanently, "
            "because that is what they are for.",
            "For everyone else, make the assignment eligible rather than permanent, so they "
            "activate the role when they need it and hold nothing the rest of the time. This "
            "needs Entra ID P2. Without it, the equivalent is a separate administrator account "
            "used only for administrative work, kept apart from the everyday account.",
            "Have each affected person activate the role once, with you watching, before you "
            "remove their permanent assignment.",
        ],
        verification=Verification(
            query=f"roles dataset from a fresh 'iamai collect', then 'iamai assess': control {result['controlId']}",
            expected=f"Control {result['controlId']} grades FULL, meaning only the emergency "
                     "accounts hold Global Administrator permanently.",
        ),
        rollback=[
            "Open Roles and administrators, then Global Administrator.",
            "Add the permanent assignment back for the affected account.",
            "The emergency accounts are untouched by this step and remain a way in.",
        ],
        watchFor=[
            "Do not remove your own permanent assignment until somebody else has activated "
            "the role successfully, or you can be left unable to undo this. The emergency "
            "accounts exist for exactly this moment, so confirm they work first.",
            "Anything running as a person rather than as an application will stop working "
            "when that person's standing access goes. Find those before the change, not after.",
        ],
        controlId=result["controlId"],
    )


def _setting_step(control: dict, result: dict) -> StepCard:
    """One tenant wide switch, with what it costs stated up front."""
    control_id = result["controlId"]
    title, actions, cost = _SETTING_STEPS[control_id]
    dataset = ("admin_consent_request_policy"
               if result.get("surface") == "adminConsentRequestPolicy"
               else "authorization_policy")
    return StepCard(
        id="pending",
        phase=2,
        title=title,
        riskClass=str(result.get("riskClass", "medium")),
        # These settings apply to the whole tenant rather than to a population
        # this tool can count, so a number here would be invented.
        affected=Affected(count=0, samples=[]),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=[_PORTAL] + list(actions),
        verification=Verification(
            query=f"{dataset} dataset from a fresh 'iamai collect', then 'iamai assess': control {control_id}",
            expected=f"Control {control_id} grades FULL.",
        ),
        rollback=[
            "Open the same settings page.",
            "Set the value back to what it was before this step.",
            "Select Save.",
        ],
        watchFor=[cost],
        controlId=control_id,
    )


def _cross_tenant_step(result: dict, answers) -> StepCard:
    """The partner MFA trust decision, either unanswered or answered 'review'."""
    answered_review = "cross-tenant-mfa-trust" in getattr(answers, "answers", {})
    if answered_review:
        actions = [
            _PORTAL,
            "Go to Identity, then External Identities, then Cross-tenant access settings.",
            "Open Default settings and select the Trust settings tab, and note whether "
            "Trust multifactor authentication from Microsoft Entra tenants is ticked.",
            "Open each organisation under Organizational settings and check the same "
            "Trust settings tab, because a partner entry can turn trust on even when "
            "the default is off.",
            "For each organisation you no longer work with or do not recognise, untick "
            "the trust boxes, or remove the organisation entry.",
            "For each organisation the trust should stay for, run the questionnaire "
            "again with 'iamai wizard' and answer that the trust is deliberate, so the "
            "decision is recorded.",
        ]
    else:
        actions = [
            "Run 'iamai wizard' and answer the question about trusting other "
            "organisations' second sign in step.",
            "If the trust is deliberate, answer that it was decided on purpose and the "
            "record is complete.",
            "If nobody remembers deciding it, follow this step's remaining actions to "
            "review the settings before answering.",
            _PORTAL,
            "Go to Identity, then External Identities, then Cross-tenant access "
            "settings, and review the Trust settings tab under Default settings and "
            "under each organisation.",
        ]
    return StepCard(
        id="pending",
        phase=2,
        title="Decide whether to trust partner organisations' second sign in step",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(count=0, samples=[]),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=actions,
        verification=Verification(
            query=(
                "cross_tenant_access dataset from a fresh 'iamai collect', then "
                "'iamai assess': control xtenant-001"
            ),
            expected=(
                "Control xtenant-001 grades FULL once the decision is recorded, or "
                "stops applying once no organisation's multifactor claim is trusted."
            ),
        ),
        rollback=[
            "Open the same Trust settings tab.",
            "Set the trust boxes back to what they were before this step.",
            "Select Save.",
        ],
        watchFor=[
            "Turning trust off means people from that organisation are asked for a "
            "second step here even though they already passed one at home. That is "
            "safer but noisier, so tell the partner's contact before changing it.",
        ],
        controlId=result["controlId"],
    )


def _device_code_carveout_step(result: dict) -> StepCard:
    """An application scoped device code carve out, rescoped to accounts."""
    return StepCard(
        id="pending",
        phase=2,
        title="Rescope the device code exception to the device accounts",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(count=0, samples=[]),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=[
            "Make a list of the specific accounts your meeting room screens or shared "
            "devices sign in with. If they are not in one group yet, create a group "
            "and put those accounts in it.",
            _PORTAL,
            "Go to Protection, then Conditional Access, and open the policy that "
            "blocks the device code flow.",
            "Under Target resources, set the policy to cover all resources, removing "
            "any application it currently leaves out.",
            "Under Users, add the device account group to Exclude.",
            "Select Save.",
        ],
        verification=Verification(
            query=(
                "conditional_access_policies dataset from a fresh 'iamai collect', "
                "then 'iamai assess': control devicecode-001"
            ),
            expected=(
                "Control devicecode-001 grades FULL, or stops applying because the "
                "block has no exceptions left."
            ),
        ),
        rollback=[
            "Open the same policy.",
            "Set Target resources and the excluded users back to what they were "
            "before this step.",
            "Select Save.",
        ],
        watchFor=[
            "The meeting room devices must be tested the same day: sign one in with "
            "the device code flow after the change to confirm the exception still "
            "covers it.",
        ],
        controlId=result["controlId"],
    )


def _tap_step(unregistered: list[str]) -> StepCard:
    return StepCard(
        id="pending",
        phase=2,
        title="Onboard unregistered people with a Temporary Access Pass",
        riskClass="medium",
        affected=Affected(count=len(unregistered), samples=unregistered[:5]),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=[
            "Send the announcement message from the communication templates section to everyone.",
            _PORTAL,
            "Go to Protection, then Authentication methods, then Policies, and confirm Temporary Access Pass is enabled.",
            "For each person who has not registered, create a Temporary Access Pass under Users, then Authentication methods, then Add authentication method.",
            "Ask each person to sign in with the pass and register the Microsoft Authenticator app when prompted.",
            "Send the reminder message from the communication templates section after three days to anyone still unregistered.",
        ],
        verification=Verification(
            query="registration_details dataset from a fresh 'iamai collect': isMfaRegistered per account",
            expected="Registration coverage reaches at least 95 percent of enabled member accounts (checkpoint G2).",
        ),
        rollback=[
            "Temporary Access Passes expire on their own. Delete any unused pass under the person's Authentication methods.",
        ],
        watchFor=[
            "A Temporary Access Pass is a sign in credential. Hand it over in person or by voice, never by email.",
            "The straggler tail is allowed to run past day 14 by design; people move into enforcement as they register.",
        ],
    )


def _legacy_inventory_step(context: dict, service_labels: list[str]) -> StepCard:
    legacy = context.get("legacyAuth") or {}
    samples = [u for u in legacy.get("sampleUPNs") or [] if u]
    clients = legacy.get("clients") or []
    lists: list[ListDetail] = []
    replacement_actions = [
        "For each account, plan a replacement: a modern app, an app password retirement, or a documented exception.",
    ]
    if service_labels:
        replacement_actions.append(_list_action(
            "Cross check the service accounts confirmed in the questionnaire",
            service_labels,
            title="Confirmed service accounts",
            unit="service accounts", lists=lists,
        ))
    return StepCard(
        id="pending",
        phase=2,
        title="Inventory legacy authentication use",
        riskClass="high",
        affected=Affected(count=len(samples), samples=samples[:5]),
        preconditions=[
            Precondition(
                statement="Sign in logs were collected for the analysis window.",
                query="signins_interactive.jsonl.gz present in the latest snapshot",
                # Asserted as passing regardless, so the report rendered
                # "checked now: pass" for a file that might not exist. A
                # fabricated fact in a tool whose contract is that it never
                # guesses (BUGS.md item 26).
                result=(
                    "fail"
                    if (context.get("legacyAuth") or {}).get("incomplete")
                    else ("pass" if (context.get("legacyAuth") or {}).get("collected") else "unverified")
                ),
            ),
        ],
        actions=[
            _PORTAL,
            "Go to Entra ID, then Monitoring, then Sign-in logs.",
            "Add a filter on Client app and select the legacy protocols: " + (", ".join(clients) if clients else "Exchange ActiveSync and Other clients") + ".",
            "List every account that appears, and what application it was using.",
        ] + replacement_actions + [
            "Do not turn on any block policy until every account on the list has a plan.",
        ],
        lists=lists,
        verification=Verification(
            query="sign in logs from a fresh 'iamai collect': events whose client app is not a modern browser or app",
            expected="Every remaining legacy sign in traces to a documented exception.",
        ),
        rollback=[
            "This step changes nothing; it only builds the inventory list.",
        ],
        watchFor=[
            "Sign in analysis covers a 30 day window. A monthly job using legacy authentication can hide outside the window; keep the block in report-only longer if unsure.",
        ],
    )


def _strength_step(control: dict, result: dict) -> StepCard:
    name = str(control.get("sourceName") or result["controlId"])
    combos = [str(c) for c in (control.get("canonical") or {}).get("combos") or []]
    lists: list[ListDetail] = []
    combos_action = _list_action(
        "Allow exactly these method combinations and nothing else", combos,
        title="Method combinations this strength allows",
        unit="method combinations", lists=lists,
    )
    return StepCard(
        id="pending",
        phase=2,
        title=f"Create the sign in strength '{name}'",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(
            count=int((result.get("affected") or {}).get("count", 0)),
            samples=list((result.get("affected") or {}).get("sampleUPNs", [])),
        ),
        preconditions=[
            Precondition(
                statement="The break glass step (day 1) is complete.",
                query="This plan's day 1 verification has passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=[
            _PORTAL,
            "Go to Protection, then Authentication methods, then Authentication strengths, then New authentication strength.",
            f"Name it '{name}'.",
            combos_action,
            "Select Create.",
        ],
        lists=lists,
        verification=Verification(
            query=f"auth_strengths dataset from a fresh 'iamai collect', then 'iamai assess': control {result['controlId']}",
            expected=f"Control {result['controlId']} grades FULL (matched by combination set, names do not matter).",
        ),
        rollback=[
            "A strength definition does nothing until a policy uses it. Delete it under Authentication strengths if it was created wrongly.",
        ],
        watchFor=[
            "The definition is matched by its combination set, not its name. Adding extra combinations weakens it and downgrades the grade.",
        ],
        controlId=result["controlId"],
    )


def _location_step(
    control: dict, result: dict, trusted_networks: list[str],
    named_locations: list[str] | None = None,
) -> StepCard:
    name = str(control.get("sourceName") or result["controlId"])
    content = (control.get("canonical") or {}).get("content") or {}
    # A slotted location is the standard's trusted location by definition; an
    # unslotted one carries its own isTrusted flag.
    is_trusted = content.get("slot") == "trustedLocations" or bool(content.get("isTrusted"))
    lists: list[ListDetail] = []
    ranges, rejected_networks = _ip_ranges(trusted_networks or [])
    if ranges:
        range_action = _list_action(
            "Add the company network addresses confirmed in the questionnaire as IP ranges",
            ranges,
            title="Company network IP ranges",
            unit="IP ranges", lists=lists,
        )
        if rejected_networks:
            range_action += f" Left out, not valid addresses: {', '.join(rejected_networks)}."
    elif named_locations:
        # The questionnaire answer named an existing location rather than
        # typing addresses, which binds the slot but leaves trustedNetworks
        # empty. Reporting that as nothing confirmed contradicted what the
        # operator actually answered (BUGS.md item 27).
        range_action = (
            "The questionnaire confirmed an existing network location rather than a "
            "list of addresses, so open that location and check its ranges are still "
            "right instead of creating a new one."
        )
    else:
        range_action = "Add the company's public network addresses as IP ranges. No trusted networks were confirmed in the questionnaire, so confirm them with whoever manages the network first."
    actions = [
        _PORTAL,
        "Go to Protection, then Conditional Access, then Named locations, then New location (IP ranges).",
        f"Name it '{name}'.",
        range_action,
    ]
    if is_trusted:
        actions.append("Tick Mark as trusted location.")
    actions.append("Select Create.")
    return StepCard(
        id="pending",
        phase=2,
        title=f"Create the named network location '{name}'",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(count=0, samples=[]),
        preconditions=[
            Precondition(
                statement="The questionnaire confirmed which networks are trusted.",
                query="answers.json: the trusted-locations answer",
                result="pass" if (trusted_networks or named_locations) else "fail",
            ),
        ],
        actions=actions,
        verification=Verification(
            query=f"named_locations dataset from a fresh 'iamai collect', then 'iamai assess': control {result['controlId']}",
            expected=f"Control {result['controlId']} is matched once this tenant has its trusted network location. The match is by the trusted role, not by the exact addresses, so this tenant's own ranges are fine.",
        ),
        rollback=[
            "Delete the location under Named locations if no policy references it yet.",
        ],
        watchFor=[
            "This location stands in for the standard's trusted network. It holds this tenant's own addresses, and the assessment matches it by that trusted role once you mark it trusted and confirm it in the questionnaire, not by the exact ranges. Make sure the addresses are the ones whoever manages the network gave you.",
        ],
        controlId=result["controlId"],
        lists=lists,
    )


def _staged_strength_step(control: dict, result: dict, strength_names: dict[tuple, str]) -> StepCard:
    name = str(control.get("sourceName") or result["controlId"])
    combos = ((control.get("canonical") or {}).get("grant") or {}).get("strengthCombos") or []
    strength = strength_names.get(tuple(combos), "the sign in strength the standard defines")
    return StepCard(
        id="pending",
        phase=5,
        title=f"Staged: raise '{name}' to the required sign in strength",
        riskClass=str(result.get("riskClass", "medium")),
        affected=Affected(
            count=int((result.get("affected") or {}).get("count", 0)),
            samples=list((result.get("affected") or {}).get("sampleUPNs", [])),
        ),
        preconditions=[
            Precondition(
                statement="Most people have registered a method stronger than text message codes.",
                query="registration_details dataset from a fresh 'iamai collect': methodsRegistered per account includes a stronger method for the large majority",
                result="unverified",
            ),
        ],
        actions=[
            _PORTAL,
            f"Go to Protection, then Conditional Access, then Policies, and open '{name}'.",
            f"Under Grant, replace Require multifactor authentication with Require authentication strength and choose '{strength}'.",
            "Select Save.",
            "Watch the sign in logs for the next two hours for unexpected blocks.",
        ],
        verification=Verification(
            query=f"conditional_access_policies dataset from a fresh 'iamai collect', then 'iamai assess': control {result['controlId']}",
            expected=f"Control {result['controlId']} grades FULL with the strength requirement in place.",
        ),
        rollback=[
            "Open the policy again.",
            "Put back Require multifactor authentication in place of the strength requirement.",
            "Select Save.",
        ],
        watchFor=[
            "The immediate enforcement deliberately used a standard multifactor requirement because the dominant registered method was text message codes. This staged step is where the stronger requirement lands.",
            _LOCKOUT_WARNING,
        ],
        controlId=result["controlId"],
    )


def _straggler_step(unregistered: list[str]) -> StepCard:
    return StepCard(
        id="pending",
        phase=5,
        title="Move newly registered people into enforcement",
        riskClass="low",
        affected=Affected(count=len(unregistered), samples=unregistered[:5]),
        preconditions=[
            Precondition(
                statement="Enforcement is on for the registered cohort (phase 4 complete).",
                query="This plan's phase 4 verifications have passed on a fresh collect.",
                result="unverified",
            ),
        ],
        actions=[
            "Once a week, run 'iamai collect' and check the registration numbers.",
            "Add each newly registered person to the enforcement group.",
            "For anyone still unregistered after two weeks, create a Temporary Access Pass and walk them through registration directly.",
            "When everyone is registered, change the policy scope from the enforcement group to All users and retire the group.",
        ],
        verification=Verification(
            query="registration_details dataset from a fresh 'iamai collect': isMfaRegistered per account",
            expected="Every enabled member account is registered or has a documented exception, and the policy covers All users.",
        ),
        rollback=[
            "Remove a person from the enforcement group if they are locked out, issue a Temporary Access Pass, and add them back once registered.",
        ],
        watchFor=[
            "This tail is allowed to run past day 14 by design. Do not force the last stragglers by locking them out.",
        ],
    )


# --- Checkpoints and phases (schema field names keep "gate") -------------------------


def _gates(alias: str) -> list[Gate]:
    return [
        Gate(
            id="G1",
            statement="Every break glass account exists, is enabled, and is excluded from every policy this plan deploys.",
            query=(
                f"'iamai collect {alias}': users dataset shows each break glass account "
                "present with accountEnabled true; conditional_access_policies shows each "
                "deployed policy lists every break glass account under exclusions"
            ),
            extensionRule="If this checkpoint is not met, nothing else in the plan starts. Fix the accounts, re-run the collection, and check again.",
        ),
        Gate(
            id="G2",
            statement="Registration coverage is at least 95 percent for the enforcement cohort.",
            query=(
                f"'iamai collect {alias}': registration_details dataset shows isMfaRegistered "
                "true for at least 95 percent of enabled member accounts"
            ),
            extensionRule="If coverage is below 95 percent, phases 3 and 4 slip day for day. Keep the campaign and the pass onboarding running, then re-run 'iamai collect' and 'iamai assess' to recheck.",
        ),
        Gate(
            id="G3",
            statement="7 consecutive days of report-only operation with zero unexpected failures.",
            query=(
                f"'iamai collect {alias}': sign in logs show appliedConditionalAccessPolicies "
                "entries for this plan's policies with no unexpected reportOnlyFailure results "
                "over 7 consecutive days"
            ),
            extensionRule="Any unexpected failure resets the 7 day count after the cause is fixed. Enforcement (phase 4) waits for a clean run; the operator re-runs collect and assess to recheck.",
        ),
        Gate(
            id="G4",
            statement="A fresh assessment grades every control this plan deployed FULL or FUNCTIONAL.",
            query=f"'iamai collect {alias}' then 'iamai assess {alias}': the grades of the deployed controls",
            extensionRule="If any deployed control grades below FUNCTIONAL, fix that control's step and re-run collect and assess before calling the plan done.",
        ),
        Gate(
            id="G5",
            statement="Every remaining account is registered or has a documented exception.",
            query=(
                f"'iamai collect {alias}': registration_details dataset shows isMfaRegistered "
                "true for every enabled member account not on the exception list"
            ),
            extensionRule="This tail runs past day 14 by design. Recheck weekly until it closes.",
        ),
    ]


def _phases(has_tail: bool, start: date) -> list[Phase]:
    def span(first: int, last: int) -> str:
        if first == last:
            return _fmt_date(_plan_day(start, first))
        return f"{_fmt_date(_plan_day(start, first))} to {_fmt_date(_plan_day(start, last))}"

    phases = [
        Phase(number=1, name="Protect the emergency accounts", days="Day 1",
              dates=span(1, 1),
              purpose="Verify or create the break glass accounts and their exclusions. Nothing else ships before this.",
              gateId="G1"),
        Phase(number=2, name="Prepare", days="Days 2 to 4",
              dates=span(2, 4),
              purpose="Registration groundwork, method settings, locations, strengths, and the legacy authentication inventory. Registration comes before any enforcement.",
              gateId="G2"),
        Phase(number=3, name="Watch", days="Days 5 to 11",
              dates=span(5, 11),
              purpose="Deploy policies in report-only mode and watch real sign ins against them. Report-only always comes before enforced.",
              gateId="G3"),
        Phase(number=4, name="Enforce", days="Days 12 to 14",
              dates=span(12, 14),
              purpose="Turn on the watched policies for the registered cohort.",
              gateId="G4"),
    ]
    if has_tail:
        phases.append(
            Phase(number=5, name="Finish the tail", days="After day 14",
                  dates=f"From {_fmt_date(_plan_day(start, 15))}",
                  purpose="Move stragglers into enforcement as they register and land the staged strength requirement. Allowed to run past day 14 by design.",
                  gateId="G5"),
        )
    return phases


# --- Watch list and comms -------------------------------------------------------------


def _service_account_labels(answers: AnswersFile, assessment: dict | None = None) -> list[str]:
    names = (assessment or {}).get("names") or {}
    labels: list[str] = []
    for answer in answers.answers.values():
        if answer.bindsTo == "serviceAccounts" and isinstance(answer.value, list):
            labels.extend(answer.labels or [str(v) for v in answer.value])
        if answer.bindsTo == "chosenSlot" and answer.value == "serviceAccounts":
            # For a single choice answer, labels holds the chosen option, not
            # the account, so the watch list read "A service account used by
            # software, not a person" and the cross check the step exists to
            # enable became impossible (BUGS.md item 24).
            subject = (answer.subject or "").lower()
            labels.append(names.get(subject) or answer.subject or "")
    return sorted(set(l for l in labels if l))


def _already_enforced(result: dict, data: dict) -> bool:
    """True when the policy this step aligns is already enforcing.

    An enforcing policy must never be switched to report-only to align it:
    that removes a protection the tenant already has, and nothing in a later
    phase would put it back (BUGS.md items 1 and 2)."""
    matched = (result.get("matchedPolicies") or [{}])[0].get("id")
    if not matched:
        return False
    for cap in data.get("conditional_access_policies") or []:
        if str(cap.get("id", "")) == str(matched):
            return str(cap.get("state", "")) == "enabled"
    return False


def _ip_ranges(values: list[str]) -> tuple[list[str], list[str]]:
    """Confirmed network answers as CIDR ranges, and the ones that are not.

    A bare IPv4 address becomes /32 and a bare IPv6 address becomes /128.
    Anything that is not an address or a network is rejected rather than
    decorated: '2001:db8::1/32' is roughly 2^96 addresses and 'the Sydney
    office/32' is nonsense, and both would do real damage if a person pasted
    them into a trusted location (BUGS.md item 3)."""
    import ipaddress

    ranges: list[str] = []
    rejected: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            if "/" in value:
                ranges.append(str(ipaddress.ip_network(value, strict=False)))
            else:
                address = ipaddress.ip_address(value)
                ranges.append(f"{value}/32" if address.version == 4 else f"{value}/128")
        except ValueError:
            rejected.append(value)
    return ranges, rejected


def _onboarding_groups(assessment: dict, answers: AnswersFile) -> list[str]:
    """Groups classified as a temporary onboarding exclusion.

    The exclusion is sanctioned so the grade reflects what the group is for,
    but it is a real weakening while it exists, so it is watched rather than
    forgotten (SPEC-PUBLIC, and the operator's ruling on classified groups)."""
    # For a single choice answer, labels holds the chosen option, not the thing
    # the question was about. Resolve the subject through the assessment's name
    # index instead, so the watch list names the group.
    names = assessment.get("names") or {}
    labels: list[str] = []
    for answer in answers.answers.values():
        if answer.bindsTo == CHOSEN_SLOT and answer.value == "onboardingGroups":
            subject = (answer.subject or "").lower()
            labels.append(names.get(subject) or answer.subject or "")
    return sorted({label for label in labels if label})


def _watch_list(assessment: dict, answers: AnswersFile, missing_sp_apps: list[str], params: dict) -> list[WatchItem]:
    items: list[WatchItem] = []
    for label in _onboarding_groups(assessment, answers):
        items.append(WatchItem(
            item=label,
            kind="account",
            reason=(
                "People are excluded from a protection while they set up a new sign "
                "in method. It is a gap for as long as anyone is in it. Empty the "
                "group once everyone has finished, then remove the exclusion. Longer "
                "term, onboarding people with an identity check plus a one time pass, "
                "or handing out a security key that is already registered, removes the "
                "need for this exclusion entirely."
            ),
        ))
    _, labels = _break_glass_answer(answers, assessment)
    for label in labels:
        items.append(WatchItem(item=label, kind="account",
                               reason="Break glass account. It should show no routine sign in activity."))
    legacy = (assessment.get("context") or {}).get("legacyAuth") or {}
    for upn in legacy.get("sampleUPNs") or []:
        if upn:
            items.append(WatchItem(item=upn, kind="account",
                                   reason="Signed in with a legacy protocol during the collection window."))
    for client in legacy.get("clients") or []:
        items.append(WatchItem(item=client, kind="application",
                               reason="Legacy protocol client seen in the collection window. It will stop working when the block is enforced."))
    for label in _service_account_labels(answers, assessment):
        items.append(WatchItem(item=label, kind="account",
                               reason="Confirmed service account. Policy changes can break the software that uses it."))
    for app_id in missing_sp_apps:
        items.append(WatchItem(item=app_id, kind="application",
                               reason="Targeted by a planned policy but not present in the tenant yet. The preflight step provisions it."))
    special = str(params.get("specialHandling") or "").strip()
    if special and special.lower() not in ("no", "none", "n/a", "not at the moment.", "not at the moment"):
        items.append(WatchItem(item="Accounts needing special care (from the questionnaire)", kind="account",
                               reason=special))
    seen: set[str] = set()
    unique: list[WatchItem] = []
    for item in items:
        key = f"{item.kind}:{item.item}"
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _comms(unregistered_count: int, start: date) -> dict[str, str]:
    from iamai.report import render_comms

    return render_comms({
        "registration_deadline": f"{_fmt_date(_plan_day(start, 11))} (day 11 of the rollout)",
        "enforcement_day": f"{_fmt_date(_plan_day(start, 12))} (day 12 of the rollout)",
        "uses_tap": unregistered_count > 0,
    })


def _start_date(supplied: str | None, tz_name: str) -> date:
    if supplied:
        return date.fromisoformat(supplied)
    try:
        from zoneinfo import ZoneInfo

        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc
    return datetime.now(tz).date()


# --- Entry point ------------------------------------------------------------------


def generate_plan(
    assessment: dict,
    answers: AnswersFile,
    artifact: dict,
    data: dict,
    *,
    tenant_id: str,
    alias: str,
    start_date: str | None = None,
) -> dict:
    """Build the plan record from the assessment, the answers, the baseline
    artifact, and the latest snapshot data. start_date is an ISO date
    (YYYY-MM-DD) supplied by the operator; when absent, the plan starts on
    the generation date in the reportTimezone the questionnaire confirmed
    (falling back to UTC when that timezone cannot be loaded)."""
    params = parameters(answers)
    start = _start_date(start_date, str(params.get("reportTimezone") or "UTC"))
    tier = str(params.get("licenseTier") or "none")
    allowed_requirements = _TIER_ALLOWS.get(tier, {"none"})
    controls_by_id = {c["id"]: c for c in artifact.get("controls", [])}
    _, break_glass_labels = _break_glass_answer(answers, assessment)
    strength_names = _strength_names(artifact, data)
    registered, unregistered = _cohort(data)
    sms_dominant = _dominant_method_is_sms(data)
    context = assessment.get("context") or {}
    unknowns = list(assessment.get("unknowns") or [])

    steps: list[StepCard] = [_break_glass_step(answers, assessment)]
    not_included: list[dict] = []
    missing_sp_apps: list[str] = []
    staged_strength: list[StepCard] = []
    legacy_block_planned = False
    require_cap_planned = False
    cohort_split_needed = bool(unregistered)

    needs_work = [r for r in assessment.get("controls", []) if r["grade"] in (PARTIAL, MISSING)]
    for result in assessment.get("controls", []):
        if result["grade"] == UNKNOWN:
            unknowns.append(
                f"Control {result['controlId']} was graded UNKNOWN, so no step was generated for it. "
                "Re-run 'iamai collect' to close the data gap, then regenerate the plan."
            )

    for result in needs_work:
        control = controls_by_id.get(result["controlId"])
        if control is None:
            continue
        requirement = str(control.get("licenseRequirement", "none"))
        if requirement not in allowed_requirements:
            not_included.append({
                "controlId": result["controlId"],
                "title": control.get("intent", result["controlId"]),
                "reason": (
                    f"This protection needs an Entra ID {requirement} license and the questionnaire "
                    f"confirmed the tenant tier as {tier}. The plan only includes steps the license can support."
                ),
            })
            continue
        surface = result.get("surface")
        if surface == "conditionalAccess":
            canonical = control.get("canonical") or {}
            signature = control_signature(canonical)
            if signature == "cap:block-legacy-auth":
                legacy_block_planned = True
            if canonical.get("category") == "require":
                require_cap_planned = True
            downgrade = bool(
                sms_dominant
                and canonical.get("category") == "require"
                and ((canonical.get("grant") or {}).get("strengthCombos"))
            )
            preflight = _sp_preflight(control, data)
            if preflight:
                missing_sp_apps.extend(preflight[2])
            steps.append(_cap_deploy_step(
                control, result, data, strength_names, break_glass_labels,
                unknowns, downgrade_strength=downgrade,
            ))
            # The rollout always ends in enforcement. The standard accepting a
            # report-only policy is a grading concession, not a rollout target:
            # a report-only policy protects nobody (BUGS.md item 1). The step is
            # skipped only when the policy is already enforcing.
            if not _already_enforced(result, data):
                steps.append(_cap_enable_step(
                    control, result, unknowns,
                    legacy_inventory_planned=True,
                    cohort_split=cohort_split_needed and signature == "cap:user-mfa",
                    registered_count=len(registered),
                ))
            if downgrade:
                staged_strength.append(_staged_strength_step(control, result, strength_names))
        elif surface == "authenticationStrength":
            steps.append(_strength_step(control, result))
        elif surface == "authMethods":
            steps.append(_method_step(control, result))
        elif surface == "registrationCampaign":
            steps.append(_campaign_step(control, result, unregistered))
        elif surface == "privilegedAccess":
            steps.append(_standing_access_step(result))
        elif surface == "crossTenantAccess":
            steps.append(_cross_tenant_step(result, answers))
        elif surface == "conditionalAccessCollection":
            steps.append(_device_code_carveout_step(result))
        elif surface in ("authorizationPolicy", "adminConsentRequestPolicy"):
            if result["controlId"] in _SETTING_STEPS:
                steps.append(_setting_step(control, result))
            else:
                # A finding with no step is a dead end, which is the one thing
                # this document must never be. Say so rather than dropping it.
                not_included.append({
                    "controlId": result["controlId"],
                    "title": control.get("intent", result["controlId"]),
                    "reason": (
                        "This was graded but no step has been written for it yet, so it is "
                        "listed here rather than left out silently."
                    ),
                })
        elif surface == "namedLocation":
            steps.append(_location_step(
                control, result,
                list(params.get("trustedNetworks") or []),
                list(params.get("trustedLocations") or []),
            ))

    legacy_seen = bool((context.get("legacyAuth") or {}).get("eventCount"))
    if legacy_block_planned or legacy_seen:
        steps.append(_legacy_inventory_step(context, _service_account_labels(answers, assessment)))
    if unregistered and require_cap_planned:
        steps.append(_tap_step(unregistered))
    steps.extend(staged_strength)
    if unregistered and require_cap_planned:
        steps.append(_straggler_step(unregistered))

    # Where two controls describe the same switch at different strengths, doing
    # the stricter one satisfies both, so listing both reads as two jobs when
    # it is one. The looser step is dropped rather than the stricter, because
    # dropping the stricter would quietly lower what the plan asks for.
    planned = {s.controlId for s in steps}
    superseded = {loose for loose, strict in _SUPERSEDES.items() if strict in planned}
    steps = [s for s in steps if s.controlId not in superseded]

    steps.sort(key=lambda s: s.phase)
    for index, step in enumerate(steps, start=1):
        step.id = f"step-{index:02d}"

    has_tail = any(step.phase == 5 for step in steps)
    watch = _watch_list(assessment, answers, sorted(set(missing_sp_apps)), params)

    plan = Plan(
        tenantId=tenant_id,
        alias=alias,
        generatedAt=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        basedOnAssessment=str(assessment.get("generatedAt", "")),
        startDate=start.isoformat(),
        licenseTier=tier,
        phases=_phases(has_tail, start),
        gates=_gates(alias),
        steps=steps,
        watchList=watch,
        notIncluded=not_included,
        bestEffortNote=(
            "This plan is the strongest position the licences this tenant "
            f"already owns can reach. {len(not_included)} protection(s) in the "
            "standard are left out because they need a licence the tenant does "
            "not have; they are listed below with what each one would protect "
            "against. Nothing in this plan depends on buying anything."
            if not_included
            else "Every protection in the standard is achievable with the "
            "licences this tenant already owns. Nothing has been left out."
        ),
        unknowns=unknowns,
        # Only ship end user messages when the plan actually does the thing
        # they announce. They were rendered unconditionally, so a two step
        # report-only plan still told staff that the second step became
        # required on a specific date (BUGS.md item 25).
        comms=(
            _comms(len(unregistered), start)
            if any(step.phase >= 4 for step in steps)
            else {}
        ),
        scopeNote=(
            "This plan is executed by a person, never by this tool. Every checkpoint "
            "is checked by re-running 'iamai collect' and 'iamai assess'. An unmet "
            "checkpoint slips the phases that depend on it; the dates move, the "
            "order never does. Nothing here expires. "
            + str(assessment.get("scopeNote", ""))
        ),
    )
    return plan.model_dump()
