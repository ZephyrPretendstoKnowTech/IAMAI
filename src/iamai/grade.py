"""Parity engine (SPEC section 7).

Six grades per baseline control, two-stage algorithm:

Stage 1, structural match: canonicalize every target policy; exact canonical
equality with an acceptable enforcement state is FULL.

Stage 2, coverage computation: derive the control's required coverage tuple
(population, applications, conditions, grant/session controls, state) and test
whether the union of acceptable target policies achieves at least that
coverage. Anything the model cannot prove is not guessed: it grades PARTIAL or
UNKNOWN with a note. Strength comparisons use the combination-set partial
order (subset = at least as strong). Block is its own category and never
satisfies a require intent or vice versa.

Conditional Access is additive: when several policies apply to a sign in, all
of their grant controls must be satisfied. Two consequences, both required by
SPEC-PUBLIC sections 3 and 4. A policy whose requirement is broader than the
standard's cannot weaken one whose requirement is narrower, so it is not a
gap on its own; it is only reported when the population it reaches turns out
to be uncovered. And coverage may be split across policies on the population
and application axes alike, so a class or an application counts as uncovered
only when every contributing policy misses it. Reaching part of the required
scope is still protection and still identifies the policy as a contributor,
which is why a contributing policy can never also be reported as surplus.

The conservative rule is absolute: ambiguity grades down, never up. Splitting
coverage across policies never claims more than the collected data proves.
"""

from __future__ import annotations

import gzip
import heapq
import json
import re
import time
from pathlib import Path

from iamai.canon import (
    SlotResolver,
    canonical_campaign,
    canonical_cap,
    canonical_method,
    canonical_strength,
    strength_at_least_as_strong,
)

FULL = "FULL"
FUNCTIONAL = "FUNCTIONAL"
PARTIAL = "PARTIAL"
MISSING = "MISSING"
UNKNOWN = "UNKNOWN"
SURPLUS = "SURPLUS"

GA_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Datasets each surface depends on; an incomplete pull makes its controls
# UNKNOWN, never guessed.
_SURFACE_DATASETS = {
    # canonical_cap resolves grants through auth_strengths and locations
    # through named_locations, so a skipped one changes the canonical form
    # rather than grading UNKNOWN (BUGS.md item 9).
    "conditionalAccess": ("conditional_access_policies", "auth_strengths", "named_locations"),
    "authenticationStrength": ("auth_strengths",),
    "authMethods": ("auth_methods_policy",),
    "registrationCampaign": ("auth_methods_policy",),
    "namedLocation": ("named_locations",),
}

_MODERN_CLIENT_APPS = {"Browser", "Mobile Apps and Desktop clients", ""}


_GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# Datasets that carry identity display names. Sign-in logs are deliberately not
# walked: they are large and add nothing this index does not already have.
_NAMED_DATASETS = (
    "groups",
    "users",
    "roles",
    "service_principals",
    "named_locations",
    "auth_strengths",
    "conditional_access_policies",
)


def _names_index(data: dict) -> dict[str, str]:
    """Identifier to display name, for output only.

    Names never participate in matching or grading (CLAUDE.md engine rule and
    SPEC-PUBLIC section 5). This index exists so a person reading a report sees
    "Breakglass Exclusion" rather than a bare GUID.
    """
    names: dict[str, str] = {}

    def walk(node) -> None:
        if isinstance(node, dict):
            label = node.get("displayName") or node.get("userPrincipalName")
            if isinstance(label, str) and label:
                for key in ("id", "appId"):
                    ident = node.get(key)
                    if isinstance(ident, str) and ident:
                        names.setdefault(ident.lower(), label)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for dataset in _NAMED_DATASETS:
        walk(data.get(dataset))
    return names


def _with_names(text: str, names: dict[str, str], unresolved: set[str]) -> str:
    """Render identifiers in display text with their names, GUID kept as detail."""

    def replace(match: re.Match) -> str:
        guid = match.group(0)
        label = names.get(guid.lower())
        if label:
            return f"{label} ({guid})"
        unresolved.add(guid)
        return guid

    return _GUID_RE.sub(replace, text)


def _dataset_status(manifest: dict | None) -> dict[str, dict]:
    status: dict[str, dict] = {}
    for record in (manifest or {}).get("datasets", []):
        status[record.get("dataset", "")] = record
    return status


def _surface_unknown_reason(surface: str, data: dict, dataset_status: dict) -> str | None:
    for dataset in _SURFACE_DATASETS.get(surface, ()):
        record = dataset_status.get(dataset)
        if record is not None and record.get("skipped"):
            return f"The {dataset} data was skipped during collection."
        if record is not None and not record.get("complete", True):
            return f"The {dataset} collector pull was incomplete."
        if data.get(dataset) is None:
            return f"The {dataset} data is missing from the snapshot."
    return None


# --- Coverage axes ------------------------------------------------------------


def _state_acceptable(state: str | None, required_state: str) -> bool:
    if required_state == "enabled":
        return state == "enabled"
    return state in ("enabled", "enabledForReportingButNotEnforced")


def _apps_shortfall(candidate: dict, required: dict, deviations: list[str]) -> set[str] | None:
    """Required applications this candidate does not reach.

    None means the candidate is not comparable on this axis at all. An empty set
    means it reaches every required application. Otherwise the set is what it
    misses, which is a real coverage gap rather than a reason to discard the
    policy: reaching some of the required applications is still protection, and
    a policy that reaches more than the standard asks for is not penalised.
    """
    c_inc, r_inc = set(candidate.get("include") or []), set(required.get("include") or [])
    c_exc, r_exc = set(candidate.get("exclude") or []), set(required.get("exclude") or [])
    if c_exc - r_exc - set(deviations):
        return None
    if (candidate.get("userActions") or []) != (required.get("userActions") or []):
        return None
    if "All" in c_inc:
        return set()
    if "All" in r_inc:
        return {"All"}
    return (r_inc - c_inc) - set(deviations)


def _set_covers(candidate: list | None, required: list | None, all_token: str | None = None) -> bool:
    """Candidate axis covers required axis: superset, with an absorbing token."""
    c, r = set(candidate or []), set(required or [])
    if all_token and all_token in c:
        return True
    if all_token and all_token in r:
        return all_token in c
    return r <= c


def _platforms_cover(candidate: dict | None, required: dict | None) -> bool:
    if candidate is None:
        return True  # not configured = applies to every platform
    if required is None:
        return False  # candidate narrows where the baseline does not
    if not _set_covers(candidate.get("include"), required.get("include"), "all"):
        return False
    return not (set(candidate.get("exclude") or []) - set(required.get("exclude") or []))


def _locations_cover(candidate: dict | None, required: dict | None) -> bool:
    if candidate is None:
        return True
    if required is None:
        return False
    if [repr(x) for x in candidate.get("include") or []] != [repr(x) for x in required.get("include") or []]:
        return False
    return [repr(x) for x in candidate.get("exclude") or []] == [repr(x) for x in required.get("exclude") or []]


def _risk_cover(candidate: dict | None, required: dict | None) -> bool:
    if candidate is None:
        return True  # no risk condition = fires on every sign-in
    if required is None:
        return False  # candidate only fires on risky sign-ins: narrower
    return _set_covers(candidate.get("signIn"), required.get("signIn")) and _set_covers(
        candidate.get("user"), required.get("user")
    )


def _grant_strong_enough(candidate: dict, required: dict) -> tuple[bool, list[str]]:
    """Candidate grant at least as strong as required. Returns (ok, notes)."""
    notes: list[str] = []
    r_combos = required.get("grant", {}).get("strengthCombos")
    c_combos = candidate.get("grant", {}).get("strengthCombos")
    r_controls = set(required.get("grant", {}).get("controls") or [])
    c_controls = set(candidate.get("grant", {}).get("controls") or [])
    if r_combos:
        if not c_combos:
            return False, ["The sign in strength requirement is missing."]
        if not strength_at_least_as_strong(c_combos, r_combos):
            if set(r_combos) <= set(c_combos):
                notes.append("Allows weaker sign in methods than the standard.")
            else:
                notes.append("The allowed sign in methods are not comparable to the standard's; not treated as covering.")
            return False, notes
    if r_controls - c_controls:
        return False, [f"Missing required controls: {', '.join(sorted(r_controls - c_controls))}."]
    if (c_controls - r_controls) and candidate.get("grant", {}).get("operator") == "OR" and len(c_controls | ({"s"} if c_combos else set())) > 1:
        # An OR of extra alternatives can be satisfied by a weaker path.
        return False, ["Extra OR alternatives could allow a weaker path; not treated as covering."]
    return True, notes


def _sign_in_frequency_hours(block: dict | None) -> float | None:
    """A sign in frequency as hours, so two of them can be compared.

    "Every time" is the strictest possible setting and sorts below any
    interval. Returns None when the shape cannot be read, which grades down
    rather than guessing."""
    if not block or not block.get("isEnabled"):
        return None
    if block.get("frequencyInterval") == "everyTime":
        return 0.0
    value = block.get("value")
    unit = block.get("type")
    if not isinstance(value, (int, float)) or unit not in ("days", "hours"):
        return None
    return float(value) * (24.0 if unit == "days" else 1.0)


def _session_cover(candidate: dict | None, required: dict | None) -> bool:
    """Candidate session controls are at least as strict as required.

    Sign in frequency is an ordered quantity, not a value to match: a tenant
    reauthenticating every 7 days satisfies a 14 day standard, and failing it
    for being stricter would be the conservative rule inverted. Everything
    else compares exactly, because nothing else here has a defined order."""
    for key, value in (required or {}).items():
        got = (candidate or {}).get(key)
        if key == "signInFrequency":
            required_hours = _sign_in_frequency_hours(value)
            candidate_hours = _sign_in_frequency_hours(got)
            if required_hours is None:
                if got != value:
                    return False
                continue
            if candidate_hours is None or candidate_hours > required_hours:
                return False
            continue
        if got != value:
            return False
    return True


# Canonical keys stage 2 compares explicitly. Anything outside this set is
# handled by _uncompared_axes_match below.
_COMPARED_KEYS = frozenset({
    "surface", "category", "users", "apps", "clientAppTypes",
    "platforms", "locations", "risk", "grant", "session", "authFlows",
})


def _uncompared_axes_match(candidate: dict, required: dict) -> bool:
    """Conservative backstop for canonical keys stage 2 does not compare.

    Without this, an axis nobody wrote a comparison for is coverage-neutral,
    which means it defaults to grading UP: a policy narrowed by a device
    filter graded as though it covered everyone. Any key outside
    _COMPARED_KEYS must therefore match exactly before the candidate can
    contribute, so adding a new axis to canonical_cap fails closed rather than
    open (BUGS.md item 5)."""
    for key in (set(candidate) | set(required)) - _COMPARED_KEYS:
        if candidate.get(key) != required.get(key):
            return False
    return True


def _hours_phrase(hours: float | None) -> str:
    if hours is None:
        return "not at all"
    if hours == 0:
        return "every time"
    if hours < 24:
        count = int(hours) if float(hours).is_integer() else hours
        return f"every {count} hours"
    days = hours / 24
    count = int(days) if float(days).is_integer() else round(days, 1)
    return f"every {count} days"


def _session_shortfall_note(candidate: dict | None, required: dict | None) -> str:
    """Why this policy's session settings fall short, in plain words.

    "No policy contributes coverage" is factually wrong when a policy does
    reach these people and merely holds the session open too long, and it
    turns a settings change into what reads like building from scratch
    (BUGS.md item 37)."""
    wanted = _sign_in_frequency_hours((required or {}).get("signInFrequency"))
    got = _sign_in_frequency_hours((candidate or {}).get("signInFrequency"))
    if wanted is not None and (got is None or got > wanted):
        return (
            "People are asked to sign in again "
            f"{_hours_phrase(got)}, where the standard asks {_hours_phrase(wanted)}."
        )
    if (required or {}).get("persistentBrowser") and not (candidate or {}).get("persistentBrowser"):
        return "Staying signed in in the browser is not configured the way the standard expects."
    return "The session settings differ from the standard."


def _privileged_access_summary(
    data: dict, bindings: dict[str, list[str]], licensing: dict | None = None
) -> dict | None:
    """Standing privileged access, counted from the schedules feed.

    roleAssignments carries no type or time field, so counting from it treats
    a Privileged Identity Management activation in flight as permanent and
    reports inflated numbers to the tenants managing this best. The schedules
    feed distinguishes Assigned from Activated and carries the expiry
    (ASSUMPTIONS.md note 25 item j).

    The schedules feed is itself a Privileged Identity Management endpoint and
    returns AadPremiumLicenseRequired without Entra ID P2. That is not a reason
    to give up: a tenant that cannot license PIM cannot be running PIM, so no
    assignment it holds can be an activation in flight, and roleAssignments is
    then an exact answer rather than an inflated one. The reason to prefer the
    schedules feed disappears in precisely the case where it is unavailable.
    """
    roles = data.get("roles") or {}
    schedules = roles.get("roleAssignmentSchedules")
    break_glass = {g.lower() for g in bindings.get("breakGlassAccounts", [])}

    if schedules is None:
        licensing = licensing or {}
        if not licensing.get("known") or licensing.get("entraP2"):
            # Either the licence is unknown, or the tenant has P2 and the feed
            # should have been readable. Both mean this cannot be answered.
            return None
        entries = roles.get("roleAssignments")
        if entries is None:
            return None
        # Without PIM every assignment is permanent by definition, so each one
        # counts and there is no expiry or type to weigh.
        standing = len(entries)
        standing_ga_other = sum(
            1 for e in entries
            if str(e.get("roleDefinitionId", "")).lower() == GA_ROLE_TEMPLATE_ID
            and str(e.get("principalId", "")).lower() not in break_glass
        )
        return {
            "standingAssignments": standing,
            "standingGlobalAdminsBesidesBreakGlass": standing_ga_other,
        }

    standing = 0
    standing_ga_other = 0
    for entry in schedules:
        if str(entry.get("assignmentType")) != "Assigned":
            continue
        expiry = ((entry.get("scheduleInfo") or {}).get("expiration") or {}).get("type")
        if expiry not in (None, "noExpiration"):
            continue
        standing += 1
        if str(entry.get("roleDefinitionId", "")).lower() != GA_ROLE_TEMPLATE_ID:
            continue
        if str(entry.get("principalId", "")).lower() not in break_glass:
            standing_ga_other += 1
    return {
        "standingAssignments": standing,
        "standingGlobalAdminsBesidesBreakGlass": standing_ga_other,
    }


def _cross_tenant_summary(data: dict, bindings: dict[str, list[str]]) -> dict | None:
    """Whether this tenant accepts a partner tenant's multifactor claim.

    The default configuration applies to every organisation; a partner
    configuration's null fields inherit it, and a non-null partner
    inboundTrust overrides it for that partner (ASSUMPTIONS.md note 37).
    Trusting the claim is a risk decision, not a misconfiguration, so the
    control asks that the decision be recorded rather than demanding the
    setting be off (SPEC-PUBLIC section 7 item 9).
    """
    collected = data.get("cross_tenant_access")
    if not isinstance(collected, dict):
        return None
    default = collected.get("default")
    partners = collected.get("partners")

    trusting_partners = [
        str(p.get("tenantId", ""))
        for p in (partners or [])
        if isinstance(p.get("inboundTrust"), dict)
        and p["inboundTrust"].get("isMfaAccepted") is True
    ]
    default_trusts = bool(
        isinstance(default, dict)
        and (default.get("inboundTrust") or {}).get("isMfaAccepted") is True
    )
    if default is None and not trusting_partners:
        # The default half could not be read and no partner proves trust, so
        # whether the tenant trusts anyone cannot be answered either way.
        return None

    decision = bindings.get("decision:crossTenantMfaTrust") or []
    return {
        "mfaTrustAccepted": default_trusts or bool(trusting_partners),
        "trustScope": "everyone" if default_trusts else "partners",
        "trustingPartnerTenantIds": sorted(trusting_partners),
        "partnerCount": len(partners or []),
        "decisionRecorded": bool(decision),
        "decisionDeliberate": "deliberate" in decision,
    }


def _device_code_carveout_summary(caps: list[dict], dataset_status: dict) -> dict | None:
    """How the policies that block the device code flow scope their carve outs.

    Meeting room hardware sometimes needs the device code flow, and the right
    shape for that is excluding the specific resource accounts or a device
    group from the blocking policy. The wrong shape is scoping the block by
    application: excluding an application, or including less than every
    application, reopens the flow for every user against everything the block
    no longer reaches (SPEC-PUBLIC section 7 item 10).

    Read from the raw policies rather than canonical forms because the
    judgement is about the policy's own scoping axes, not about matching a
    standard's shape.
    """
    record = dataset_status.get("conditional_access_policies")
    if record is not None and (record.get("skipped") or not record.get("complete", True)):
        return None

    blocking: list[dict] = []
    for cap in caps:
        if str(cap.get("state", "")) == "disabled":
            continue
        grant = (cap.get("grantControls") or {}).get("builtInControls") or []
        if "block" not in [str(g) for g in grant]:
            continue
        methods = str(((cap.get("conditions") or {}).get("authenticationFlows") or {})
                      .get("transferMethods") or "")
        if "deviceCodeFlow" not in {m.strip() for m in methods.split(",")}:
            continue
        blocking.append(cap)

    user_carveouts: set[str] = set()
    app_carveout_policies: list[str] = []
    for cap in blocking:
        cond = cap.get("conditions") or {}
        users = cond.get("users") or {}
        for entry in list(users.get("excludeUsers") or []) + list(users.get("excludeGroups") or []):
            user_carveouts.add(str(entry))
        apps = cond.get("applications") or {}
        include = [str(a) for a in apps.get("includeApplications") or []]
        exclude = [str(a) for a in apps.get("excludeApplications") or []]
        if exclude or (include and include != ["All"]):
            app_carveout_policies.append(str(cap.get("displayName") or cap.get("id") or ""))

    return {
        "blocksDeviceCode": bool(blocking),
        "hasCarveOut": bool(user_carveouts) or bool(app_carveout_policies),
        "userOrGroupCarveOutCount": len(user_carveouts),
        "applicationCarveOutCount": len(app_carveout_policies),
        "applicationCarveOutPolicies": sorted(app_carveout_policies),
    }


def _read_path(node, path: str):
    """Read a dotted path out of collected data, or None if it is not there."""
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _predicate_holds(node, predicate: dict) -> bool:
    """One machine checkable statement about the tenant's own configuration."""
    value = _read_path(node, str(predicate.get("path", "")))
    if "equals" in predicate:
        return value == predicate["equals"]
    if "contains" in predicate:
        wanted = predicate["contains"]
        wanted = wanted if isinstance(wanted, list) else [wanted]
        have = {str(v).lower() for v in value} if isinstance(value, list) else set()
        return all(str(w).lower() in have for w in wanted)
    if "notEquals" in predicate:
        return value != predicate["notEquals"]
    if "oneOf" in predicate:
        # Several settings have more than one acceptable answer, and the
        # strictest is not always the recommended one. Matching a set says that
        # plainly rather than picking a winner the sources do not agree on.
        allowed = predicate["oneOf"]
        allowed = allowed if isinstance(allowed, list) else [allowed]
        return any(value == a for a in allowed)
    if "withPrefixOnlyAllows" in predicate:
        # A deny list of known bad values is the wrong shape for a setting the
        # tenant can point at anything. The live lab tenant carries two consent
        # policy ids that appear in no published list, and a deny list passed
        # it silently while user consent was plainly switched on. Only values
        # known to be restrictive pass, so an unrecognised one grades down
        # rather than through (BUGS.md, conservative rule).
        if not isinstance(value, list):
            return False
        spec = predicate["withPrefixOnlyAllows"]
        prefix = str(spec.get("prefix", "")).lower()
        allowed = {str(a).lower() for a in spec.get("allows") or []}
        for entry in value:
            entry = str(entry).lower()
            if entry.startswith(prefix) and entry not in allowed:
                return False
        return True
    if "noneStartWith" in predicate:
        if not isinstance(value, list):
            return False
        prefixes = predicate["noneStartWith"]
        prefixes = prefixes if isinstance(prefixes, list) else [prefixes]
        lowered = [str(v).lower() for v in value]
        return not any(v.startswith(str(p).lower()) for v in lowered for p in prefixes)
    if "excludes" in predicate:
        # An unreadable list is not proof the value is absent from it, so an
        # answer is only given when the list was actually read.
        if not isinstance(value, list):
            return False
        unwanted = predicate["excludes"]
        unwanted = unwanted if isinstance(unwanted, list) else [unwanted]
        have = {str(v).lower() for v in value}
        return not any(str(u).lower() in have for u in unwanted)
    if "present" in predicate:
        return (value is not None) == bool(predicate["present"])
    if "atMost" in predicate:
        return isinstance(value, (int, float)) and value <= predicate["atMost"]
    if "atLeast" in predicate:
        return isinstance(value, (int, float)) and value >= predicate["atLeast"]
    return False


def _grade_conditional_control(control: dict, observed: dict | None) -> dict | None:
    """A control that only exists when the tenant has configured something.

    Some items in the standard are traps rather than requirements: restricting
    which authenticators may register is good practice, and the danger is only
    that a restriction which omits Microsoft Authenticator silently blocks its
    passkeys while security keys keep working. Nothing is wrong until the
    condition holds, so a plain control would be wrong for every tenant that
    never configured it (SPEC-PUBLIC section 7.2b).

    Returns None when the control does not apply, so the caller can leave it
    out of the score entirely rather than grading it.
    """
    if observed is None:
        return _result(
            control, UNKNOWN, [], [],
            ["The configuration this check depends on is not in the snapshot."],
        )
    for predicate in control.get("appliesWhen") or []:
        if not _predicate_holds(observed, predicate):
            return None
    failures = [
        predicate for predicate in control.get("requires") or []
        if not _predicate_holds(observed, predicate)
    ]
    if not failures:
        return _result(control, FULL, [], [], [])
    return _result(
        control, PARTIAL, [],
        [str(control.get("failureText") or "This does not match what the standard expects.")],
        [],
    )


def _category_compatible(candidate: str | None, required: str | None) -> bool:
    """Whether a candidate of this category can serve that intent.

    Block is its own world: it never satisfies a require or session intent,
    and neither satisfies it. A session requirement is different. It is an
    extra dimension on a policy rather than an alternative to a grant, and
    real tenants routinely put a sign in frequency on the very policy that
    requires multifactor authentication. Because the canonical category is
    derived from the grant, such a policy reads as "require" and could never
    contribute to a session control, so a tenant that had configured the
    protection was told it was missing entirely.

    The reverse is not true: a policy carrying only session controls proves
    nothing about a grant requirement.
    """
    if candidate == required:
        return True
    if "block" in (candidate, required):
        return False
    return required == "session"


def _population(tokens: dict) -> tuple[set[str], set[str]]:
    return set(tokens.get("include") or []), set(tokens.get("exclude") or [])


def _sanctioned(exclusions: set[str]) -> tuple[set[str], set[str]]:
    sanctioned = {t for t in exclusions if t.startswith("slot:")}
    return sanctioned, exclusions - sanctioned


# --- Per-surface grading ------------------------------------------------------


def _grade_cap_control(control: dict, target_caps: list[dict], resolver, named_locations,
                       strengths, cap_canon_cache: dict | None = None) -> dict:
    required = control["canonical"]
    required_state = control["requiredState"]
    deviations = control.get("knownOptionalDeviations") or []
    r_include, r_exclude = _population(required.get("users") or {})

    candidates = []
    for cap in target_caps:
        if str(cap.get("state", "")) == "disabled":
            # A disabled policy protects nobody. Treating it as report-only
            # evidence turned MISSING into PARTIAL and produced a gap telling
            # the reader to enforce a policy that is not running (BUGS.md
            # item 7).
            continue
        # canonical_cap depends only on (cap, resolver, named_locations,
        # strengths), none of which change across controls within one
        # assessment, so it was being recomputed identically for every
        # control -- O(controls x policies). Memoized per run on the policy's
        # identity (the same policy dicts recur across control calls), turning
        # it into O(policies) (PERF-2-003).
        if cap_canon_cache is None:
            canonical = canonical_cap(cap, resolver, named_locations, strengths)
        else:
            key = id(cap)
            canonical = cap_canon_cache.get(key)
            if canonical is None:
                canonical = canonical_cap(cap, resolver, named_locations, strengths)
                cap_canon_cache[key] = canonical
        candidates.append({
            "policy": cap,
            "canonical": canonical,
            "state": cap.get("state"),
            "state_ok": _state_acceptable(cap.get("state"), required_state),
        })

    # Stage 1: exact structural match with acceptable state.
    for cand in candidates:
        if cand["canonical"] == required and cand["state_ok"]:
            return _result(control, FULL, [cand], [], [])

    # Stage 2: axis-aligned coverage by the union of acceptable policies.
    notes: list[str] = []
    gaps: list[str] = []
    contributors = []
    downgraded_state = []
    unsanctioned_all: set[str] = set()
    weaker_overlaps: list[dict] = []

    for cand in candidates:
        canonical = cand["canonical"]
        if not _category_compatible(canonical.get("category"), required.get("category")):
            continue
        if required.get("category") == "block":
            r_flows = set(required.get("authFlows") or [])
            c_flows = set(canonical.get("authFlows") or [])
            if r_flows:
                if not r_flows <= c_flows:
                    continue
            elif c_flows:
                # Candidate blocks only specific flows: narrower than required.
                continue
        if required.get("category") == "require":
            ok, grant_notes = _grant_strong_enough(canonical, required)
            if not ok:
                # Conditional Access is additive: when several policies apply to a
                # sign in, all of their grant controls must be satisfied. A policy
                # with a broader requirement therefore cannot weaken one with a
                # narrower requirement, so this candidate simply does not
                # contribute here. Remember it, so that if the population turns out
                # to be genuinely uncovered we can say why rather than only
                # reporting the population as missing.
                if grant_notes and _population_overlaps(canonical, required):
                    c_inc, _ = _population(canonical.get("users") or {})
                    weaker_overlaps.append({
                        "cand": cand,
                        "include": c_inc,
                        "gap": "The sign in requirement is weaker than the standard.",
                        "notes": grant_notes,
                    })
                continue
        # A session requirement is checked whenever the standard carries one,
        # not only when the control's category happens to be session. The
        # category comes from the grant, so a control with both a grant and a
        # session control used to lose its session requirement entirely
        # (BUGS.md item 4).
        if required.get("session"):
            if not _session_cover(canonical.get("session"), required.get("session")):
                # A near miss has to be about the same setting. A policy that
                # sets a sign in frequency is not a weaker form of a token
                # protection requirement, it is a different control, and
                # treating it as one both buries the policy the reader must
                # actually edit and turns a genuine MISSING into a PARTIAL.
                shares_setting = bool(
                    set(required.get("session") or {}) & set(canonical.get("session") or {})
                )
                if shares_setting and _population_overlaps(canonical, required):
                    c_inc, _ = _population(canonical.get("users") or {})
                    weaker_overlaps.append({
                        "cand": cand,
                        "include": c_inc,
                        "gap": "The session requirement is weaker than the standard.",
                        "notes": [
                            _session_shortfall_note(
                                canonical.get("session"), required.get("session")
                            )
                        ],
                    })
                continue
        if required.get("category") != "block" and canonical.get("authFlows"):
            # Candidate applies only to specific authentication flows, so it is
            # narrower than a requirement that applies to all of them.
            continue
        if not _uncompared_axes_match(canonical, required):
            continue
        app_gap = _apps_shortfall(canonical.get("apps") or {}, required.get("apps") or {}, deviations)
        if app_gap is None:
            continue
        # Deviations are already subtracted from app_gap, so compare against a
        # required set with the same subtraction or the guard never fires
        # (BUGS.md item 11).
        r_apps = set((required.get("apps") or {}).get("include") or []) - set(deviations)
        if app_gap and (app_gap == {"All"} or app_gap >= r_apps):
            # Reaches none of the required applications.
            continue
        if not _set_covers(canonical.get("clientAppTypes"), required.get("clientAppTypes"), "all"):
            continue
        if not _platforms_cover(canonical.get("platforms"), required.get("platforms")):
            continue
        if not _locations_cover(canonical.get("locations"), required.get("locations")):
            continue
        if not _risk_cover(canonical.get("risk"), required.get("risk")):
            continue

        c_include, c_exclude = _population(canonical.get("users") or {})
        extra_exclusions = c_exclude - r_exclude
        _, unsanctioned = _sanctioned(extra_exclusions)
        # Role and guest-class exclusions are universal constants: they carve
        # population out of this policy's coverage arithmetically below.
        # Opaque user/group GUID exclusions cannot be verified from data;
        # those are the unsanctioned holes that downgrade (SPEC 6).
        extra_computable = {t for t in unsanctioned if t.startswith(("role:", "guests:"))}
        opaque = unsanctioned - extra_computable
        if not cand["state_ok"]:
            downgraded_state.append(cand)
            continue
        contributors.append({
            "opaque": opaque,
            "cand": cand,
            "include": c_include,
            "exclude": c_exclude,
            "coversAll": "All" in c_include,
            # Role and guest-class carve-outs are computable population, so they
            # do not disqualify this policy. They are only genuinely uncovered
            # when every contributor carves out the same class, which is
            # resolved after all contributors are known.
            "carve": extra_computable,
            "appGap": app_gap,
            "covers": set(),
        })

    covered: set[str] = set()
    app_gaps_by_token: dict[str, set[str]] = {}
    for token in r_include:
        reaching = []
        for entry in contributors:
            if token == "All":
                ok = entry["coversAll"]
            else:
                ok = (token in entry["include"] or "All" in entry["include"]) and token not in entry["exclude"]
            if ok:
                reaching.append(entry)
                covered.add(token)
                entry["covers"].add(token)
        if reaching:
            # An application is only covered for this population when a policy
            # that reaches this population also reaches that application. The
            # two axes were computed independently, so one policy per role,
            # each on a different application, graded as full coverage while a
            # role was unprotected on an application (BUGS.md item 6).
            shortfall = set.intersection(*[e["appGap"] for e in reaching])
            if shortfall:
                app_gaps_by_token[token] = shortfall
    uncovered = r_include - covered

    contributing = [e for e in contributors if e["covers"]]
    matched = [e["cand"] for e in contributing]
    # Only a policy that actually contributes may inject an unsanctioned
    # exclusion finding. An unrelated policy used to import its own exclusions
    # into this control while also appearing in surplus (BUGS.md item 8).
    for entry in contributing:
        unsanctioned_all |= entry["opaque"]

    # A carved-out class is only genuinely uncovered when every policy that
    # covers everyone carves out that same class. If one policy excludes guests
    # and another covers them, the union covers everyone.
    all_covering = [e for e in contributing if e["coversAll"] and "All" in e["covers"]]
    residual_carve: set[str] = set()
    if all_covering:
        residual_carve = set.intersection(*[e["carve"] for e in all_covering])
        # Coverage splits on this axis too. A class carved out of every broad
        # policy is still covered when another policy achieving the same intent
        # reaches it directly, which is how tenants commonly handle admins and
        # guests: one policy for everyone else, a separate one for the class.
        for entry in contributors:
            if entry["appGap"]:
                # A policy that misses required applications cannot vouch for a
                # class it only partly reaches (BUGS.md item 8).
                continue
            residual_carve -= {
                token
                for token in residual_carve
                if token in entry["include"] and token not in entry["exclude"]
            }

    # An application is only genuinely uncovered when every contributing policy
    # misses it. Coverage may be split across policies here too.
    residual_app_gap: set[str] = set()
    for shortfall in app_gaps_by_token.values():
        residual_app_gap |= shortfall

    if contributing and not uncovered and not residual_carve and not residual_app_gap and not unsanctioned_all:
        return _result(
            control, FUNCTIONAL, matched, [], [], _difference_summary(contributing, required)
        )

    if contributing or downgraded_state or weaker_overlaps or unsanctioned_all:
        if unsanctioned_all:
            gaps.append("Unsanctioned exclusions: " + ", ".join(sorted(unsanctioned_all)) + ".")
            notes.append("Accounts or groups are excluded that the standard does not sanction. The questionnaire can classify them.")
        # Population a weaker policy does reach is reported as a weak requirement
        # rather than as missing coverage, because the distinction changes what the
        # reader has to do about it.
        missing_population = uncovered | residual_carve
        weaker_reach: set[str] = set()
        for entry in weaker_overlaps:
            include = entry["include"]
            for token in missing_population:
                # The weak policy has to actually reach the token. Absorbing
                # "All" unconditionally hid the fact that most of the tenant
                # had no policy at all (BUGS.md item 10).
                if token in include or "All" in include:
                    weaker_reach.add(token)
        if weaker_reach:
            for note in dict.fromkeys(n for e in weaker_overlaps for n in e["notes"]):
                if note not in notes:
                    notes.append(note)
            for gap in dict.fromkeys(e["gap"] for e in weaker_overlaps):
                if gap not in gaps:
                    gaps.append(gap)
            matched.extend(e["cand"] for e in weaker_overlaps)
        for token in sorted(missing_population - weaker_reach):
            gaps.append(f"Population not covered: {token}.")
        for token, shortfall in sorted(app_gaps_by_token.items()):
            for app in sorted(shortfall):
                if token == "All":
                    gaps.append(f"Applications not covered: {app}.")
                else:
                    gaps.append(f"Applications not covered for {token}: {app}.")
        for cand in downgraded_state:
            gaps.append("Policy is report-only where the standard enforces.")
            matched.append(cand)
        structural = (
            _difference_summary(contributing, required, include_generic=False)
            if contributing
            else []
        )
        result = _result(control, PARTIAL, matched, gaps, notes, structural)
        if unsanctioned_all:
            # Structured tokens for the questionnaire's exclusion questions;
            # the human-readable gap text above is display only.
            result["unsanctionedExclusions"] = sorted(unsanctioned_all)
        return result

    return _result(control, MISSING, [], ["No target policy contributes coverage of this intent."], [])


def _population_overlaps(canonical: dict, required: dict) -> bool:
    c_inc, _ = _population(canonical.get("users") or {})
    r_inc, _ = _population(required.get("users") or {})
    return bool(c_inc & r_inc) or "All" in c_inc or "All" in r_inc


def _difference_summary(contributing, required, include_generic: bool = True) -> list[str]:
    """Structural findings: how this tenant's construction differs in shape.

    These never affect the grade (SPEC-PUBLIC section 2). The protection is
    present either way, so the wording states the difference plainly and says
    when the only reason to align is consistency, rather than implying risk.
    """
    if len(contributing) > 1:
        return [
            f"The protection is achieved by {len(contributing)} policies working together "
            "rather than the single policy the standard describes. The protection is "
            "equivalent. Consolidating would make this easier to review later, which is "
            "the only reason to do it."
        ]
    canonical = contributing[0]["cand"]["canonical"]
    c_inc, _ = _population(canonical.get("users") or {})
    r_inc, _ = _population(required.get("users") or {})
    if c_inc != r_inc:
        return [
            "The policy applies to a wider group of people than the standard requires. "
            "That is not a weakness and nothing needs to change for security. It is "
            "recorded so the difference stays a deliberate choice rather than an accident."
        ]
    if not include_generic:
        # On a control that already has real gaps, the catch-all would restate
        # the gap as though it were a tidiness observation. Say nothing.
        return []
    return [
        "The policy is built differently from the standard but achieves the same "
        "protection. Aligning the construction would only buy consistency."
    ]


def _grade_strength_control(control: dict, target_strengths: list[dict]) -> dict:
    # validate_pack does not check canonical shape, so an authored pack can
    # reach here without combos and used to raise KeyError out of the whole
    # assessment (BUGS.md item 33).
    required = (control.get("canonical") or {}).get("combos")
    if required is None:
        return _result(
            control, UNKNOWN, [], [],
            ["This control does not say which sign in method combinations it allows, "
             "so it cannot be graded."],
        )
    for strength in target_strengths:
        if canonical_strength(strength)["combos"] == required:
            return _result(control, FULL, [{"policy": strength}], [], [])
    weaker = []
    for strength in target_strengths:
        combos = canonical_strength(strength)["combos"]
        if set(required) < set(combos):
            weaker.append((strength, combos))
    if weaker:
        strength, combos = weaker[0]
        extra = sorted(set(combos) - set(required))
        return _result(
            control, PARTIAL, [{"policy": strength}],
            [f"Allows weaker sign in method combinations than the standard: {', '.join(extra)}."], [],
        )
    return _result(control, MISSING, [], ["No matching sign in strength definition exists."], [])


# Method settings that describe a quantity rather than a value. A tenant that
# configured one more strictly than the standard has the security effect the
# standard is asking for, so grading it down would be the conservative rule
# inverted (SPEC-PUBLIC section 3). Anything not listed here is compared
# exactly, because "stricter" has no meaning without a defined direction.
_SETTING_ORDER = {
    "TemporaryAccessPass": {
        # A shorter lived pass is a smaller window for an attacker.
        "maximumLifetimeInMinutes": "atMost",
        "defaultLifetimeInMinutes": "atMost",
        # A longer pass is harder to guess.
        "defaultLength": "atLeast",
        # A pass that dies on first use cannot be replayed.
        "isUsableOnce": "stricterIsTrue",
        # The floor on what an admin may issue. It bounds no attacker and
        # carries no security effect of its own, so it is not graded.
        "minimumLifetimeInMinutes": None,
    },
}


def _method_settings_cover(candidate, required, method) -> bool:
    """True when the tenant's method settings are at least as strict."""
    if candidate == required:
        return True
    if not isinstance(candidate, dict) or not isinstance(required, dict):
        return False
    order = _SETTING_ORDER.get(str(method))
    if order is None:
        return False
    for key, wanted in required.items():
        if key not in order:
            # An axis nobody has reasoned about yet. Fail closed so a new
            # setting cannot silently pass by being unrecognised.
            return False
        direction = order[key]
        if direction is None:
            continue
        have = candidate.get(key)
        if have == wanted:
            continue
        if direction == "stricterIsTrue":
            if have is not True:
                return False
        elif isinstance(have, bool) or isinstance(wanted, bool) or not isinstance(have, (int, float)) or not isinstance(wanted, (int, float)):
            return False
        elif direction == "atMost" and have > wanted:
            return False
        elif direction == "atLeast" and have < wanted:
            return False
    # A tenant carrying settings the standard does not mention is not
    # graded on them, but one missing a setting the standard names is.
    return all(key in candidate for key in required)


def _grade_method_control(control: dict, methods_policy: dict, resolver) -> dict:
    required = control["canonical"]
    configs = methods_policy.get("authenticationMethodConfigurations") or []
    for config in configs:
        if str(config.get("id")) != str(required.get("method")):
            continue
        canonical = canonical_method(config, resolver)
        if canonical == required:
            return _result(control, FULL, [{"policy": config}], [], [])
        gaps = []
        if canonical.get("state") != required.get("state"):
            gaps.append(
                f"The {required.get('method')} method is {canonical.get('state')} where the standard has it {required.get('state')}."
            )
        for key in ("includeTargets", "features"):
            if canonical.get(key) != required.get(key):
                gaps.append(f"The {required.get('method')} method's {key} differ from the standard.")
        if not _method_settings_cover(
            canonical.get("settings"), required.get("settings"), required.get("method")
        ):
            gaps.append(f"The {required.get('method')} method's settings differ from the standard.")
        if not gaps:
            # Every difference was a tenant configured stricter than the
            # standard. The security effect is present, so it is not a gap.
            return _result(control, FULL, [{"policy": config}], [], [])
        return _result(control, PARTIAL, [{"policy": config}], gaps, [])
    return _result(control, MISSING, [], [f"The {required.get('method')} method configuration is absent."], [])


def _grade_campaign_control(control: dict, methods_policy: dict, resolver) -> dict:
    required = control["canonical"]
    campaign = canonical_campaign(methods_policy, resolver)
    if campaign is None:
        return _result(control, MISSING, [], ["No registration campaign configuration exists."], [])
    if campaign == required:
        return _result(control, FULL, [{"policy": {"id": "registrationCampaign"}}], [], [])
    gaps = []
    # Who the campaign leaves out does not change whether people are being
    # nudged to set up a passkey, which is the whole security effect here.
    # Excluding the emergency accounts is worth doing so an emergency sign in
    # is never interrupted by a prompt, but it is a tidiness point and belongs
    # on the structural axis, which never moves a grade (SPEC-PUBLIC section 2).
    structural = []
    if campaign.get("excludeTargets") != required.get("excludeTargets"):
        structural.append(
            "The campaign does not leave out the emergency accounts, so they can "
            "be prompted to register a method during an emergency sign in."
        )
    rest_matches = all(
        campaign.get(key) == required.get(key)
        for key in ("snoozeDurationInDays", "includeTargets")
    )
    state_matches = campaign.get("state") == required.get("state")
    if not state_matches and campaign.get("state") == "default" and rest_matches \
            and required.get("state") == "enabled":
        # "Microsoft managed" reports as default, and Microsoft currently
        # manages it to on. The users are being nudged, which is the whole
        # point of the control, so failing this tenant would be a false
        # finding against people following Microsoft's own recommendation.
        # It is not FULL because the tenant is not the one holding it on.
        return _result(
            control, FUNCTIONAL, [{"policy": {"id": "registrationCampaign"}}], [], [],
            structural + [
                "The campaign is left for Microsoft to manage rather than turned on "
                "here. It is running today, but Microsoft decides that, not this tenant."
            ],
        )
    if not state_matches:
        gaps.append(f"The campaign is {campaign.get('state')} where the standard has it {required.get('state')}.")
    for key in ("snoozeDurationInDays", "includeTargets"):
        if campaign.get(key) != required.get(key):
            gaps.append(f"The campaign's {key} differs from the standard.")
    grade = PARTIAL if gaps else FULL
    return _result(control, grade, [{"policy": {"id": "registrationCampaign"}}], gaps, [], structural)


def _grade_location_control(control: dict, target_locations: list[dict], resolver) -> dict:
    from iamai.canon import canonical_location

    required = control["canonical"]["content"]
    for location in target_locations:
        if canonical_location(location, resolver) == required:
            return _result(control, FULL, [{"policy": location}], [], [])
    return _result(control, MISSING, [], ["No named location matches this content."], [])


def _result(
    control: dict,
    grade: str,
    matched,
    gaps: list[str],
    notes: list[str],
    structural: list[str] | None = None,
) -> dict:
    matched_policies = []
    for m in matched:
        policy = m.get("policy") if isinstance(m, dict) else m
        matched_policies.append({
            "id": str(policy.get("id", "")),
            "displayName": str(policy.get("displayName", policy.get("id", ""))),
        })
    return {
        "controlId": control["id"],
        "surface": control["surface"],
        "grade": grade,
        "matchedPolicies": matched_policies,
        "coverageGaps": gaps,
        "notes": notes,
        # Structural conformance is a separate axis (SPEC-PUBLIC section 2). It
        # describes how the tenant's construction differs from the standard's
        # shape. It never affects the grade or the grade counts.
        "structural": structural or [],
    }


# --- Affected population and context -----------------------------------------


def _users_list(data: dict) -> list[dict]:
    users = data.get("users") or []
    return users if isinstance(users, list) else users.get("value", [])


def _affected(control: dict, data: dict) -> dict:
    users = [u for u in _users_list(data) if u.get("accountEnabled", True)]
    tokens = set((control["canonical"].get("users") or {}).get("include") or [])
    surface = control["surface"]
    if surface in ("authMethods", "registrationCampaign", "authenticationStrength") or "All" in tokens:
        # nsmallest(5) is O(n), sorted()[:5] was O(n log n) -- same five UPNs in
        # the same order, once per control across the whole population (PERF-2-004).
        sample = heapq.nsmallest(5, (str(u.get("userPrincipalName", "")) for u in users))
        return {"count": len(users), "sampleUPNs": sample}
    if any(t.startswith("role:") for t in tokens):
        roles = data.get("roles") or {}
        template_ids = {t.split(":", 1)[1] for t in tokens if t.startswith("role:")}
        principal_ids = {
            str(a.get("principalId", "")).lower()
            for a in roles.get("roleAssignments") or []
            if str(a.get("roleDefinitionId", "")).lower() in template_ids
        }
        holders = [u for u in users if str(u.get("id", "")).lower() in principal_ids]
        sample = heapq.nsmallest(5, (str(u.get("userPrincipalName", "")) for u in holders))
        return {"count": len(holders), "sampleUPNs": sample}
    return {"count": 0, "sampleUPNs": []}


def _legacy_auth_usage(snapshot_dir: Path | None, dataset_status: dict | None = None) -> dict:
    result = {"eventCount": 0, "clients": [], "sampleUPNs": []}
    # A partial sign-in pull leaves a valid gzip holding a few events, and
    # reading it straight off disk reported a clean tenant. That conclusion
    # then removed the legacy authentication work from the questionnaire and
    # the plan entirely, so an incomplete pull looked like good news
    # (BUGS.md item 20).
    record = (dataset_status or {}).get("signins")
    if record is not None and (record.get("skipped") or not record.get("complete", True)):
        result["incomplete"] = True
        return result
    if snapshot_dir is None:
        return result
    feed = snapshot_dir / "raw" / "signins_interactive.jsonl.gz"
    if not feed.exists():
        feed = snapshot_dir / "signins_interactive.jsonl.gz"
    # Recorded so the plan can state whether the analysis rests on data,
    # rather than asserting it did (BUGS.md item 26).
    result["collected"] = feed.exists()
    if not feed.exists():
        return result
    clients: set[str] = set()
    upns: set[str] = set()
    count = 0
    with gzip.open(feed, "rt", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            client = str(event.get("clientAppUsed") or "")
            if client and client not in _MODERN_CLIENT_APPS:
                count += 1
                clients.add(client)
                if len(upns) < 5:
                    upns.add(str(event.get("userPrincipalName", "")))
    result.update({"eventCount": count, "clients": sorted(clients), "sampleUPNs": sorted(upns)})
    return result


def _service_plan_names(data: dict) -> set[str]:
    org = data.get("org_licenses") or {}
    skus = org.get("subscribedSkus") or []
    if isinstance(skus, dict):
        skus = skus.get("value", [])
    return {
        str(p.get("servicePlanName", "")).upper()
        for sku in skus
        for p in sku.get("servicePlans") or []
    }


def detected_licensing(data: dict) -> dict[str, bool]:
    """What the tenant's own subscribed SKUs prove it can license."""
    plan_names = _service_plan_names(data)
    return {
        # Whether the snapshot proves anything at all. Without licence data we
        # cannot prove a tenant lacks a licence, and excluding a control on an
        # unproven absence would quietly raise the score.
        "known": bool(plan_names),
        "entraP1": "AAD_PREMIUM" in plan_names or "AAD_PREMIUM_P2" in plan_names,
        "entraP2": "AAD_PREMIUM_P2" in plan_names,
    }


def _license_available(requirement: str, licensing: dict[str, bool]) -> bool:
    """Whether the tenant can license this control at all.

    A control the tenant cannot buy is not a failure on its part, so it is
    never graded and never counted (SPEC-PUBLIC section 6)."""
    if requirement in ("", "none"):
        return True
    if not licensing.get("known"):
        # No licence data collected, so absence is unproven. Grade the control
        # rather than excusing the tenant from it.
        return True
    if requirement == "P1":
        return bool(licensing.get("entraP1"))
    if requirement == "P2":
        return bool(licensing.get("entraP2"))
    return True


_LICENSE_LABELS = {"P1": "Entra ID P1", "P2": "Entra ID P2"}


def _context_block(data: dict, snapshot_dir: Path | None, dataset_status: dict | None = None) -> dict:
    org = data.get("org_licenses") or {}
    skus = org.get("subscribedSkus") or []
    if isinstance(skus, dict):
        skus = skus.get("value", [])
    plan_names = _service_plan_names(data)
    registration = data.get("registration_details") or []
    if isinstance(registration, dict):
        registration = registration.get("value", [])
    roles = data.get("roles") or {}
    ga_holders = [
        a for a in roles.get("roleAssignments") or []
        if str(a.get("roleDefinitionId", "")).lower() == GA_ROLE_TEMPLATE_ID
    ]
    security_defaults = data.get("security_defaults") or {}
    if isinstance(security_defaults, list):
        security_defaults = security_defaults[0] if security_defaults else {}
    domains = data.get("domains") or []
    if isinstance(domains, dict):
        domains = domains.get("value", [])
    return {
        "licenses": {
            "skuPartNumbers": sorted(str(s.get("skuPartNumber", "")) for s in skus),
            "entraP1": "AAD_PREMIUM" in plan_names or "AAD_PREMIUM_P2" in plan_names,
            "entraP2": "AAD_PREMIUM_P2" in plan_names,
        },
        "registration": {
            "totalUsers": len(registration),
            "mfaCapable": sum(1 for r in registration if r.get("isMfaCapable")),
            "mfaRegistered": sum(1 for r in registration if r.get("isMfaRegistered")),
        },
        "legacyAuth": _legacy_auth_usage(snapshot_dir, dataset_status),
        "globalAdministrators": {"count": len(ga_holders)},
        "securityDefaultsEnabled": bool(security_defaults.get("isEnabled")),
        "federatedDomains": sorted(
            str(d.get("id", "")) for d in domains
            if str(d.get("authenticationType", "")).lower() == "federated"
        ),
    }


# --- Assessment entry point ---------------------------------------------------


def assess_snapshot(
    artifact: dict,
    data: dict,
    manifest: dict | None,
    *,
    tenant_id: str,
    alias: str,
    snapshot_dir: Path | None = None,
    answer_bindings: dict[str, list[str]] | None = None,
) -> dict:
    """Grade one snapshot against a baseline artifact."""
    bindings: dict[str, list[str]] = {}
    for parameter in artifact.get("parameters", []):
        bindings.setdefault(parameter["slot"], []).extend(parameter.get("boundGuids", []))
    for slot, guids in (answer_bindings or {}).items():
        bindings.setdefault(slot, []).extend(guids)
    resolver = SlotResolver(bindings)

    dataset_status = _dataset_status(manifest)
    caps = data.get("conditional_access_policies") or []
    named_locations = data.get("named_locations") or []
    strengths = data.get("auth_strengths") or []
    # One canonicalization per policy for the whole run, shared across every
    # Conditional Access control (PERF-2-003).
    cap_canon_cache: dict = {}
    methods_policy = data.get("auth_methods_policy") or {}
    if isinstance(methods_policy, list):
        methods_policy = methods_policy[0] if methods_policy else {}

    names = _names_index(data)
    licensing = detected_licensing(data)
    results = []
    out_of_reach: list[dict] = []
    not_applicable: list[dict] = []

    # Security Defaults and Conditional Access are mutually exclusive in Entra:
    # policies cannot be enabled while Security Defaults is on, and it cannot
    # be turned on while policies exist. A tenant on Security Defaults is using
    # a simpler model, not failing a hundred policy checks, and reporting it as
    # a pile of missing controls would be both wrong and the fastest way to
    # lose a small tenant's trust (SPEC-PUBLIC section 7 item 11).
    security_defaults = data.get("security_defaults") or {}
    if isinstance(security_defaults, list):
        security_defaults = security_defaults[0] if security_defaults else {}
    security_defaults_on = bool(security_defaults.get("isEnabled"))
    matched_cap_ids: set[str] = set()
    for control in artifact.get("controls", []):
        requirement = str(control.get("licenseRequirement", "none"))
        if not _license_available(requirement, licensing):
            # Never graded and never counted. Telling a tenant it fails a
            # control it cannot buy reads as a security failure when it is a
            # purchasing decision nobody put to them (SPEC-PUBLIC section 6).
            label = _LICENSE_LABELS.get(requirement, requirement)
            out_of_reach.append({
                "controlId": control["id"],
                "intent": control.get("intent", ""),
                # Carried so the compliance crosswalk can show the item as not
                # assessed. Without this the item vanishes from the crosswalk
                # entirely, and a silently absent row reads as nothing to say.
                "citations": control.get("citations", []),
                "requires": requirement,
                "protects": control.get("rationale", ""),
                # Authored per control by the pack. Empty means no licensed
                # alternative has been written for this one yet, which is
                # stated rather than filled in with a guess (SPEC-PUBLIC
                # section 6 point 5).
                "mitigation": control.get("mitigation", ""),
                "note": (
                    f"This protection needs {label}, which this tenant's current "
                    "licensing does not include. It is not counted in the grades "
                    "and nothing here says the tenant is failing. It is listed so "
                    "the choice is visible."
                ),
            })
            continue
        if security_defaults_on and control["surface"] == "conditionalAccess":
            not_applicable.append({
                "controlId": control["id"],
                "intent": control.get("intent", ""),
                "citations": control.get("citations", []),
                "note": (
                    "This tenant uses Security Defaults, which cannot be combined "
                    "with Conditional Access policies: Entra allows one or the "
                    "other. Security Defaults already requires a second step for "
                    "everyone and blocks the oldest sign in methods, so this is "
                    "not a gap. Moving to Conditional Access is what makes this "
                    "control possible, and it needs an Entra ID P1 licence."
                ),
            })
            continue
        if control.get("checkType") == "conditional":
            observed = None
            if control["surface"] == "securityDefaults":
                observed = security_defaults
            elif control["surface"] == "authMethodsPolicy":
                observed = methods_policy
            elif control["surface"] == "privilegedAccess":
                observed = _privileged_access_summary(data, bindings, licensing)
            elif control["surface"] == "crossTenantAccess":
                observed = _cross_tenant_summary(data, bindings)
            elif control["surface"] == "conditionalAccessCollection":
                observed = _device_code_carveout_summary(caps, dataset_status)
            elif control["surface"] == "authorizationPolicy":
                observed = data.get("authorization_policy")
                if isinstance(observed, list):
                    observed = observed[0] if observed else None
            elif control["surface"] == "adminConsentRequestPolicy":
                observed = data.get("admin_consent_request_policy")
                if isinstance(observed, list):
                    observed = observed[0] if observed else None
            elif control["surface"] == "authMethods":
                observed = next(
                    (
                        c for c in methods_policy.get("authenticationMethodConfigurations") or []
                        if str(c.get("id")) == str(control.get("method"))
                    ),
                    None,
                )
                if observed is not None:
                    # Who a method is turned on for is a security question of
                    # its own: a weak method scoped to one team is a decision,
                    # the same method left on for everybody is a hole. The raw
                    # targets are a list of objects, so flatten the ids to
                    # something a predicate can read.
                    observed = dict(observed)
                    observed["includeTargetIds"] = [
                        str(t.get("id")) for t in (observed.get("includeTargets") or [])
                        if isinstance(t, dict) and t.get("id") is not None
                    ]
            result = _grade_conditional_control(control, observed)
            if result is None:
                # The condition does not hold, so there is nothing to grade and
                # nothing wrong. Recorded, not scored.
                not_applicable.append({
                    "controlId": control["id"],
                    "intent": control.get("intent", ""),
                    "citations": control.get("citations", []),
                    "note": str(control.get("notApplicableText") or
                                "This does not apply to how this tenant is set up."),
                })
                continue
            result["tenantId"] = tenant_id
            result["intent"] = control.get("intent", "")
            result["rationale"] = control.get("rationale", "")
            result["riskClass"] = control.get("riskClass", "medium")
            result["profile"] = control.get("profile", "baseline")
            result["citations"] = control.get("citations", [])
            result["affected"] = _affected(control, data)
            results.append(result)
            continue
        unknown_reason = _surface_unknown_reason(control["surface"], data, dataset_status)
        if unknown_reason:
            result = _result(control, UNKNOWN, [], [], [unknown_reason + " Graded honestly, not guessed."])
        elif control["surface"] == "conditionalAccess":
            result = _grade_cap_control(control, caps, resolver, named_locations, strengths,
                                        cap_canon_cache)
        elif control["surface"] == "authenticationStrength":
            result = _grade_strength_control(control, strengths)
        elif control["surface"] == "authMethods":
            result = _grade_method_control(control, methods_policy, resolver)
        elif control["surface"] == "registrationCampaign":
            result = _grade_campaign_control(control, methods_policy, resolver)
        elif control["surface"] == "namedLocation":
            result = _grade_location_control(control, named_locations, resolver)
        else:
            result = _result(control, UNKNOWN, [], [], ["Unrecognized surface."])
        result["tenantId"] = tenant_id
        result["intent"] = control.get("intent", "")
        result["rationale"] = control.get("rationale", "")
        result["riskClass"] = control.get("riskClass", "medium")
        result["profile"] = control.get("profile", "baseline")
        result["citations"] = control.get("citations", [])
        result["affected"] = _affected(control, data)
        results.append(result)
        for m in result["matchedPolicies"]:
            matched_cap_ids.add(m["id"])

    surplus = []
    for cap in caps:
        if cap.get("state") == "disabled":
            continue
        if str(cap.get("id", "")) not in matched_cap_ids:
            surplus.append({
                "type": "conditionalAccessPolicy",
                "id": str(cap.get("id", "")),
                "displayName": str(cap.get("displayName", "")),
                "state": cap.get("state"),
                "note": "Outside the standard. Not penalized. Review as a rollout conflict candidate.",
            })
    baseline_combo_sets = {
        tuple((c.get("canonical") or {}).get("combos") or ())
        for c in artifact.get("controls", [])
        if c["surface"] == "authenticationStrength"
    }
    for strength in strengths:
        if tuple(canonical_strength(strength)["combos"]) not in baseline_combo_sets:
            surplus.append({
                "type": "authenticationStrength",
                "id": str(strength.get("id", "")),
                "displayName": str(strength.get("displayName", "")),
                "state": "enabled",
                "note": "A sign in strength outside the standard. Not penalized, listed for review.",
            })

    unknowns = []
    for record in dataset_status.values():
        if record.get("skipped"):
            unknowns.append(f"{record.get('dataset')}: skipped during collection ({'; '.join(record.get('errors') or []) or 'not licensed'}).")
        elif not record.get("complete", True):
            unknowns.append(f"{record.get('dataset')}: collector pull incomplete.")
    roles = data.get("roles") or {}
    if roles.get("roleEligibilityStatus") == "unknown":
        unknowns.append("Role eligibility (PIM) could not be read; eligible role holders are unknown.")
    unknowns.append("Sign in analysis covers a 30 day window. Rarer activity, such as a monthly job using legacy authentication, can hide outside the window.")

    grade_counts: dict[str, int] = {}
    for result in results:
        grade_counts[result["grade"]] = grade_counts.get(result["grade"], 0) + 1

    return {
        "schemaVersion": 1,
        "tenantId": tenant_id,
        "alias": alias,
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "baseline": artifact.get("builtFrom", {}),
        "gradeCounts": grade_counts,
        "controls": results,
        "surplus": surplus,
        # Controls the tenant cannot license, kept out of the score and listed
        # on their own so the grades describe what the tenant could actually
        # have done (SPEC-PUBLIC section 6).
        "outOfReach": out_of_reach,
        # Conditional checks whose condition does not hold. Nothing is wrong,
        # so they are recorded rather than scored (SPEC-PUBLIC section 7.2b).
        "notApplicable": not_applicable,
        "licensing": licensing,
        "unknowns": unknowns,
        # Display only. The report, plan, and questionnaire resolve identifiers
        # from this one index so they never disagree with each other.
        "names": names,
        "context": _context_block(data, snapshot_dir, dataset_status),
        "scopeNote": (
            "Evaluation is constrained to the standard's specific protections. "
            "This is not a general policy equivalence engine. Device posture is "
            "not assessed in this version."
        ),
    }
