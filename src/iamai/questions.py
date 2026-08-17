"""Questionnaire engine (SPEC section 9).

Questions are data, generated from the assessment. The two renderers (the
Flask wizard and the CLI runner) contain zero business logic: generation,
answer validation, persistence, parameter binding, and the automatic regrade
all live here.

Answers persist to data/{alias}/answers.json and a question is never asked
twice. Slot bindings from answers feed the parity engine's SlotResolver, so a
sanctioned exclusion can lift a control's grade; the regrade never guesses
beyond what the bindings prove.

The exclusion classification questions bind whichever slot the answer picks
(their bindsTo is the sentinel "chosenSlot"); every other question binds the
fixed slot named in bindsTo.
"""

from __future__ import annotations

import functools
import gzip
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from iamai.canon import SLOT_NAMES
from iamai.store import SnapshotStore, load_snapshot_data

ANSWERS_NAME = "answers.json"
CHOSEN_SLOT = "chosenSlot"

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

AnswerType = Literal[
    "confirmSet", "selectAccounts", "selectLocations", "singleChoice", "selectOne", "freeText"
]


class Evidence(BaseModel):
    """The snapshot query behind a question and the rows it produced."""

    query: str
    rows: list[dict] = Field(default_factory=list)


class QuestionOption(BaseModel):
    value: str
    label: str


class Question(BaseModel):
    """One question, renderer-agnostic (SPEC 9). trigger doubles as the
    why-we-ask line both renderers show."""

    id: str
    trigger: str
    evidence: Evidence
    text: str
    answerType: AnswerType
    bindsTo: str
    required: bool
    subject: str = ""
    options: list[QuestionOption] = Field(default_factory=list)


class Answer(BaseModel):
    questionId: str
    answerType: str
    bindsTo: str
    subject: str = ""
    value: list[str] | str
    labels: list[str] = Field(default_factory=list)
    note: str = ""
    answeredAt: str


class AnswersFile(BaseModel):
    schemaVersion: int = 1
    tenantId: str
    alias: str
    answers: dict[str, Answer] = Field(default_factory=dict)


# --- Snapshot helpers -----------------------------------------------------------


def _users_list(data: dict) -> list[dict]:
    users = data.get("users") or []
    return users if isinstance(users, list) else users.get("value", [])


def _groups_list(data: dict) -> list[dict]:
    groups = data.get("groups") or []
    return groups.get("groups", []) if isinstance(groups, dict) else groups


def _display_names(data: dict) -> dict[str, str]:
    names: dict[str, str] = {}
    for user in _users_list(data):
        names[str(user.get("id", "")).lower()] = str(user.get("userPrincipalName", ""))
    for group in _groups_list(data):
        names[str(group.get("id", "")).lower()] = f"{group.get('displayName', '')} (group)"
    return names


_ALL_FEEDS = ("signins_interactive.jsonl.gz", "signins_noninteractive.jsonl.gz")


@functools.lru_cache(maxsize=4)
def _signin_events_cached(snapshot_dir: Path, feeds: tuple[str, ...]) -> tuple[dict, ...]:
    """Materialized sign-in events for a snapshot, cached. A snapshot is
    immutable once its manifest is written, so caching by path is safe, and it
    collapses the repeated gunzip+parse that question generation and the
    regrade otherwise do over the same feeds within one run (PERF-2-002).
    Callers must treat the events as read only; they are shared."""
    events: list[dict] = []
    for name in feeds:
        feed = snapshot_dir / "raw" / name
        if not feed.exists():
            feed = snapshot_dir / name
        if not feed.exists():
            continue
        with gzip.open(feed, "rt", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return tuple(events)


def _signin_events(snapshot_dir: Path | None, feeds: tuple[str, ...] = _ALL_FEEDS):
    if snapshot_dir is None:
        return
    yield from _signin_events_cached(snapshot_dir, feeds)


# --- Question generation (the V1 seed questions, only when relevant) -------------


def _break_glass_question(data: dict, snapshot_dir: Path | None) -> Question:
    signed_in = {
        str(event.get("userId", "")).lower() for event in _signin_events(snapshot_dir)
    }
    names = _display_names(data)
    rows: list[dict] = []
    options: list[QuestionOption] = []
    seen: set[str] = set()
    for cap in data.get("conditional_access_policies") or []:
        if cap.get("state") == "disabled":
            continue
        users_block = (cap.get("conditions") or {}).get("users") or {}
        excluded = list(users_block.get("excludeUsers") or []) + list(
            users_block.get("excludeGroups") or []
        )
        for guid in excluded:
            key = str(guid).lower()
            if key in seen:
                continue
            seen.add(key)
            label = names.get(key, key)
            rows.append({"item": label, "detail": f"Excluded from the policy '{cap.get('displayName', '')}'"})
            options.append(QuestionOption(value=key, label=label))
    absent = [
        user for user in _users_list(data)
        if user.get("accountEnabled", True) and str(user.get("id", "")).lower() not in signed_in
    ]
    for user in absent[:10]:
        key = str(user.get("id", "")).lower()
        if key in seen:
            continue
        seen.add(key)
        label = str(user.get("userPrincipalName", ""))
        rows.append({"item": label, "detail": "No sign in activity in the collection window"})
        options.append(QuestionOption(value=key, label=label))
    if len(absent) > 10:
        rows.append({
            "item": f"and {len(absent) - 10} more accounts",
            "detail": "No sign in activity in the collection window",
        })
    return Question(
        id="break-glass",
        trigger=(
            "The remediation plan protects break glass accounts first and excludes "
            "them from every new policy, so the list must be confirmed by a person."
        ),
        evidence=Evidence(
            query=(
                "Accounts and groups excluded from enabled access policies in the "
                "latest snapshot, plus enabled accounts with no sign in activity in "
                "the collection window."
            ),
            rows=rows,
        ),
        text=(
            "Which accounts or groups are the break glass accounts for this "
            "tenant? Break glass accounts are emergency sign in accounts kept "
            "outside normal policies so an administrator can always get in. "
            "Select none if this tenant has no break glass account yet: the plan "
            "will tell you to create one."
        ),
        answerType="selectAccounts",
        bindsTo="breakGlassAccounts",
        required=True,
        options=options,
    )


def _location_summary(location: dict) -> str:
    odata = str(location.get("@odata.type", ""))
    if "ipNamedLocation" in odata:
        cidrs = ", ".join(
            r.get("cidrAddress", "") for r in location.get("ipRanges") or [] if r.get("cidrAddress")
        )
        trusted = "marked trusted" if location.get("isTrusted") else "not marked trusted"
        return f"Network ranges {cidrs}, currently {trusted}"
    if "countryNamedLocation" in odata:
        return "Countries " + ", ".join(sorted(location.get("countriesAndRegions") or []))
    return "A named location defined in the tenant"


# Share of interactive sign ins from one address above which it is worth
# flagging as a likely office or VPN. A hint for the operator, never a grade.
_OFFICE_SHARE = 0.30


def _trusted_locations_question(data: dict, snapshot_dir: Path | None) -> Question | None:
    ip_counts: Counter[str] = Counter()
    for event in _signin_events(snapshot_dir, feeds=("signins_interactive.jsonl.gz",)):
        ip = event.get("ipAddress")
        if ip:
            ip_counts[str(ip)] += 1
    named = data.get("named_locations") or []
    if not named and not ip_counts:
        return None
    rows: list[dict] = []
    options: list[QuestionOption] = []
    for location in named:
        label = str(location.get("displayName", ""))
        rows.append({"item": label, "detail": _location_summary(location)})
        options.append(QuestionOption(value=str(location.get("id", "")).lower(), label=label))
    total_events = sum(ip_counts.values())
    for ip, count in sorted(ip_counts.items(), key=lambda pair: (-pair[1], pair[0]))[:10]:
        events = "event" if count == 1 else "events"
        share = count / total_events if total_events else 0.0
        detail = f"{count} sign in {events} came from this address, {round(share * 100)}% of the window"
        # A single address carrying a large share of sign ins is usually an
        # office network or VPN egress. Surface the hint, but let the person
        # confirm: it could equally be a proxy nobody should trust.
        if share >= _OFFICE_SHARE:
            detail += ". One address this busy is often an office network or VPN, worth confirming as trusted"
        rows.append({"item": ip, "detail": detail})
        options.append(QuestionOption(value=ip, label=ip))
    return Question(
        id="trusted-locations",
        trigger=(
            "Policies can treat sign ins from trusted company networks differently. "
            "Only a person can confirm which networks really belong to the company."
        ),
        evidence=Evidence(
            query=(
                "Named network locations defined in the tenant, plus the network "
                "addresses that sign ins came from in the collection window."
            ),
            rows=rows,
        ),
        text=(
            "Which of these network locations are trusted company networks? You can "
            "also enter your office public IP address or range below. Select none if "
            "your team is fully remote with no company network, or you are not sure."
        ),
        answerType="selectLocations",
        bindsTo="trustedLocations",
        required=True,
        options=options,
    )


_EXCLUSION_OPTIONS = [
    QuestionOption(value="breakGlassAccounts", label="A break glass emergency account"),
    QuestionOption(value="serviceAccounts", label="A service account used by software, not a person"),
    QuestionOption(value="pilotGroups", label="A pilot group used to test changes on a few people first"),
    QuestionOption(
        value="onboardingGroups",
        label=(
            "A group people sit in only while they set up a new sign in method, "
            "such as enrolling a passkey (the plan will remind you to empty it)"
        ),
    ),
    QuestionOption(value="other", label="Something else (a short reason is recorded)"),
]


def _subject_phrase(guid: str, label: str, group_ids: set[str]) -> str:
    """Name the thing in plain words, so the question reads like a sentence."""
    if guid in group_ids:
        return f"The group '{label.removesuffix(' (group)')}'"
    if label and label != guid:
        return f"The account '{label}'"
    return f"The object with id {guid}, which is not in the collected data,"


def _exclusion_questions(assessment: dict, data: dict) -> list[Question]:
    names = _display_names(data)
    group_ids = {str(g.get("id", "")).lower() for g in _groups_list(data)}
    caps = data.get("conditional_access_policies") or []
    questions: list[Question] = []
    seen: set[str] = set()
    for control in assessment.get("controls", []):
        for token in control.get("unsanctionedExclusions") or []:
            guid = token.split(":", 1)[-1].lower()
            if guid in seen:
                continue
            seen.add(guid)
            label = names.get(guid, guid)
            rows: list[dict] = []
            for cap in caps:
                users_block = (cap.get("conditions") or {}).get("users") or {}
                excluded = [
                    str(g).lower()
                    for g in list(users_block.get("excludeUsers") or [])
                    + list(users_block.get("excludeGroups") or [])
                ]
                if guid in excluded:
                    rows.append({"item": str(cap.get("displayName", "")), "detail": "This policy excludes it"})
            for other in assessment.get("controls", []):
                if token in (other.get("unsanctionedExclusions") or []):
                    rows.append({
                        "item": other.get("intent") or other["controlId"],
                        "detail": f"Graded {other['grade']} partly because of this exclusion",
                    })
            questions.append(Question(
                id=f"exclusion-{guid}",
                trigger=(
                    "An exclusion the standard does not sanction weakens a protection. "
                    "Classifying it either approves it with a purpose or flags it for cleanup."
                ),
                evidence=Evidence(
                    query=(
                        "Policies in the latest snapshot that exclude this account or "
                        "group, and the graded controls the exclusion weakens."
                    ),
                    rows=rows,
                ),
                text=(
                    f"{_subject_phrase(guid, label, group_ids)} is excluded from one or "
                    "more access policies and the standard does not sanction it. "
                    "What is it?"
                ),
                answerType="singleChoice",
                bindsTo=CHOSEN_SLOT,
                required=True,
                subject=guid,
                options=list(_EXCLUSION_OPTIONS),
            ))
    return questions


def _legacy_auth_question(assessment: dict) -> Question | None:
    legacy = (assessment.get("context") or {}).get("legacyAuth") or {}
    if not legacy.get("eventCount"):
        return None
    rows = [
        {"item": client, "detail": "An old sign in method seen in the collection window"}
        for client in legacy.get("clients") or []
    ]
    options = [
        QuestionOption(value=upn, label=upn)
        for upn in legacy.get("sampleUPNs") or []
        if upn
    ]
    for option in options:
        rows.append({"item": option.label, "detail": "This account used an old sign in method"})
    return Question(
        id="legacy-auth",
        trigger=(
            "The plan will block old sign in methods. Service accounts that still "
            "use them need special handling first so nothing breaks."
        ),
        evidence=Evidence(
            query=(
                "Sign in events in the collection window whose client is not a "
                "modern browser or app, grouped by client and account."
            ),
            rows=rows,
        ),
        text=(
            "These accounts recently signed in with old methods that skip modern "
            "security checks. Confirm which of them are service accounts used by "
            "software rather than people."
        ),
        answerType="confirmSet",
        bindsTo="serviceAccounts",
        required=True,
        options=options,
    )


def _cross_tenant_trust_question(data: dict) -> Question | None:
    """Asked only when the tenant accepts a partner's multifactor claim.

    Trusting the claim means this tenant's own policies accept another
    organisation's word that the person passed a second sign in step. That is
    a legitimate arrangement between organisations that know each other and a
    risk decision either way, so it gets a question rather than a default
    (SPEC-PUBLIC section 7 item 9). The answer records the decision; the
    xtenant-001 control grades on whether it was recorded as deliberate.
    """
    from iamai.grade import _cross_tenant_summary

    summary = _cross_tenant_summary(data, {})
    if not summary or not summary.get("mfaTrustAccepted"):
        return None
    if summary.get("trustScope") == "everyone":
        rows = [{
            "item": "Every organisation",
            "detail": "The default cross tenant setting accepts multifactor claims from any partner tenant",
        }]
        scope_phrase = "any outside organisation"
    else:
        rows = [
            {"item": tenant_id, "detail": "This partner tenant's multifactor claims are trusted"}
            for tenant_id in summary.get("trustingPartnerTenantIds") or []
        ]
        count = len(rows)
        scope_phrase = f"{count} named partner organisation" + ("s" if count != 1 else "")
    return Question(
        id="cross-tenant-mfa-trust",
        trigger=(
            "When a partner's multifactor claim is trusted, your sign in policies "
            "accept their word that the person passed a second step, so their "
            "security becomes part of yours."
        ),
        evidence=Evidence(
            query=(
                "The cross tenant access settings in the latest snapshot, read from "
                "the default configuration and every partner configuration."
            ),
            rows=rows,
        ),
        text=(
            f"This tenant accepts multifactor claims from {scope_phrase}. That is a "
            "reasonable arrangement with organisations you know and trust, and a "
            "risk with ones you do not. Was this decided on purpose?"
        ),
        answerType="singleChoice",
        bindsTo="decision:crossTenantMfaTrust",
        required=True,
        options=[
            QuestionOption(
                value="deliberate",
                label="Yes, we trust these organisations and decided this on purpose",
            ),
            QuestionOption(
                value="review",
                label="No, or nobody remembers deciding it, so it should be reviewed",
            ),
        ],
    )


def _license_question(assessment: dict) -> Question:
    licenses = (assessment.get("context") or {}).get("licenses") or {}
    if licenses.get("entraP2"):
        detected = "Entra ID P2"
    elif licenses.get("entraP1"):
        detected = "Entra ID P1"
    else:
        detected = "no premium Entra ID license"
    rows = [
        {"item": sku, "detail": "License SKU found in the tenant"}
        for sku in licenses.get("skuPartNumbers") or []
    ]
    rows.append({"item": "Detected tier", "detail": detected})
    return Question(
        id="license-tier",
        trigger=(
            "Some protections need a specific license. The plan only includes "
            "steps the tenant's license can actually support."
        ),
        evidence=Evidence(
            query="License SKUs read from the tenant's subscription data in the latest snapshot.",
            rows=rows,
        ),
        text="Which license tier should the plan assume for this tenant?",
        answerType="singleChoice",
        bindsTo="licenseTier",
        required=True,
        options=[
            QuestionOption(value="P2", label="Entra ID P2, included with Microsoft 365 E5 (adds risk based sign in policies)"),
            QuestionOption(value="P1", label="Entra ID P1, included with Microsoft 365 E3 (adds conditional access policies)"),
            QuestionOption(value="BusinessPremium", label="Microsoft 365 Business Premium (includes the Entra ID P1 features)"),
            QuestionOption(value="none", label="No premium Entra ID license"),
        ],
    )


def _timezone_question() -> Question:
    from zoneinfo import available_timezones

    # Every IANA zone, UTC first, so the web wizard shows a real dropdown and
    # the answer is always a valid zone. Picking from this set is the
    # validation: an unknown name used to be accepted and then silently fall
    # back to UTC in the plan, so reports showed the wrong times unnoticed.
    ordered = ["UTC"] + sorted(z for z in available_timezones() if z != "UTC")
    return Question(
        id="report-timezone",
        trigger="Collected timestamps are stored in UTC and converted for display only.",
        evidence=Evidence(query="No snapshot data is needed for this question.", rows=[]),
        text="Which timezone should reports use for dates and times?",
        answerType="selectOne",
        bindsTo="reportTimezone",
        required=True,
        options=[QuestionOption(value=zone, label=zone) for zone in ordered],
    )


def _special_handling_question() -> Question:
    return Question(
        id="special-handling",
        trigger="Plan steps can call out accounts that need extra care before changes apply to them.",
        evidence=Evidence(query="No snapshot data is needed for this question.", rows=[]),
        text=(
            "Is there anyone who needs special care during the rollout, such as "
            "executives, shared accounts, or people who are traveling? Describe "
            "them, or leave this blank."
        ),
        answerType="freeText",
        bindsTo="specialHandling",
        required=False,
    )


def generate_questions(assessment: dict, data: dict, snapshot_dir: Path | None) -> list[Question]:
    """The V1 seed questions, each generated only when relevant, in a stable order."""
    questions: list[Question] = [_break_glass_question(data, snapshot_dir)]
    locations = _trusted_locations_question(data, snapshot_dir)
    if locations:
        questions.append(locations)
    questions.extend(_exclusion_questions(assessment, data))
    legacy = _legacy_auth_question(assessment)
    if legacy:
        questions.append(legacy)
    trust = _cross_tenant_trust_question(data)
    if trust:
        questions.append(trust)
    questions.append(_license_question(assessment))
    questions.append(_timezone_question())
    questions.append(_special_handling_question())
    return questions


def pending_questions(questions: list[Question], answers: AnswersFile) -> list[Question]:
    """Questions not yet answered. Answered questions are never asked twice."""
    return [q for q in questions if q.id not in answers.answers]


# --- Answer construction and persistence ------------------------------------------


def make_answer(question: Question, raw: list[str] | str, data: dict, *, note: str = "") -> Answer:
    """Validate renderer input and build the persisted answer.

    Set-type answers accept option values, object id GUIDs, or typed account
    names; names the snapshot knows resolve to their object ids so they can
    bind parameter slots. Unknown names are kept verbatim (persisted, never
    bound)."""
    answered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    common = {
        "questionId": question.id,
        "answerType": question.answerType,
        "bindsTo": question.bindsTo,
        "subject": question.subject,
        "answeredAt": answered_at,
    }
    if question.answerType == "freeText":
        text = str(raw).strip()
        if question.required and not text:
            raise ValueError("This question needs an answer before the questionnaire can finish.")
        return Answer(value=text, note=note.strip(), **common)
    if question.answerType in ("singleChoice", "selectOne"):
        choice = str(raw).strip()
        by_value = {option.value: option.label for option in question.options}
        if choice not in by_value:
            raise ValueError("Pick one of the listed choices.")
        if choice == "other" and not note.strip():
            raise ValueError("Describe what it is so the record is meaningful.")
        return Answer(value=choice, labels=[by_value[choice]], note=note.strip(), **common)
    items = [raw] if isinstance(raw, str) else list(raw)
    names = _display_names(data)
    upn_to_id = {
        str(user.get("userPrincipalName", "")).lower(): str(user.get("id", "")).lower()
        for user in _users_list(data)
        if user.get("userPrincipalName")
    }
    wants_networks = question.answerType == "selectLocations"
    value: list[str] = []
    labels: list[str] = []
    unusable: list[str] = []
    for item in items:
        entry = str(item).strip()
        if not entry:
            continue
        if _GUID_RE.match(entry):
            resolved = entry.lower()
        else:
            resolved = upn_to_id.get(entry.lower(), "")
            if not resolved and wants_networks and _is_network(entry):
                resolved = entry
        if not resolved:
            # Anything that is neither an object in this tenant nor, on a
            # locations question, a real network address used to be stored
            # verbatim and then dropped by slot_bindings, so the answer was
            # accepted, persisted, never used and never asked again
            # (BUGS.md item 28).
            unusable.append(entry)
            continue
        if resolved in value:
            continue
        value.append(resolved)
        labels.append(names.get(resolved.lower(), entry))
    if unusable:
        detail = ", ".join(unusable)
        if wants_networks:
            raise ValueError(
                f"These are not network addresses this tool can use: {detail}. "
                "Enter an address like 203.0.113.5, a range like 203.0.113.0/24, "
                "or pick a location from the list."
            )
        raise ValueError(
            f"These are not accounts or groups in this tenant: {detail}. Pick from "
            "the list, or type the exact sign in name."
        )
    # An empty selection stays a valid answer: "none of these" is a real
    # response to "which of these are break glass accounts".
    return Answer(value=value, labels=labels, note=note.strip(), **common)


def _is_network(value: str) -> bool:
    """True for an IP address or CIDR range, so a locations answer may carry
    one alongside named location ids."""
    import ipaddress

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def answers_path(alias_dir: Path) -> Path:
    return alias_dir / ANSWERS_NAME


def load_answers(alias_dir: Path, tenant_id: str, alias: str) -> AnswersFile:
    path = answers_path(alias_dir)
    if path.exists():
        return AnswersFile.model_validate_json(path.read_text(encoding="utf-8"))
    return AnswersFile(tenantId=tenant_id, alias=alias)


def save_answer(alias_dir: Path, answers: AnswersFile, answer: Answer) -> Path:
    """Persist one answer immediately, so an interrupted run keeps progress."""
    answers.answers[answer.questionId] = answer
    path = answers_path(alias_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written through a temporary file, because writing in place is exactly
    # the interruption this function claims to survive: a truncated
    # answers.json raised out of every wizard route, the CLI runner and the
    # plan command, losing every prior answer (BUGS.md item 29).
    payload = json.dumps(answers.model_dump(), indent=2, sort_keys=True, ensure_ascii=False)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)
    return path


# --- Parameter binding --------------------------------------------------------------


def slot_bindings(answers: AnswersFile) -> dict[str, list[str]]:
    """GUIDs bound to parameter slots by the answers. Feeds the parity
    engine's SlotResolver on regrade. Only object id GUIDs bind; typed names
    the snapshot could not resolve never do."""
    bindings: dict[str, set[str]] = {}
    for answer in answers.answers.values():
        if answer.bindsTo == CHOSEN_SLOT and answer.subject:
            choice = answer.value if isinstance(answer.value, str) else ""
            if choice in SLOT_NAMES:
                bindings.setdefault(choice, set()).add(answer.subject.lower())
            continue
        if answer.bindsTo in SLOT_NAMES and isinstance(answer.value, list):
            for item in answer.value:
                if _GUID_RE.match(str(item)):
                    bindings.setdefault(answer.bindsTo, set()).add(str(item).lower())
            continue
        if answer.bindsTo.startswith("decision:") and isinstance(answer.value, str) and answer.value:
            # A recorded risk decision, not an object id. It reaches the
            # engine so a conditional control can grade on whether the
            # decision was taken on purpose (SPEC-PUBLIC section 7 item 9);
            # SlotResolver ignores it because no policy carries the value.
            bindings.setdefault(answer.bindsTo, set()).add(answer.value)
    return {slot: sorted(guids) for slot, guids in bindings.items()}


def parameters(answers: AnswersFile) -> dict:
    """Everything the plan generator needs from the answers: the slot
    bindings plus the scalar parameters and confirmed non GUID entries."""
    params: dict = {"slots": slot_bindings(answers)}
    trusted_networks: list[str] = []
    for answer in answers.answers.values():
        if answer.answerType in ("freeText", "selectOne") or (
            answer.answerType == "singleChoice" and answer.bindsTo != CHOSEN_SLOT
        ):
            params[answer.bindsTo] = answer.value
        if answer.bindsTo == "trustedLocations" and isinstance(answer.value, list):
            trusted_networks.extend(
                str(item) for item in answer.value if not _GUID_RE.match(str(item))
            )
    if trusted_networks:
        params["trustedNetworks"] = sorted(set(trusted_networks))
    return params


# --- Regrade (automatic at the end of the questionnaire) ----------------------------


def latest_assessment(store: SnapshotStore, alias: str) -> dict:
    out_dir = store.alias_dir(alias) / "assessments"
    # Write time, not name: a same-second regrade gets a collision suffix
    # that would sort lexically before the file it follows.
    files = sorted(
        out_dir.glob("*-assessment.json"),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )
    if not files:
        raise FileNotFoundError(
            f"No assessment found for alias '{alias}'. Run 'iamai assess {alias}' first."
        )
    return json.loads(files[-1].read_text(encoding="utf-8"))


def assess_with_answers(
    alias: str, tenant_id: str, artifact: dict, store: SnapshotStore,
    standard: dict | None = None,
) -> tuple[dict, Path, Path, int]:
    """Assess the latest snapshot with all saved answer bindings applied and
    write the assessment and report. Returns (assessment, assessment_path,
    report_path, answer_count). With no saved answers this is a plain assess.

    ``standard`` describes which standard graded this (name, version, control
    count); it is stamped into the assessment so every report can state it."""
    from iamai.grade import assess_snapshot
    from iamai.report import render_assessment

    snapshot_dir = store.latest_snapshot(alias)
    data, manifest = load_snapshot_data(snapshot_dir)
    answers = load_answers(store.alias_dir(alias), tenant_id, alias)
    assessment = assess_snapshot(
        artifact,
        data,
        manifest,
        tenant_id=tenant_id,
        alias=alias,
        snapshot_dir=snapshot_dir,
        answer_bindings=slot_bindings(answers),
    )
    if standard:
        assessment["standard"] = standard
    out_dir = store.alias_dir(alias) / "assessments"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stem = stamp
    suffix = 1
    while (out_dir / f"{stem}-assessment.json").exists():
        stem = f"{stamp}-{suffix}"
        suffix += 1
    out_path = out_dir / f"{stem}-assessment.json"
    out_path.write_text(
        json.dumps(assessment, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    report_path = out_dir / f"{stem}-report.html"
    from iamai.plan import _role_names

    report_path.write_text(
        render_assessment(assessment, manifest, role_names=_role_names(data)),
        encoding="utf-8",
    )
    return assessment, out_path, report_path, len(answers.answers)


def grade_changes(old: dict, new: dict) -> list[dict]:
    """Controls whose grade changed between two assessments, by control id."""
    before = {c["controlId"]: c["grade"] for c in old.get("controls", [])}
    changes = []
    for control in new.get("controls", []):
        previous = before.get(control["controlId"])
        if previous and previous != control["grade"]:
            changes.append({
                "controlId": control["controlId"],
                "from": previous,
                "to": control["grade"],
            })
    return sorted(changes, key=lambda change: change["controlId"])
