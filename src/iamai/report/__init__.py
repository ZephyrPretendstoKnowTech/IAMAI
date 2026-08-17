"""Assessment report rendering (SPEC section 8).

HTML via Jinja2, printable to PDF from the browser. The report is one
self-contained file: inline styles, no scripts, no external assets, so it
never triggers an outbound request when opened. Tenants appear by alias
only; the baseline is always called "the standard".
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from iamai.theme import theme_css

FULL = "FULL"
FUNCTIONAL = "FUNCTIONAL"
PARTIAL = "PARTIAL"
MISSING = "MISSING"
UNKNOWN = "UNKNOWN"

GRADE_ORDER = (FULL, FUNCTIONAL, PARTIAL, MISSING, UNKNOWN)

# Plain-language category labels per grading surface, in report order.
# One canonical map, defined next to the engine that stamps it per control,
# so the report summary and the JSON artifact can never drift apart and a
# camelCase surface name can never reach a reader.
from iamai.grade import SECTION_LABELS as SURFACE_LABELS  # noqa: E402

GRADE_MEANINGS = {
    FULL: "Matches the standard.",
    FUNCTIONAL: "Protected, but built differently from the standard.",
    PARTIAL: "Present but weaker than the standard.",
    MISSING: "This protection does not exist in the tenant.",
    UNKNOWN: "The collected data was not good enough to judge. Never guessed.",
}

# Category status is conservative, like the grades: one MISSING control turns
# the category red; any PARTIAL or UNKNOWN control turns it amber; green means
# every control in the category is FULL or FUNCTIONAL.
_STATUS = {
    "green": {"label": "Meets the standard", "icon": "✓"},
    "amber": {"label": "Needs attention", "icon": "!"},
    "red": {"label": "Protection missing", "icon": "✕"},
}

# One colour per grade, so a page of controls is scannable. FUNCTIONAL is its
# own teal rather than sharing FULL's green: "protected, built differently" is
# a distinct answer from "matches the standard", and the two-axes model exists
# to draw exactly that line. UNKNOWN is a neutral grey, not amber, because a
# genuine data gap is not the same as a weak-but-present control.
_GRADE_STATUS = {
    FULL: "green",
    FUNCTIONAL: "teal",
    PARTIAL: "amber",
    UNKNOWN: "gray",
    MISSING: "red",
}

_SURPLUS_TYPE_LABELS = {
    "conditionalAccessPolicy": "access policy",
    "authenticationStrength": "sign in strength definition",
}


def _category_status(grades: list[str]) -> str:
    if MISSING in grades:
        return "red"
    if PARTIAL in grades or UNKNOWN in grades:
        return "amber"
    return "green"


def _grouped(controls: list[dict]) -> list[dict]:
    """Group by plain-language section. Two surfaces can share a section
    (Conditional Access policies and their collection-level checks are one
    subject to a reader), so grouping happens on the label a person sees,
    never on the internal surface name."""
    label_order = list(dict.fromkeys(SURFACE_LABELS.values())) + ["Other checks"]

    def label_of(control: dict) -> str:
        return control.get("section") or SURFACE_LABELS.get(control["surface"], "Other checks")

    labels: list[str] = []
    for control in controls:
        if label_of(control) not in labels:
            labels.append(label_of(control))
    labels.sort(key=lambda l: label_order.index(l) if l in label_order else len(label_order))
    groups = []
    for label in labels:
        members = [c for c in controls if label_of(c) == label]
        grades = [c["grade"] for c in members]
        met = sum(1 for g in grades if g in (FULL, FUNCTIONAL))
        status = _category_status(grades)
        groups.append({
            "surface": members[0]["surface"],
            "label": label,
            "controls": members,
            "met": met,
            "total": len(members),
            "status": status,
            "statusLabel": _STATUS[status]["label"],
            "statusIcon": _STATUS[status]["icon"],
        })
    return groups


def _data_warnings(assessment: dict, manifest: dict | None) -> list[str]:
    warnings = []
    unknown = assessment.get("gradeCounts", {}).get(UNKNOWN, 0)
    if unknown:
        warnings.append(
            f"{unknown} control{'s were' if unknown != 1 else ' was'} graded UNKNOWN "
            "because the data behind them could not be read completely. "
            "Those grades are honest gaps, not guesses."
        )
    if manifest is not None and not manifest.get("complete", True):
        warnings.append(
            "The collection this report is based on did not finish completely. "
            "The section 'What this assessment cannot see' lists what is missing. "
            "Re-run the collection to close these gaps."
        )
    return warnings


def render_comms(context: dict) -> dict[str, str]:
    """Render the three comms text templates (SPEC 10) with the plan's
    checkpoints and real calendar dates. Plain text; rendered into the plan
    HTML, never sent."""
    env = Environment(
        loader=PackageLoader("iamai.report", "templates"),
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=True,
    )
    return {
        name: env.get_template(f"comms_{name}.txt.j2").render(**context)
        for name in ("announcement", "reminder", "helpdesk")
    }


_RISK_LABELS = {
    "high": "High impact",
    "medium": "Medium impact",
    "low": "Low impact",
}

_PRECONDITION_LABELS = {
    "pass": "checked now: pass",
    "fail": "checked now: FAIL, fix before this step",
    "unverified": "check at execution time",
}

_COMMS_TITLES = {
    "announcement": "End user announcement",
    "reminder": "Reminder",
    "helpdesk": "Helpdesk one pager",
}


def render_plan(plan: dict) -> str:
    """Render one plan record to a self-contained HTML page."""
    env = Environment(
        loader=PackageLoader("iamai.report", "templates"),
        autoescape=select_autoescape(("html", "j2")),
    )
    steps_by_phase: dict[int, list[dict]] = {}
    positions: dict[str, int] = {}
    for index, step in enumerate(plan.get("steps", []), start=1):
        steps_by_phase.setdefault(int(step["phase"]), []).append(step)
        positions[step["id"]] = index
    gates_by_id = {gate["id"]: gate for gate in plan.get("gates", [])}
    template = env.get_template("plan.html.j2")
    return template.render(
        alias=plan.get("alias", ""),
        generated_at=plan.get("generatedAt", ""),
        based_on=plan.get("basedOnAssessment", ""),
        start_date=plan.get("startDate", ""),
        license_tier=plan.get("licenseTier", ""),
        phases=plan.get("phases", []),
        gates=plan.get("gates", []),
        gates_by_id=gates_by_id,
        steps_by_phase=steps_by_phase,
        positions=positions,
        total_steps=len(plan.get("steps", [])),
        watch_list=plan.get("watchList", []),
        not_included=plan.get("notIncluded", []),
        best_effort_note=plan.get("bestEffortNote", ""),
        unknowns=plan.get("unknowns", []),
        comms=plan.get("comms", {}),
        comms_titles=_COMMS_TITLES,
        risk_labels=_RISK_LABELS,
        precondition_labels=_PRECONDITION_LABELS,
        scope_note=plan.get("scopeNote", ""),
        base_css=theme_css(),
    )


_EMPTY_CONTEXT = {
    "licenses": {"skuPartNumbers": [], "entraP1": False, "entraP2": False},
    "registration": {},
    "legacyAuth": {},
    "globalAdministrators": {},
    "federatedDomains": [],
    "securityDefaultsEnabled": False,
}


import re as _re

_PRINCIPAL_TOKEN = _re.compile(r"\b(group|user):([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")


def _humanize_principals(text: str, names: dict[str, str]) -> str:
    """Replace 'group:<guid>' / 'user:<guid>' tokens with plain phrases."""
    def repl(match: "_re.Match") -> str:
        kind, guid = match.group(1).lower(), match.group(2)
        label = names.get(guid.lower(), guid)
        return f"the group {label}" if kind == "group" else f"the account {label}"

    return _PRINCIPAL_TOKEN.sub(repl, text)


def _resolved_controls(
    controls: list[dict],
    role_names: dict[str, str],
    names: dict[str, str] | None = None,
) -> list[dict]:
    """Copies of the control results with identifiers in gap and note text
    resolved to display names: role template ids to role names (SPEC-V2
    section 2), and group, user, and application ids to their names
    (SPEC-PUBLIC section 5). The assessment artifact itself stays raw; this is
    presentation only, and names never take part in matching or grading."""
    from iamai.grade import _with_names
    from iamai.plan import resolve_role_tokens

    names = names or {}
    unresolved: set[str] = set()

    def clean(text: str) -> str:
        # Turn the internal "group:<guid>" / "user:<guid>" tokens into plain
        # words before the generic GUID resolver runs, so a reader sees
        # "the group Finance" rather than "group:Finance (a1b2...)".
        text = _humanize_principals(text, names)
        return _with_names(resolve_role_tokens(text, role_names), names, unresolved)

    resolved = []
    for control in controls:
        control = dict(control)
        control["coverageGaps"] = [clean(g) for g in control.get("coverageGaps") or []]
        control["notes"] = [clean(n) for n in control.get("notes") or []]
        resolved.append(control)
    return resolved


# Compliance crosswalk status per cited item, conservative like the grades and
# consistent with the report's own green/amber/red: one MISSING control misses
# the item, any PARTIAL partially meets it, an UNKNOWN with nothing worse
# leaves it not assessed, and a set of only FULL or FUNCTIONAL (both green)
# meets it. Derived from grades alone, never asserted beyond them.
_CROSSWALK_STATUS_ORDER = ("misses", "partially meets", "not assessed", "meets")


def _crosswalk_status(grades: set[str]) -> str:
    if MISSING in grades:
        return "misses"
    if PARTIAL in grades:
        return "partially meets"
    if UNKNOWN in grades:
        return "not assessed"
    return "meets"


def _compliance_crosswalk(controls: list[dict], excused: list[dict] | None = None) -> list[dict]:
    """Group the cited compliance items by source and derive a met status for
    each from the grades of the controls that cite it (SPEC-V2 section 3).

    A control that was never graded, because the tenant cannot license it or
    because the check does not apply, still contributes its cited items as not
    assessed. Leaving them out instead would drop the row from the table with
    no trace, and a silently absent row reads as nothing to say rather than as
    something nobody judged.
    """
    grades_by_item: dict[tuple[str, str], set[str]] = {}
    for control in list(controls) + list(excused or []):
        grade = control.get("grade", UNKNOWN)
        for citation in control.get("citations") or []:
            source = str(citation.get("source", "")).strip()
            item = str(citation.get("item", "")).strip()
            if not source or not item:
                continue
            if "placeholder" in source.lower():
                # A placeholder is a coverage claim with nothing behind it.
                # validate_pack rejects them at import; this guards artifacts
                # written before that rule existed (SPEC-PUBLIC section 11).
                continue
            grades_by_item.setdefault((source, item), set()).add(grade)

    by_source: dict[str, list[dict]] = {}
    for (source, item), grades in grades_by_item.items():
        by_source.setdefault(source, []).append(
            {"item": item, "status": _crosswalk_status(grades)}
        )

    crosswalk = []
    for source in sorted(by_source):
        rows = sorted(by_source[source], key=lambda row: row["item"])
        counts = {status: 0 for status in _CROSSWALK_STATUS_ORDER}
        for row in rows:
            counts[row["status"]] += 1
        crosswalk.append({
            "source": source,
            "rows": rows,
            "counts": counts,
            "total": len(rows),
        })
    return crosswalk


def render_assessment(
    assessment: dict,
    manifest: dict | None = None,
    role_names: dict[str, str] | None = None,
) -> str:
    """Render one assessment record to a self-contained HTML page."""
    env = Environment(
        loader=PackageLoader("iamai.report", "templates"),
        autoescape=select_autoescape(("html", "j2")),
    )
    counts = assessment.get("gradeCounts", {})
    template = env.get_template("assessment.html.j2")
    controls = _resolved_controls(
        assessment.get("controls", []), role_names or {}, assessment.get("names") or {}
    )
    return template.render(
        alias=assessment.get("alias", ""),
        standard=assessment.get("standard"),
        generated_at=assessment.get("generatedAt", ""),
        collected_at=(manifest or {}).get("collectedAt", ""),
        grade_order=GRADE_ORDER,
        grade_counts={grade: counts.get(grade, 0) for grade in GRADE_ORDER},
        grade_meanings=GRADE_MEANINGS,
        grade_status=_GRADE_STATUS,
        groups=_grouped(controls),
        surplus=assessment.get("surplus", []),
        surplus_type_labels=_SURPLUS_TYPE_LABELS,
        out_of_reach=assessment.get("outOfReach", []),
        structural=[
            {
                "controlId": control["controlId"],
                "intent": control.get("intent", ""),
                "findings": control["structural"],
            }
            for control in controls
            if control.get("structural")
        ],
        unknowns=assessment.get("unknowns", []),
        # Filled out to the full shape so a truncated or older-schema
        # assessment read back from disk renders with blanks instead of
        # aborting the whole report on a missing key (BUGS.md item 36).
        context={**_EMPTY_CONTEXT, **(assessment.get("context") or {})},
        scope_note=assessment.get("scopeNote", ""),
        data_warnings=_data_warnings(assessment, manifest),
        total_controls=len(assessment.get("controls", [])),
        crosswalk=_compliance_crosswalk(
            assessment.get("controls", []),
            list(assessment.get("outOfReach") or []) + list(assessment.get("notApplicable") or []),
        ),
        base_css=theme_css(),
    )
