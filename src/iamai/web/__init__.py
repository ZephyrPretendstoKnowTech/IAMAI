"""Flask wizard for the questionnaire (SPEC section 9).

This is a renderer only: question generation, answer validation, persistence,
binding, and the regrade all live in iamai.questions. The routes translate
form fields into raw values and hand them over.

The wizard binds to 127.0.0.1 only and its pages load no external assets, so
nothing ever leaves the machine.
"""

from __future__ import annotations

import hmac
import secrets

from flask import Flask, abort, redirect, render_template, request, url_for

from iamai.questions import (
    assess_with_answers,
    generate_questions,
    grade_changes,
    latest_assessment,
    load_answers,
    make_answer,
    pending_questions,
    save_answer,
)
from iamai.store import SnapshotStore, load_snapshot_data
from iamai.theme import theme_css


def _raw_from_form(question, form) -> tuple[list[str] | str, str]:
    """Translate submitted form fields into the raw value make_answer expects."""
    if question.answerType == "freeText":
        return form.get("text", ""), ""
    if question.answerType in ("singleChoice", "selectOne"):
        return form.get("choice", ""), form.get("note", "")
    selected = list(form.getlist("selection"))
    extra = form.get("extra", "")
    selected.extend(part.strip() for part in extra.split(",") if part.strip())
    return selected, ""


def _prefill_from_answer(answer, question) -> dict:
    """Render-ready values for a question that already has a saved answer, so
    navigating back shows what was chosen rather than a blank form. Best effort
    for set questions: option values that match are pre-checked, anything typed
    by hand comes back in the extra box."""
    prefill = {"selected": set(), "choice": "", "text": "", "note": "", "extra": ""}
    if answer is None:
        return prefill
    prefill["note"] = answer.note
    if answer.answerType == "freeText":
        prefill["text"] = answer.value if isinstance(answer.value, str) else ""
    elif answer.answerType in ("singleChoice", "selectOne"):
        prefill["choice"] = answer.value if isinstance(answer.value, str) else ""
    else:
        values = answer.value if isinstance(answer.value, list) else []
        option_values = {option.value for option in question.options}
        prefill["selected"] = {v for v in values if v in option_values}
        prefill["extra"] = ", ".join(v for v in values if v not in option_values)
    return prefill


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def create_app(*, alias: str, tenant_id: str, artifact: dict, store: SnapshotStore) -> Flask:
    app = Flask(__name__)
    # Templates end in .j2, which Flask does not autoescape by default.
    app.jinja_env.autoescape = True

    @app.before_request
    def _reject_non_loopback_host():
        # The CSRF token defends against a cross-origin page forging a POST,
        # but not against DNS rebinding: an attacker page whose domain is
        # rebound to 127.0.0.1 becomes same-origin and can then read the token
        # out of a rendered page and replay it. Refusing any request whose Host
        # header is not a loopback name closes that, because the rebound
        # request still arrives with the attacker's Host (AUTHZ-2-001).
        hostname = (request.host or "").rsplit(":", 1)[0]
        if hostname not in _LOOPBACK_HOSTS:
            abort(403)

    base_assessment = latest_assessment(store, alias)
    state: dict = {"regraded": None}
    # Generated once per wizard run, not stored anywhere. The wizard sets no
    # Flask session and no SECRET_KEY, so a page open in another tab on the
    # same browser during a wizard session has no way to read or guess this
    # value, and cannot forge a POST that carries it (AUTHZ-001).
    csrf_token = secrets.token_urlsafe(32)

    # The snapshot is immutable for the wizard's lifetime, so the expensive
    # parts of a request -- parsing every dataset and re-streaming the gzipped
    # sign-in feeds inside generate_questions -- are computed once here rather
    # than on every one of the ~20 requests a wizard session makes. Only the
    # answers file changes between requests, and reading it is cheap
    # (PERF-2-001).
    immutable: dict = {}

    def csrf_ok() -> bool:
        return hmac.compare_digest(request.form.get("csrf_token", ""), csrf_token)

    def load_state():
        if not immutable:
            snapshot_dir = store.latest_snapshot(alias)
            data, _ = load_snapshot_data(snapshot_dir)
            immutable["data"] = data
            immutable["questions"] = generate_questions(base_assessment, data, snapshot_dir)
        answers = load_answers(store.alias_dir(alias), tenant_id, alias)
        return immutable["data"], answers, immutable["questions"]

    @app.get("/")
    def index():
        _, answers, questions = load_state()
        pending = pending_questions(questions, answers)
        if not pending:
            return redirect(url_for("done"))
        return redirect(url_for("question", question_id=pending[0].id))

    @app.route("/question/<question_id>", methods=["GET", "POST"])
    def question(question_id: str):
        data, answers, questions = load_state()
        by_id = {q.id: q for q in questions}
        if question_id not in by_id:
            return redirect(url_for("index"))
        current = by_id[question_id]
        error = ""
        if request.method == "POST":
            if not csrf_ok():
                # A page on another origin can auto-submit a form here with no
                # user action, since the browser sends cookies and form posts
                # cross origin by default. It cannot read this token out of a
                # page it was never allowed to load, so a request missing it
                # or carrying the wrong one is refused before anything it
                # submitted is looked at (AUTHZ-001).
                abort(403)
            raw, note = _raw_from_form(current, request.form)
            try:
                answer = make_answer(current, raw, data, note=note)
            except ValueError as exc:
                error = str(exc)
            else:
                save_answer(store.alias_dir(alias), answers, answer)
                return redirect(url_for("index"))
        index_pos = questions.index(current)
        has_other = any(option.value == "other" for option in current.options)
        # Back and forward move by position through the ordered list, so a
        # previous answer can be revisited and changed. "Save and continue"
        # still drives completion by jumping to the next unanswered question.
        prev_id = questions[index_pos - 1].id if index_pos > 0 else None
        next_id = questions[index_pos + 1].id if index_pos < len(questions) - 1 else None
        return render_template(
            "question.html.j2",
            alias=alias,
            question=current,
            position=index_pos + 1,
            total=len(questions),
            has_other=has_other,
            error=error,
            csrf_token=csrf_token,
            prev_id=prev_id,
            next_id=next_id,
            prefill=_prefill_from_answer(answers.answers.get(current.id), current),
            base_css=theme_css(),
        )

    @app.get("/done")
    def done():
        # Left as a GET, deliberately. It was flagged alongside the POST
        # route because a background tab could load it as an <img> to force
        # an early regrade -- but it takes no input of its own, and the one
        # POST route that does now rejects anything without a token that
        # tab cannot obtain. Once that path is closed, this endpoint only
        # ever recomputes the assessment from answers that are already
        # known good, which is not a state worth protecting against being
        # read early (AUTHZ-001).
        _, answers, questions = load_state()
        pending = pending_questions(questions, answers)
        if pending:
            return redirect(url_for("question", question_id=pending[0].id))
        if state["regraded"] is None:
            assessment, out_path, report_path, _ = assess_with_answers(
                alias, tenant_id, artifact, store
            )
            state["regraded"] = {
                "assessment": assessment,
                "outPath": str(out_path),
                "reportPath": str(report_path),
                "changes": grade_changes(base_assessment, assessment),
            }
        regraded = state["regraded"]
        counts = regraded["assessment"].get("gradeCounts", {})
        order = ["FULL", "FUNCTIONAL", "PARTIAL", "MISSING", "UNKNOWN"]
        return render_template(
            "done.html.j2",
            alias=alias,
            grade_counts=[(grade, counts.get(grade, 0)) for grade in order],
            changes=regraded["changes"],
            out_path=regraded["outPath"],
            report_path=regraded["reportPath"],
            base_css=theme_css(),
        )

    return app
