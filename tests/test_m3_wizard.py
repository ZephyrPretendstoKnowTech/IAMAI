"""M3: the Flask wizard renderer (SPEC section 9).

The wizard renders the same question definitions as the CLI runner and holds
zero business logic. Tested with Flask's test client, no live server and no
network. The full flow: walk every question, answer through the forms, land
on the done page, and see the automatic regrade lift the sanctioned
exclusion's control from PARTIAL to FULL.
"""

import copy
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

import iamai.cli as cli

from conftest import freeze_test_baseline
from iamai.questions import (
    assess_with_answers,
    generate_questions,
    latest_assessment,
    load_answers,
)
from iamai.store import load_snapshot_data
from iamai.web import create_app

from test_m1_canon import make_artifact
from test_m3_questions import (
    BOGUS,
    USER_MFA,
    cap_named,
    workspace,  # noqa: F401  (fixture)
    write_snapshot,
)

pytestmark = pytest.mark.m3

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


@pytest.fixture()
def wizard_setup(golden, tmp_path):
    """A snapshot with one unsanctioned exclusion, assessed once, wizard ready."""
    data, manifest = golden
    artifact = make_artifact(data)
    control_id = next(
        c["id"] for c in artifact["controls"] if c.get("sourceName") == USER_MFA
    )
    cap_named(data, USER_MFA)["conditions"]["users"]["excludeUsers"] = [BOGUS]
    store = write_snapshot(tmp_path, "target", data, manifest)
    first, _, _, _ = assess_with_answers("target", "target-tenant", artifact, store)
    app = create_app(alias="target", tenant_id="target-tenant", artifact=artifact, store=store)
    app.config["TESTING"] = True
    return app.test_client(), store, first, control_id, data


def _extract_csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]*)"', html)
    assert match, "the form did not carry a csrf_token field"
    return match.group(1)


def _form_data(question, token: str) -> dict:
    if question.answerType == "freeText":
        data = {"text": "UTC"}
    elif question.answerType == "selectOne":
        data = {"choice": question.options[0].value}  # first option (UTC for timezone)
    elif question.answerType == "singleChoice":
        choice = "breakGlassAccounts" if question.id.startswith("exclusion-") else question.options[0].value
        data = {"choice": choice}
    else:
        data = {"extra": ""}  # select none for set questions
    data["csrf_token"] = token
    return data


def test_wizard_completes_the_flow_and_regrades(wizard_setup):
    client, store, first, control_id, data = wizard_setup
    graded = {c["controlId"]: c["grade"] for c in first["controls"]}
    assert graded[control_id] == "PARTIAL"

    snapshot_dir = store.latest_snapshot("target")
    questions = {q.id: q for q in generate_questions(first, data, snapshot_dir)}
    assert any(q.startswith("exclusion-") for q in questions)

    for _ in range(len(questions) + 2):
        landing = client.get("/")
        assert landing.status_code == 302
        location = landing.headers["Location"]
        if location.endswith("/done"):
            break
        question_id = location.rsplit("/", 1)[-1]
        page = client.get(location)
        assert page.status_code == 200
        html = page.get_data(as_text=True)
        assert "Question " in html and " of " in html
        assert "Why we ask:" in html
        token = _extract_csrf_token(html)
        saved = client.post(location, data=_form_data(questions[question_id], token))
        assert saved.status_code == 302, question_id
    else:
        pytest.fail("The wizard never reached the done page.")

    done = client.get("/done")
    assert done.status_code == 200
    html = done.get_data(as_text=True)
    assert "The questionnaire is finished" in html
    assert f"Control {control_id} moved from PARTIAL to FULL." in html
    assert "PARTIAL: 0" in html

    answers = load_answers(store.alias_dir("target"), "target-tenant", "target")
    assert set(answers.answers) == set(questions)
    regraded = latest_assessment(store, "target")
    grades = {c["controlId"]: c["grade"] for c in regraded["controls"]}
    assert grades[control_id] == "FULL"


def test_wizard_rejects_an_invalid_answer_without_advancing(wizard_setup):
    client, store, first, control_id, data = wizard_setup
    token = _extract_csrf_token(client.get("/question/report-timezone").get_data(as_text=True))
    page = client.post("/question/report-timezone", data={"choice": "Nowhere/Nonsense", "csrf_token": token})
    assert page.status_code == 200
    assert "Pick one of the listed choices." in page.get_data(as_text=True)
    answers = load_answers(store.alias_dir("target"), "target-tenant", "target")
    assert "report-timezone" not in answers.answers

    token = _extract_csrf_token(client.get(f"/question/exclusion-{BOGUS}").get_data(as_text=True))
    bad_choice = client.post(f"/question/exclusion-{BOGUS}", data={"choice": "nonsense", "csrf_token": token})
    assert bad_choice.status_code == 200
    assert "Pick one of the listed choices." in bad_choice.get_data(as_text=True)


def test_wizard_back_and_forward_navigation_and_prefill(wizard_setup):
    """Every question carries back/forward arrows so a prior answer can be
    revisited, and revisiting shows the saved answer, not a blank form."""
    client, store, first, control_id, data = wizard_setup
    snapshot_dir = store.latest_snapshot("target")
    ids = [q.id for q in generate_questions(first, data, snapshot_dir)]
    assert len(ids) >= 3

    # First question: no Back, Next points to the second question by position.
    first_page = client.get(f"/question/{ids[0]}").get_data(as_text=True)
    assert "Back" not in first_page
    assert f'/question/{ids[1]}"' in first_page and "Next" in first_page

    # A middle question: both arrows, aimed at its neighbours.
    mid = client.get(f"/question/{ids[1]}").get_data(as_text=True)
    assert f'/question/{ids[0]}"' in mid and "Back" in mid
    assert f'/question/{ids[2]}"' in mid and "Next" in mid

    # Dropdown answer is pre-selected on return. Use a non-default zone so the
    # pre-fill is what selects it, not the template's default-to-first.
    token = _extract_csrf_token(client.get("/question/report-timezone").get_data(as_text=True))
    client.post("/question/report-timezone", data={"choice": "Australia/Sydney", "csrf_token": token})
    assert 'value="Australia/Sydney" selected' in client.get("/question/report-timezone").get_data(as_text=True)

    # Single-choice answer is pre-checked on return.
    qid = f"exclusion-{BOGUS}"
    token = _extract_csrf_token(client.get(f"/question/{qid}").get_data(as_text=True))
    client.post(f"/question/{qid}", data={"choice": "breakGlassAccounts", "csrf_token": token})
    revisit = client.get(f"/question/{qid}").get_data(as_text=True)
    assert 'value="breakGlassAccounts" checked' in revisit


def test_wizard_rejects_a_post_with_no_or_wrong_csrf_token(wizard_setup):
    """A page on another origin can auto-submit a form here with no user
    action, and cookies and form posts travel cross origin by default. It
    cannot read this token out of a page it was never allowed to load, so a
    request missing it or carrying the wrong one must be refused before
    anything it submitted is looked at (AUTHZ-001)."""
    client, store, first, control_id, data = wizard_setup

    missing = client.post("/question/report-timezone", data={"text": "UTC"})
    assert missing.status_code == 403

    wrong = client.post("/question/report-timezone", data={"text": "UTC", "csrf_token": "guessed"})
    assert wrong.status_code == 403

    answers = load_answers(store.alias_dir("target"), "target-tenant", "target")
    assert "report-timezone" not in answers.answers


def test_wizard_pages_are_self_contained_and_plain(wizard_setup):
    client, _, _, _, _ = wizard_setup
    landing = client.get("/", follow_redirects=True)
    html = landing.get_data(as_text=True)
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html
    assert "—" not in html  # no em dashes anywhere


def test_wizard_rejects_a_non_loopback_host_header(wizard_setup):
    """A CSRF token cannot help against DNS rebinding: an attacker page rebound
    to 127.0.0.1 becomes same-origin and can read the token out of a page. The
    rebound request still carries the attacker's Host, so refusing any
    non-loopback Host closes it (AUTHZ-2-001)."""
    client, _, _, _, _ = wizard_setup
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 403
    assert client.get("/", headers={"Host": "127.0.0.1:8765"}).status_code in (200, 302)
    assert client.get("/", headers={"Host": "localhost"}).status_code in (200, 302)


def test_wizard_reuses_parsed_state_across_requests(wizard_setup, monkeypatch):
    """The snapshot is immutable for the wizard's lifetime, so the expensive
    parse + gzip re-stream should happen once, not on every request
    (PERF-2-001)."""
    import iamai.web as web

    calls = {"n": 0}
    real = web.load_snapshot_data

    def counting(snapshot_dir):
        calls["n"] += 1
        return real(snapshot_dir)

    monkeypatch.setattr(web, "load_snapshot_data", counting)
    client, _, _, _, _ = wizard_setup
    for _ in range(4):
        client.get("/", follow_redirects=False)
    assert calls["n"] == 1, f"snapshot parsed {calls['n']} times across 4 requests"


runner = CliRunner()


def test_wizard_command_serves_on_localhost_only(workspace, mock_graph, monkeypatch):  # noqa: F811
    freeze_test_baseline()
    assert runner.invoke(cli.app, ["assess", "golden"]).exit_code == 0

    captured = {}

    def fake_run(self, host=None, port=None, **kwargs):
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr("flask.Flask.run", fake_run)
    result = runner.invoke(cli.app, ["wizard", "golden"])
    assert result.exit_code == 0, result.output
    assert captured == {"host": "127.0.0.1", "port": 8765}
    assert "http://127.0.0.1:8765" in result.output
