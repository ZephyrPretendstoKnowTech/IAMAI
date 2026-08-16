# Contributing

Thanks for looking at IAMAI. This is a read-only identity posture tool for
Microsoft Entra; the guiding aim is that it is honest, safe to run against a live
production tenant, and easy for a non-specialist to read.

## Getting set up

You need Python 3.12.

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.venv\Scripts\python.exe -m pip install --no-deps -e .
.venv\Scripts\python.exe -m pytest -q
```

On macOS or Linux use `.venv/bin/python`. The test suite makes **zero** live
network calls: every Graph interaction is served from recorded, sanitized
fixtures, and the harness fails rather than allowing a real request. A change
should keep the suite green and add tests for new behaviour.

## Ground rules

These are not style preferences; they protect the tool's promises.

- **Read only.** Never add a Graph call that writes, nor a code path that changes
  a tenant. The only write scope is the one setup uses to create the tool's own
  app.
- **No real identifiers anywhere in the repository.** No real tenant ids, user
  principal names, display names, or IP addresses in code, tests, fixtures, docs
  or commit messages. Test fixtures are sanitized; keep them that way.
- **Nothing leaves the machine.** No telemetry, no new network destinations
  beyond Microsoft's own endpoints. Published pages under `docs/` must be
  self-contained: no external script, stylesheet, font or image. A small
  *inline* script is allowed on the docs pages (for example the copy buttons),
  but the report, plan and wizard, which handle real tenant data, stay strictly
  script-free.
- **Plain language in anything a user sees**, and no em dashes in user-facing
  copy (reports, plans, the wizard, the docs pages).
- **Grades are conservative.** Ambiguity grades down, never up. `UNKNOWN` is a
  real answer, not a failure to be smoothed over.

## Regenerating generated files

- **Dependencies.** `requirements.txt` and `requirements-dev.txt` are generated,
  not hand-edited. After changing a pin in `pyproject.toml`, regenerate both with
  [pip-tools](https://pypi.org/project/pip-tools/):

  ```
  pip-compile --generate-hashes --output-file=requirements.txt pyproject.toml
  pip-compile --generate-hashes --extra=test --output-file=requirements-dev.txt pyproject.toml
  ```

- **The docs pages.** `docs/index.html`, `docs/use-cases.html`, `docs/guide.html`
  and `docs/example-report.html` are generated from the scripts in `scripts/` and
  the shared theme in `src/iamai/theme.py`. After changing the theme or the copy,
  regenerate with the matching `python scripts/build_*.py` and commit the result.
  Drift tests fail if a committed page no longer matches its generator.

## Tests and structure

- Tests live in `tests/`, grouped by milestone marker (see `pyproject.toml`).
- Prefer a test that reads from the sanitized golden fixture in
  `tests/fixtures/golden_sanitized` over inventing new data.
- `ARTIFACTS.md` and `schemas/` are the contract for the assessment and plan
  JSON; if you change the output shape, update both, and the schema test will
  keep them in agreement.

## Pull requests

Keep changes focused, explain the why, and make sure the full suite passes.
Commit messages that describe the reasoning, not just the change, are
appreciated. For anything security-relevant, see `SECURITY.md`.
