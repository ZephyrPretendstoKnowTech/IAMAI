"""The assessment and plan artifacts conform to the published JSON schemas.

The schemas in schemas/ are the machine-readable half of ARTIFACTS.md, the
contract a Claude skill or any other reader builds against. These tests keep
the real output and the schema in agreement, so the contract cannot silently
drift.

jsonschema is not a dependency (this tool keeps its dependency set small), so a
minimal validator for the subset of JSON Schema the schemas actually use is
implemented here. A self-test confirms the validator rejects violations rather
than passing everything.
"""

import json
from pathlib import Path

import pytest

from iamai.grade import assess_snapshot
from iamai.store import load_snapshot_data

from test_m1_canon import make_artifact

pytestmark = pytest.mark.m13

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"


def validate(instance, schema, defs=None, path="$"):
    """Validate `instance` against the JSON Schema subset the artifact schemas
    use: type, required, properties, items, enum, const, minimum, $ref into
    #/$defs, and additionalProperties. Returns a list of error strings (empty
    when valid)."""
    defs = defs if defs is not None else schema.get("$defs", {})
    errors: list[str] = []

    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/$defs/"), ref
        return validate(instance, defs[ref.split("/")[-1]], defs, path)

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")

    types = schema.get("type")
    if types:
        types = [types] if isinstance(types, str) else types
        ok = any(_is_type(instance, t) for t in types)
        if not ok:
            errors.append(f"{path}: {type(instance).__name__} is not any of {types}")
            return errors  # further checks assume the type held

    if schema.get("type") == "object" or isinstance(instance, dict) and "properties" in schema:
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required '{req}'")
        props = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                errors += validate(value, props[key], defs, f"{path}.{key}")
            else:
                extra = schema.get("additionalProperties")
                if isinstance(extra, dict):
                    errors += validate(value, extra, defs, f"{path}.{key}")

    if schema.get("type") == "array" and isinstance(instance, list):
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(instance):
                errors += validate(item, item_schema, defs, f"{path}[{i}]")

    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        errors.append(f"{path}: {instance} < minimum {schema['minimum']}")

    return errors


def _is_type(instance, t):
    if t == "object":
        return isinstance(instance, dict)
    if t == "array":
        return isinstance(instance, list)
    if t == "string":
        return isinstance(instance, str)
    if t == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if t == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if t == "boolean":
        return isinstance(instance, bool)
    if t == "null":
        return instance is None
    raise AssertionError(f"unknown type {t}")


def _load_schema(name):
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_the_validator_actually_rejects_violations():
    """A validator that passes everything would make the other tests
    meaningless. Confirm it catches a missing required field, a wrong type,
    and a bad enum value."""
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "integer"}, "g": {"$ref": "#/$defs/grade"}},
        "$defs": {"grade": {"enum": ["FULL", "MISSING"]}},
    }
    assert validate({"a": 1}, schema) == []
    assert validate({}, schema)  # missing required
    assert validate({"a": "no"}, schema)  # wrong type
    assert validate({"a": 1, "g": "NONSENSE"}, schema)  # bad enum


def test_a_real_assessment_conforms_to_its_schema():
    data, manifest = load_snapshot_data(FIXTURES)
    assessment = assess_snapshot(
        make_artifact(data), data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )
    errors = validate(assessment, _load_schema("assessment.schema.json"))
    assert not errors, "assessment does not conform:\n" + "\n".join(errors)


def test_a_real_plan_conforms_to_its_schema():
    from test_m4_plan import make_plan

    data, manifest = load_snapshot_data(FIXTURES)
    plan, _ = make_plan(data, manifest)
    errors = validate(plan, _load_schema("plan.schema.json"))
    assert not errors, "plan does not conform:\n" + "\n".join(errors)


def test_schemas_are_valid_json_and_self_describe():
    for name in ("assessment.schema.json", "plan.schema.json"):
        schema = _load_schema(name)
        assert schema["$schema"].startswith("https://json-schema.org/")
        assert schema["type"] == "object"
        assert schema["required"], name
