"""Config load/save.

config.yaml is written and read by this module only. The dependency list in
the specification is exclusive and does not include a YAML library, so this
module implements the small YAML subset the config actually uses: scalar
string values and one nested mapping (tenants), with comments and blank lines.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path("config.yaml")


class Config(BaseModel):
    """Tool configuration. V1 holds exactly two tenants: golden and target."""

    appId: str
    homeTenantId: str
    certPath: str
    goldenTenantId: str
    tenants: dict[str, str] = Field(default_factory=dict)

    def tenant_id(self, alias: str) -> str:
        if alias not in self.tenants:
            known = ", ".join(sorted(self.tenants)) or "(none)"
            raise KeyError(f"Unknown tenant alias '{alias}'. Known aliases: {known}")
        return self.tenants[alias]


def _parse_simple_yaml(text: str) -> dict:
    """Parse the YAML subset used by config.yaml.

    Supports `key: value` scalars at the top level and one level of nested
    mapping introduced by `key:` followed by two-space-indented `key: value`
    lines. Comments (#) and blank lines are ignored. Quotes around values are
    stripped.
    """
    result: dict = {}
    current_nested: dict | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indented = line.startswith("  ")
        key, sep, value = stripped.partition(":")
        if not sep:
            raise ValueError(f"Cannot parse config line: {raw_line!r}")
        key = key.strip()
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if indented:
            if current_nested is None:
                raise ValueError(f"Unexpected indented line: {raw_line!r}")
            current_nested[key] = value
        elif value == "":
            current_nested = {}
            result[key] = current_nested
        else:
            current_nested = None
            result[key] = value
    return result


def _emit_simple_yaml(data: dict) -> str:
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for nested_key, nested_value in value.items():
                lines.append(f"  {nested_key}: {nested_value}")
        else:
            lines.append(f"{key}: {value}")
    return "\n".join(lines) + "\n"


def load_config(path: Path | None = None) -> Config:
    config_path = path or DEFAULT_CONFIG_PATH
    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found at {config_path}. Run 'iamai setup' first."
        )
    return Config.model_validate(_parse_simple_yaml(config_path.read_text(encoding="utf-8")))


def save_config(config: Config, path: Path | None = None) -> Path:
    config_path = path or DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_emit_simple_yaml(config.model_dump()), encoding="utf-8")
    return config_path
