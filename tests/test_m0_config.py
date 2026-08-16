import pytest

from iamai.config import Config, load_config, save_config

pytestmark = pytest.mark.m0


def _sample_config() -> Config:
    return Config(
        appId="f0000000-0000-0000-0000-00000000000f",
        homeTenantId="11111111-1111-1111-1111-111111111111",
        certPath="certs/iamai.pem",
        goldenTenantId="11111111-1111-1111-1111-111111111111",
        tenants={
            "golden": "11111111-1111-1111-1111-111111111111",
            "target": "22222222-2222-2222-2222-222222222222",
        },
    )


def test_roundtrip(tmp_path):
    path = tmp_path / "config.yaml"
    save_config(_sample_config(), path)
    loaded = load_config(path)
    assert loaded == _sample_config()


def test_parse_tolerates_comments_and_quotes(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "# IAMAI config\n"
        "appId: 'f0000000-0000-0000-0000-00000000000f'\n"
        "homeTenantId: 11111111-1111-1111-1111-111111111111\n"
        "certPath: certs/iamai.pem\n"
        "goldenTenantId: 11111111-1111-1111-1111-111111111111\n"
        "\n"
        "tenants:\n"
        "  golden: 11111111-1111-1111-1111-111111111111\n"
        "  target: 22222222-2222-2222-2222-222222222222\n",
        encoding="utf-8",
    )
    loaded = load_config(path)
    assert loaded == _sample_config()


def test_missing_config_points_at_setup(tmp_path):
    with pytest.raises(FileNotFoundError, match="iamai setup"):
        load_config(tmp_path / "config.yaml")


def test_unknown_alias_lists_known(tmp_path):
    with pytest.raises(KeyError, match="golden"):
        _sample_config().tenant_id("nope")
