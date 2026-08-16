"""The app keeps its files in one per-user location, overridable by IAMAI_HOME.

These guard that the tool never again writes data, certs or config into the
working directory, and that the override the installer and the test suite rely
on actually takes effect.
"""

import pathlib

import pytest

from iamai import paths

pytestmark = pytest.mark.m0


def test_iamai_home_override_controls_every_path(monkeypatch, tmp_path):
    monkeypatch.setenv("IAMAI_HOME", str(tmp_path))
    assert paths.app_home() == tmp_path
    assert paths.data_dir() == tmp_path / "data"
    assert paths.config_path() == tmp_path / "config.yaml"
    assert paths.cert_dir() == tmp_path / "certs"


def test_default_home_is_a_per_user_app_directory_not_the_cwd(monkeypatch):
    monkeypatch.delenv("IAMAI_HOME", raising=False)
    home = paths.app_home()
    # An absolute per-user location, not "data" relative to wherever it ran.
    assert home.is_absolute()
    assert home.name == "IAMAI"
    assert home != pathlib.Path("data").resolve().parent / "data"


def test_store_config_and_cert_default_under_the_app_home(monkeypatch, tmp_path):
    monkeypatch.setenv("IAMAI_HOME", str(tmp_path))
    from iamai.config import Config, load_config, save_config
    from iamai.store import SnapshotStore

    # SnapshotStore with no explicit dir lands under the app home.
    assert SnapshotStore().data_dir == tmp_path / "data"

    # save/load config with no explicit path uses the app home, creating it.
    config = Config(
        appId="f0000000-0000-0000-0000-00000000000f",
        homeTenantId="11111111-1111-1111-1111-111111111111",
        certPath=str(tmp_path / "certs" / "iamai.pem"),
        goldenTenantId="11111111-1111-1111-1111-111111111111",
        tenants={"golden": "11111111-1111-1111-1111-111111111111"},
    )
    saved = save_config(config)
    assert saved == tmp_path / "config.yaml"
    assert load_config().appId == config.appId
