from app.config import Config, ConfigKongProxy
from app.features import FEATURES, enabled_features
from tests.conftest import make_config


def _config(kong_proxy_enabled: bool) -> Config:
    return make_config(kong_proxy=ConfigKongProxy(enabled=kong_proxy_enabled, url="http://kong.example.com"))


def _ids(config: Config) -> list[str]:
    return [feature.id for feature in enabled_features(config)]


def test_all_features_enabled_with_kong_proxy() -> None:
    assert _ids(_config(kong_proxy_enabled=True)) == [feature.info.id for feature in FEATURES]


def test_kong_proxy_feature_follows_config_flag() -> None:
    assert "kong_proxy" in _ids(_config(kong_proxy_enabled=True))
    assert "kong_proxy" not in _ids(_config(kong_proxy_enabled=False))


def test_feature_ids_are_unique() -> None:
    ids = [feature.info.id for feature in FEATURES]

    assert len(ids) == len(set(ids))
