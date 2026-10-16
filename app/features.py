from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from app.config import Config


class FeatureInfo(BaseModel):
    id: str
    title: str
    description: str


@dataclass(frozen=True)
class Feature:
    info: FeatureInfo
    enabled: Callable[[Config], bool]


FEATURES: list[Feature] = [
    Feature(
        info=FeatureInfo(
            id="gateway_validation",
            title="Gateway request validation",
            description=(
                "Validate the bearer token and acting identity of gateway requests and return the verified "
                "identity headers"
            ),
        ),
        enabled=lambda _: True,
    ),
    Feature(
        info=FeatureInfo(
            id="kong_proxy",
            title="Kong proxy (development)",
            description=(
                "Development reverse proxy that emulates Kong: validates requests and forwards them to the "
                "backend with the verified identity headers"
            ),
        ),
        enabled=lambda config: config.kong_proxy.enabled,
    ),
]


def enabled_features(config: Config) -> list[FeatureInfo]:
    return [feature.info for feature in FEATURES if feature.enabled(config)]
