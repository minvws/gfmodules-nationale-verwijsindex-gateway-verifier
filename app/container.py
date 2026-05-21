import logging

import inject

from app.config import Config, get_config
from app.services.ca import CaService
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()
    binder.bind(Config, config)

    ca_service = CaService([config.oin.oin_ca_path])
    binder.bind(CaService, ca_service)

    jwt_service = JWTService(
        config.oin.jwks_url,
        config.oin.mtls_cert,
        config.oin.mtls_key,
        config.oin.verify_ca,
    )
    binder.bind(JWTService, jwt_service)


def get_ca_service() -> CaService:
    return inject.instance(CaService)


def get_jwt_service() -> JWTService:
    return inject.instance(JWTService)


def configure() -> None:
    inject.configure(container_config, once=True)
