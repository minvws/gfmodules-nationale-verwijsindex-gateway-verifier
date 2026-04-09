import logging

import inject

from app.config import Config, get_config
from app.db.db import Database
from app.services.ca import CaService
from app.services.healthcare_provider import HealthcareProviderService
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()
    binder.bind(Config, config)

    db = Database(config_database=config.database)
    binder.bind(Database, db)

    healthcare_provider_service = HealthcareProviderService(db)
    binder.bind(HealthcareProviderService, healthcare_provider_service)

    ca_service = CaService(config.app.oin_ca_path)
    binder.bind(CaService, ca_service)

    jwt_service = JWTService(
        config.app.jwks_url,
        config.app.mtls_cert,
        config.app.mtls_key,
        config.app.verify_ca,
    )
    binder.bind(JWTService, jwt_service)


def get_database() -> Database:
    return inject.instance(Database)


def get_healthcare_provider_service() -> HealthcareProviderService:
    return inject.instance(HealthcareProviderService)


def get_ca_service() -> CaService:
    return inject.instance(CaService)


def get_jwt_service() -> JWTService:
    return inject.instance(JWTService)


def configure() -> None:
    inject.configure(container_config, once=True)
