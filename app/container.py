import logging

import inject

from app.config import Config, get_config
from app.db.db import Database
from app.services.healthcare_provider import HeatlhcareProviderService
from app.services.jwt import JWTService
from app.utils import load_file

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()
    binder.bind(Config, config)

    db = Database(config_database=config.database)
    binder.bind(Database, db)

    healthcare_provider_service = HeatlhcareProviderService(db)
    binder.bind(HeatlhcareProviderService, healthcare_provider_service)

    private_key = load_file("./secrets/test.pub").strip()

    jwt_service = JWTService(private_key)
    binder.bind(JWTService, jwt_service)


def get_database() -> Database:
    return inject.instance(Database)


def get_healthcare_provider_service() -> HeatlhcareProviderService:
    return inject.instance(HeatlhcareProviderService)


def get_jwt_service() -> JWTService:
    return inject.instance(JWTService)


def configure() -> None:
    inject.configure(container_config, once=True)
