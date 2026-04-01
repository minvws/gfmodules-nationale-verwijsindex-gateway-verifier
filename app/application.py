import logging
from typing import Any

import uvicorn
from fastapi import FastAPI

from app import container
from app.config import get_config
from app.middleware.stats import StatsdMiddleware
from app.routers.default import router as default_router
from app.routers.health import router as health_router
from app.routers.healthcare_provider import router as healthcare_provider_router


def get_uvicorn_params() -> dict[str, Any]:
    config = get_config()

    kwargs = {
        "host": config.uvicorn.host,
        "port": config.uvicorn.port,
        "reload": config.uvicorn.reload,
        "reload_delay": config.uvicorn.reload_delay,
        "reload_dirs": config.uvicorn.reload_dirs,
        "factory": True,
    }
    if (
        config.uvicorn.use_ssl
        and config.uvicorn.ssl_base_dir is not None
        and config.uvicorn.ssl_cert_file is not None
        and config.uvicorn.ssl_key_file is not None
    ):
        kwargs["ssl_keyfile"] = config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_key_file
        kwargs["ssl_certfile"] = config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_cert_file
    return kwargs


def run() -> None:
    uvicorn.run("app.application:create_fastapi_app", **get_uvicorn_params())


def create_fastapi_app() -> FastAPI:
    setup_logging()
    fastapi = setup_fastapi()

    return fastapi


def setup_logging() -> None:
    config = get_config()
    if config.app.loglevel.upper() not in logging.getLevelNamesMapping():
        raise ValueError(f"Invalid loglevel {config.app.loglevel.upper()}")
    logging.basicConfig(
        level=logging.getLevelNamesMapping()[config.app.loglevel.upper()],
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )


def setup_fastapi() -> FastAPI:
    config = get_config()

    fastapi = (
        FastAPI(
            docs_url=config.uvicorn.docs_url,
            redoc_url=config.uvicorn.redoc_url,
            title="Localisation API",
        )
        if config.uvicorn.swagger_enabled
        else FastAPI(docs_url=None, redoc_url=None)
    )

    container.configure()

    routers = [default_router, health_router, healthcare_provider_router]

    for router in routers:
        fastapi.include_router(router)

    if config.stats.enabled:
        fastapi.add_middleware(StatsdMiddleware, module_name=config.stats.module_name or "default")

    return fastapi
