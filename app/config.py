import configparser
import logging
import os
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)


_PATH = "app.conf"
_ENVIRONMENT_CONFIG_PATH_NAME = "FASTAPI_CONFIG_PATH"
_CONFIG = None


class LogLevel(str, Enum):
    debug = "debug"
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class ConfigApp(BaseModel):
    loglevel: LogLevel = Field(default=LogLevel.info)


class ConfigLogging(BaseModel):
    app_path: str | None = Field(default=None)
    siem_path: str | None = Field(default=None)
    public_inspect_path: str | None = Field(default=None)
    debug_path: str | None = Field(default=None)
    include_traces: bool = Field(default=True)
    debug_logs_in_console: bool = Field(default=False)


class ConfigOin(BaseModel):
    oin_ca_path: str
    issuer: str
    audience: list[str]
    jwks_url: str
    mtls_cert: str | None = Field(default=None)
    mtls_key: str | None = Field(default=None)
    verify_ca: bool | str = Field(default=True)

    @field_validator("verify_ca", mode="before")
    @classmethod
    def parse_verify_ca(cls, v: Any) -> Any:
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower() == "true"
        return v

    @field_validator("audience", mode="before")
    @classmethod
    def parse_audience(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


class ConfigUvicorn(BaseModel):
    swagger_enabled: bool = Field(default=False)
    docs_url: str = Field(default="/docs")
    redoc_url: str = Field(default="/redoc")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8503, gt=0, lt=65535)
    reload: bool = Field(default=True)
    reload_delay: float = Field(default=1)
    reload_dirs: list[str] = Field(default=["app"])
    use_ssl: bool = Field(default=False)
    ssl_base_dir: str | None
    ssl_cert_file: str | None
    ssl_key_file: str | None


class ConfigTelemetry(BaseModel):
    enabled: bool = Field(default=False)
    endpoint: str | None
    service_name: str | None
    tracer_name: str | None


class ConfigStats(BaseModel):
    enabled: bool = Field(default=False)
    host: str | None
    port: int | None
    module_name: str | None


class ConfigKongProxy(BaseModel):
    enabled: bool = Field(default=False)
    url: str


class Config(BaseModel):
    app: ConfigApp
    logging: ConfigLogging = Field(default_factory=ConfigLogging)
    telemetry: ConfigTelemetry
    stats: ConfigStats
    uvicorn: ConfigUvicorn
    kong_proxy: ConfigKongProxy
    oin: ConfigOin


def read_ini_file(path: str) -> Any:
    ini_data = configparser.ConfigParser()
    ini_data.read(path)

    ret = {}
    for section in ini_data.sections():
        ret[section] = dict(ini_data[section])
        remove_empty_values(ret[section])
    return ret


def remove_empty_values(section: dict[str, Any]) -> None:
    for key in list(section.keys()):
        if section[key] == "":
            del section[key]


def reset_config() -> None:
    global _CONFIG
    _CONFIG = None


def set_config(config: Config) -> None:
    global _CONFIG
    _CONFIG = config


def get_config(path: str | None = None) -> Config:
    global _CONFIG
    global _PATH

    if _CONFIG is not None:
        return _CONFIG

    if path is None:
        path = os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME) or _PATH

    # To be inline with other python code, we use INI-type files for configuration. Since this isn't
    # a standard format for pydantic, we need to do some manual parsing first.
    ini_data = read_ini_file(path)

    try:
        _CONFIG = Config.model_validate(ini_data)
    except ValidationError as e:
        logger.error(f"Configuration validation error: {e}")
        raise e

    return _CONFIG
