from typing import Annotated, Any, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    certificate_organization_identifier: Annotated[str, Field(alias="x-gf-act-sub")]
    client_domains: Annotated[list[str], Field(alias="x-gf-act-cn")]
    bearer: Annotated[str, Field(alias="Authorization")]

    @field_validator("client_domains", mode="before")
    @classmethod
    def _split_domains(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.split(",")
        return value

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
