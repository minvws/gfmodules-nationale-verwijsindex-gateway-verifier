from typing import Annotated, Any, Dict, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    certificate_organization_identifier: Annotated[str, Field(alias="x-gf-act-sub")]
    certificate_domain: Annotated[str, Field(alias="x-gf-act-cn")]
    bearer: Annotated[str, Field(alias="Authorization")]

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: Dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            value = headers.get(header_name)

            data[name] = value

        return cls(**data)
