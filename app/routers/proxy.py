import json
import logging
from typing import Annotated

import requests as http_requests
from fastapi import APIRouter, Depends, Request, Response

from app.config import get_config
from app.container import get_ca_service, get_healthcare_provider_service, get_jwt_service
from app.routers.healthcare_provider import run_validate
from app.services.ca import CaService
from app.services.healthcare_provider import HealthcareProviderService
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.api_route("/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(
    request: Request,
    healthcare_service: Annotated[HealthcareProviderService, Depends(get_healthcare_provider_service)],
    ca_service: Annotated[CaService, Depends(get_ca_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    config = get_config()

    if not config.kong_proxy.enabled:
        return Response("Kong proxy is not enabled", status_code=503)

    # Validate the request using the same logic as /validate
    validate_response = run_validate(request, healthcare_service, ca_service, jwt_service)
    if validate_response.status_code != 200:
        return validate_response

    # Convert the X-* fields from the validate response into HTTP headers
    validate_data = json.loads(bytes(validate_response.body))
    x_headers = {k: str(v) for k, v in validate_data.items() if k.startswith("X-") and v is not None}

    # Forward the original request body to the kong proxy using the same HTTP method
    body = await request.body()
    kong_response = http_requests.request(
        request.method, config.kong_proxy.url, headers=x_headers, data=body, timeout=30
    )

    return Response(content=kong_response.content, status_code=kong_response.status_code)
