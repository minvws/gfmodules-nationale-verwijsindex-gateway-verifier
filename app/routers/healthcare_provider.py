import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse

from app.config import get_config
from app.container import get_ca_service, get_healthcare_provider_service, get_jwt_service
from app.services.ca import CaService
from app.services.healthcare_provider import HealthcareProviderService
from app.services.jwt import JwtException, JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


def run_validate(
    request: Request,
    healthcare_service: HealthcareProviderService,
    ca_service: CaService,
    jwt_service: JWTService,
) -> Response:
    config = get_config()

    auth = request.headers.get("Authorization")
    if auth is None or not auth.startswith("Bearer "):
        return Response("Bearer authorization header is required", status_code=401)
    token = auth[len("Bearer ") :]

    (is_oin_cert, cert_oin) = ca_service.is_oin_certificate(request)
    if not is_oin_cert or cert_oin is None:
        return Response("Failed to extract OIN certificate from request.", status_code=403)

    try:
        token = jwt_service.verify(token, config.app.issuer, config.app.audience)
    except JwtException as e:
        logger.error(f"Failed to verify JWT: {e}")
        return Response("Token verification failed", status_code=400)

    claims = json.loads(token.claims)
    jwt_oin = claims["oin"]
    if jwt_oin is None:
        return Response("Failed to extract OIN number", status_code=400)
    if str(jwt_oin) != str(cert_oin):
        return Response("Certificate OIN does not match JWT OIN", status_code=400)

    source_id = request.headers.get("X-Source-Id") or None
    entities = healthcare_service.find(cert_oin, source_id)
    if len(entities) == 0:
        return Response(status_code=404)
    if len(entities) > 1:
        return Response("Multiple healthcare provider entries found for the given OIN and source_id", status_code=400)

    return JSONResponse(
        {
            "X-Oin-Number": str(jwt_oin),
            "X-Source-Id": source_id,
            "X-Ura-Number": entities[0].ura_number,
            "X-Authorized-Role": claims["authorized_role"],
            "X-Audience": claims["aud"],
        },
        status_code=200,
    )


@router.get("/validate")
def validate(
    request: Request,
    healthcare_service: Annotated[HealthcareProviderService, Depends(get_healthcare_provider_service)],
    ca_service: Annotated[CaService, Depends(get_ca_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    return run_validate(request, healthcare_service, ca_service, jwt_service)
