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

    logger.debug("Received request for /validate endpoint")

    auth = request.headers.get("Authorization")
    if auth is None or not auth.startswith("Bearer "):
        logger.error("Received invalid authorization header")
        return Response("Bearer authorization header is required", status_code=401)
    token = auth[len("Bearer ") :]

    (is_oin_cert, cert_oin) = ca_service.is_oin_certificate(request)
    if not is_oin_cert or cert_oin is None:
        logger.error("Failed to validate OIN certificate from request")
        return Response("Failed to extract OIN certificate from request.", status_code=403)

    try:
        token = jwt_service.verify(token, config.app.issuer, config.app.audience)
    except JwtException as e:
        logger.error(f"Failed to verify JWT: {e}")
        return Response("Token verification failed", status_code=400)

    claims = json.loads(token.claims)
    jwt_oin = claims.get("oin") or claims.get("oin_number")
    if not jwt_oin:
        logger.error("Failed to extract OIN claims from token")
        return Response("Failed to extract OIN number", status_code=400)
    if str(jwt_oin) != str(cert_oin):
        logger.error(f"OIN mismatch between token and cert: cert: {cert_oin}, token: {jwt_oin}")
        return Response("Certificate OIN does not match JWT OIN", status_code=400)

    source_id = claims.get("source_id")
    entities = healthcare_service.find(cert_oin, source_id)
    if len(entities) == 0:
        logger.error(f"Failed to find any entities for {cert_oin} / {source_id}")
        return Response(status_code=404)
    if len(entities) > 1:
        logger.error(f"Found multiple entities for {cert_oin} / {source_id}")
        return Response("Multiple healthcare provider entries found for the given OIN and source_id", status_code=400)

    # Check if the URA for this oin/source is the same as in the JWT
    if entities[0].ura_number != claims["sub"]:
        logger.error(
            f"Failed to verify OIN number for {cert_oin} / {source_id}: {entities[0].ura_number} <-> {claims['sub']}"
        )
        return Response("Failed to verify OIN number", status_code=400)

    return JSONResponse(
        {
            "X-Oin-Number": str(jwt_oin),
            "X-Source-Id": source_id,
            "X-Ura-Number": entities[0].ura_number,
            "X-Authorized-Role": claims["authorized_role"],
            "X-Audience": claims["aud"],
            "X-Scope": claims["scope"],
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
