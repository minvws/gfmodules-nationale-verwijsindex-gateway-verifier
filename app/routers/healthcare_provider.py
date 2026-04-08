import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.config import get_config
from app.container import get_ca_service, get_healthcare_provider_service, get_jwt_service
from app.services.ca import CaService
from app.services.healthcare_provider import HealthcareProviderService
from app.services.jwt import JwtException, JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/validate")
def validate(
    request: Request,
    healthcare_service: Annotated[HealthcareProviderService, Depends(get_healthcare_provider_service)],
    ca_service: Annotated[CaService, Depends(get_ca_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    config = get_config()

    # Get authorization JWT token
    auth = request.headers.get("Authorization")
    if auth is None or not auth.startswith("Bearer "):
        return Response("Bearer authorization header is required", status_code=401)
    token = auth[len("Bearer ") :]

    # Fetch OIN certificate
    (is_oin_cert, cert_oin) = ca_service.is_oin_certificate(request)
    if not is_oin_cert or cert_oin is None:
        return Response("Failed to extract OIN certificate from request.", 403)

    # Check if we have a valid JWT
    try:
        token = jwt_service.verify(token, config.app.issuer, config.app.audience)
    except JwtException as e:
        logger.error(f"Failed to verify JWT: {e}")
        return Response("Token verification failed", status_code=400)

    # Check if the token's OIN matches the certificate's OIN
    claims = json.loads(token.claims)
    jwt_oin = claims["oin"]
    if jwt_oin is None:
        return Response("Failed to extract OIN number", 400)
    if str(jwt_oin) != str(cert_oin):
        return Response("Certificate OIN does not match JWT OIN", 400)

    # First, check if the OIN number exists
    source_id = request.headers.get("X-Source-Id") or None
    if healthcare_service.exists(cert_oin, source_id):
        return Response("OIN verified", status_code=200)
    else:
        return Response("OIN not found", status_code=404)
