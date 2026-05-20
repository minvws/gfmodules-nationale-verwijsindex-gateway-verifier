import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse

from app.config import Config, get_config
from app.container import get_ca_service, get_jwt_service
from app.models.oin import OinNumber
from app.services.ca import CaService
from app.services.jwt import JwtException, JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


def _aud_str(aud: object) -> str:
    """Normalise the JWT aud claim to a string — it can legally be a string or a list."""
    if isinstance(aud, list):
        return ", ".join(str(a) for a in aud)
    return str(aud) if aud is not None else ""


def run_validate(
    request: Request,
    ca_service: CaService,
    jwt_service: JWTService,
) -> Response:
    logger.debug("Received request for /validate endpoint")
    config = get_config()

    auth = request.headers.get("Authorization")
    if auth is None or not auth.startswith("Bearer "):
        logger.error("Received invalid authorization header")
        return Response("Bearer authorization header is required", status_code=401)
    token = auth[len("Bearer ") :]
    ok, cert_oin = ca_service.is_oin_certificate(request)
    if ok and cert_oin is not None:
        return _validate_oin(cert_oin, token, request, ca_service, jwt_service, config)

    return Response("Authentication failed", status_code=403)


def _check_cert_fingerprint(claims: dict[str, object], request: Request, ca_service: CaService) -> Response | None:
    """Returns an error Response if the cnf/x5t#S256 fingerprint is missing or doesn't match the cert."""
    cnf = claims.get("cnf")
    thumbprint = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    if not thumbprint:
        logger.error("Missing cnf/x5t#S256 claim in token")
        return Response("Missing certificate fingerprint claim in token", status_code=400)
    if not ca_service.check_cert_fingerprint(request, thumbprint):
        logger.error("Certificate fingerprint does not match cnf/x5t#S256 claim")
        return Response("Certificate fingerprint mismatch", status_code=400)
    return None


def _validate_oin(
    cert_oin: OinNumber,
    token: str,
    request: Request,
    ca_service: CaService,
    jwt_service: JWTService,
    config: Config,
) -> Response:
    try:
        verified_token = jwt_service.verify(token, config.oin.issuer, config.oin.audience)
    except JwtException as e:
        logger.error(f"Failed to verify JWT: {e}")
        return Response("Token verification failed", status_code=400)

    claims = json.loads(verified_token.claims)

    if err := _check_cert_fingerprint(claims, request, ca_service):
        return err

    jwt_oin = claims.get("oin") or claims.get("oin_number")
    if not jwt_oin:
        logger.error("Missing OIN claim in token")
        return Response("Missing OIN claim in token", status_code=400)
    if str(jwt_oin) != str(cert_oin):
        logger.error(f"OIN mismatch: cert={cert_oin}, jwt={jwt_oin}")
        return Response("Certificate OIN does not match JWT OIN", status_code=400)

    headers: dict[str, str] = {
        "x-gf-cert-type": "OIN",
        "x-gf-audience": _aud_str(claims.get("aud")),
        "x-gf-scope": claims.get("scope", ""),
        "x-gf-authorized-role": claims.get("authorized_role", ""),
    }
    if claims.get("oin"):
        headers["x-gf-oin"] = str(claims["oin"])
    if claims.get("source_id"):
        headers["x-gf-source-id"] = str(claims["source_id"])

    return JSONResponse(headers, status_code=200)


@router.get("/validate")
def validate(
    request: Request,
    ca_service: Annotated[CaService, Depends(get_ca_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    return run_validate(request, ca_service, jwt_service)
