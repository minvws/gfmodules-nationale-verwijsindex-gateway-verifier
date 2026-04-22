import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse

from app.config import Config, get_config
from app.container import get_ca_service, get_healthcare_provider_service, get_jwt_service
from app.db.models.oin import OinNumber
from app.services.ca import CaService
from app.services.healthcare_provider import HealthcareProviderService
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
    healthcare_service: HealthcareProviderService,
) -> Response:
    logger.debug("Received request for /validate endpoint")
    config = get_config()

    auth = request.headers.get("Authorization")
    if auth is None or not auth.startswith("Bearer "):
        logger.error("Received invalid authorization header")
        return Response("Bearer authorization header is required", status_code=401)
    token = auth[len("Bearer ") :]

    if config.app.allow_oin_certs:
        ok, cert_oin = ca_service.is_oin_certificate(request)
        if ok and cert_oin is not None:
            return _validate_oin(cert_oin, token, request, ca_service, jwt_service, healthcare_service, config)

    if config.app.allow_uzi_certs:
        ok, cert_ura = ca_service.is_uzi_certificate(request)
        if ok and cert_ura is not None:
            return _validate_uzi(cert_ura, token, request, ca_service, jwt_service, config)

    if config.app.allow_ldn_certs and ca_service.is_ldn_certificate(request):
        return _validate_ldn(token, request, ca_service, jwt_service, config)

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
    healthcare_service: HealthcareProviderService,
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

    source_id = claims.get("source_id")
    entities = healthcare_service.find(cert_oin, source_id)
    if len(entities) == 0:
        return Response("Healthcare provider not found", status_code=404)
    if len(entities) > 1:
        return Response("Multiple healthcare provider entries found", status_code=400)

    if entities[0].ura_number != claims.get("sub"):
        logger.error("URA mismatch between database and JWT sub claim")
        return Response("URA number mismatch", status_code=400)

    headers: dict[str, str] = {
        "x-gf-cert-type": "OIN",
        "x-gf-audience": _aud_str(claims.get("aud")),
        "x-gf-ura": entities[0].ura_number,
        "x-gf-scope": claims.get("scope", ""),
        "x-gf-authorized-role": claims.get("authorized_role", ""),
    }
    if claims.get("oin"):
        headers["x-gf-oin"] = str(claims["oin"])
    if claims.get("source_id"):
        headers["x-gf-source-id"] = str(claims["source_id"])

    return JSONResponse(headers, status_code=200)


def _validate_uzi(
    cert_ura: str,
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

    jwt_ura = claims.get("sub")
    if not jwt_ura:
        logger.error("Missing sub claim in token for UZI validation")
        return Response("Missing sub claim in token", status_code=400)
    if str(jwt_ura) != str(cert_ura):
        logger.error(f"URA mismatch: cert={cert_ura}, jwt={jwt_ura}")
        return Response("Certificate URA does not match JWT sub claim", status_code=400)

    headers: dict[str, str] = {
        "x-gf-cert-type": "UZI",
        "x-gf-audience": _aud_str(claims.get("aud")),
        "x-gf-ura": cert_ura,
        "x-gf-scope": claims.get("scope", ""),
    }
    if claims.get("authorized_role"):
        headers["x-gf-authorized-role"] = claims["authorized_role"]

    return JSONResponse(headers, status_code=200)


def _validate_ldn(
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

    headers: dict[str, str] = {
        "x-gf-cert-type": "LDN",
        "x-gf-audience": _aud_str(claims.get("aud")),
        "x-gf-ura": str(claims.get("sub", "")),
        "x-gf-scope": claims.get("scope", ""),
    }
    if claims.get("authorized_role"):
        headers["x-gf-authorized-role"] = claims["authorized_role"]

    return JSONResponse(headers, status_code=200)


@router.get("/validate")
def validate(
    request: Request,
    ca_service: Annotated[CaService, Depends(get_ca_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
    healthcare_service: Annotated[HealthcareProviderService, Depends(get_healthcare_provider_service)],
) -> Response:
    return run_validate(request, ca_service, jwt_service, healthcare_service)
