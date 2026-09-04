import json
import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.responses import JSONResponse

from app.config import Config, get_config
from app.container import get_jwt_service
from app.logging.events import BaseLog, get_application_log
from app.models.auth_headers import AuthHeaders
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
    jwt_service: JWTService,
) -> Response:
    logger.debug("Received request for /validate endpoint")
    config = get_config()
    log = get_application_log()

    try:
        auth_headers = AuthHeaders.from_request(request)
    except ValueError:
        gflog.emit(
            logger,
            log.MISSING_AUTHORIZATION_HEADER,
            "Headers are not correctly enforced in gateway, invalid authorization headers in request.",
            fields={
                "failure_reason": "missing_oin_claim",
                "token_present": False,
                "request_headers": dict(request.headers),
            },
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Unauthorized request")
    if not auth_headers.bearer.startswith("Bearer "):
        gflog.emit(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "malformed Authorization header",
            fields={"error_reason": "malformed_authorization_header", "token_present": True},
        )
        return Response("Bearer authorization header is required", status_code=401)

    token = auth_headers.bearer[len("Bearer ") :]
    return _validate_oin(
        log=log,
        auth_headers=auth_headers,
        token=token,
        jwt_service=jwt_service,
        config=config,
    )


def _validate_oin(
    log: type[BaseLog],
    auth_headers: AuthHeaders,
    token: str,
    jwt_service: JWTService,
    config: Config,
) -> Response:
    try:
        verified_token = jwt_service.verify(token, config.oin.issuer, config.oin.audience)
    except JwtException as e:
        gflog.emit(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "failed to verify JWT",
            fields={"error_reason": str(e), "token_present": True},
        )
        return Response("Token verification failed", status_code=400)

    claims = json.loads(verified_token.claims)

    act = claims.get("act")
    if act is None:
        gflog.emit(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "Missing act in claims",
            fields={
                "client_organization_id": auth_headers.client_organization_id,
                "client_common_name": auth_headers.client_common_name,
                "failure_reason": "oin_mismatch",
                "claims": claims,
            },
        )
        return Response("Missing `act` in claims", status_code=400)

    sub_org_id = act.get("sub")
    if not sub_org_id:
        gflog.emit(
            logger,
            log.URA_AUTHORIZATION_MISMATCH,
            "missing OIN claim in token",
            fields={
                "client_organization_id": auth_headers.client_organization_id,
                "client_common_name": auth_headers.client_common_name,
                "failure_reason": "missing_oin_claim",
                "claims": claims,
            },
        )
        return Response("Missing OIN claim in token", status_code=400)

    if str(sub_org_id) != str(auth_headers.client_organization_id):
        gflog.emit(
            logger,
            log.URA_AUTHORIZATION_MISMATCH,
            "certificate OIN does not match JWT OIN",
            fields={
                "client_organization_id": auth_headers.client_organization_id,
                "client_common_name": auth_headers.client_common_name,
                "failure_reason": "oin_mismatch",
                "claims": claims,
            },
        )
        return Response("Certificate OIN does not match JWT OIN", status_code=400)

    token_common_name = act.get("cn")
    if token_common_name != auth_headers.client_common_name:
        gflog.emit(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "JWT act.cn does not match certificate CommonName",
            fields={
                "client_organization_id": auth_headers.client_organization_id,
                "client_common_name": auth_headers.client_common_name,
                "failure_reason": "oin_mismatch",
                "claims": claims,
            },
        )

        return Response("JWT `act.cn` does not match certificate CommonName", status_code=400)

    headers: dict[str, str] = {
        "x-gf-cert-type": "OIN",
        "x-gf-audience": _aud_str(claims.get("aud")),
        "x-gf-scope": claims.get("scope", ""),
        "x-gf-sub": claims.get("sub"),  # this is the parent org (RFC. 8693)
        "x-gf-act-sub": sub_org_id,
        "x-gf-act-cn": token_common_name,
        "x-gf-organization-name": claims.get("organization_name"),
    }

    if claims.get("source_id"):
        headers["x-gf-source-id"] = str(claims["source_id"])
    gflog.emit(logger, log.AUTHENTICATION_SUCCESS, "successfully validated JWT + Client", fields={"claims": claims})

    return JSONResponse(headers, status_code=200)


@router.get("/validate")
def validate(
    request: Request,
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    return run_validate(request, jwt_service)
