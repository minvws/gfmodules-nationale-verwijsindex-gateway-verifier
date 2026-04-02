import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.container import get_healthcare_provider_service, get_jwt_service
from app.services.healthcare_provider import HeatlhcareProviderService
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/validate", tags=["Gateway Request Validation"])


@router.get("")
def validate(
    request: Request,
    service: Annotated[HeatlhcareProviderService, Depends(get_healthcare_provider_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Any:
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None:
        raise HTTPException(status_code=400)

    token = authorization_header.strip("Bearer").strip()
    data = jwt_service.deserialize(token)
    oin = data.get("oin-number")
    ura_number = data.get("ura-number")
    source_id = data.get("source-id")
    if oin is None or ura_number is None:
        raise HTTPException(status_code=404)
    results = service.exists(oin, ura_number, source_id)
    return Response(status_code=200 if results is True else 404)
