import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.container import get_healthcare_provider_service
from app.services.healthcare_provider import HeatlhcareProviderService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/healthcare-providers", tags=["Healthcare Providers"])


@router.get("")
def validate(
    request: Request,
    service: Annotated[HeatlhcareProviderService, Depends(get_healthcare_provider_service)],
) -> Response:
    prefix = request.headers.get("X-Oin-Prefix")
    number = request.headers.get("X-Oin-Number")
    if prefix is None or number is None:
        raise HTTPException(status_code=400)

    oin = str(prefix + number)
    results = service.exists(oin)
    return Response(status_code=200 if results is True else 404)
