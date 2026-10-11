# Authentication and validation

import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_api_key

# Only accepts strings or none
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided: str | None = Security(api_key_header)) -> None:
    expected = get_api_key()
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key not configured on server",
        )
    if provided is None or not secrets.compare_digest(
        provided.encode(), expected.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
