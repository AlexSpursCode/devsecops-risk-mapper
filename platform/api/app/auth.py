from collections.abc import Callable

import jwt
from fastapi import Header, HTTPException, status

from .config import settings
from .models import Role

ROLE_PERMISSIONS = {
    Role.security_architect: {"read", "ingest", "evaluate", "model", "admin"},
    Role.appsec_engineer: {"read", "ingest", "evaluate", "model"},
    Role.dev_lead: {"read", "evaluate"},
    Role.auditor: {"read"},
    Role.platform_admin: {"read", "ingest", "evaluate", "model", "admin"},
}


def _resolve_role(x_role: str | None, authorization: str | None) -> Role:
    if settings.auth_mode == "jwt":
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = jwt.decode(token, settings.auth_jwt_secret, algorithms=[settings.auth_jwt_algorithm])
            role_raw = claims.get("role")
            return Role(role_raw)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token") from exc

    role_text = x_role or "dev_lead"
    try:
        role = Role(role_text)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid role") from exc
    return role


def require_permission(permission: str, x_role: str | None, authorization: str | None) -> Role:
    role = _resolve_role(x_role, authorization)
    if permission not in ROLE_PERMISSIONS[role]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient permissions")
    return role


def permission_dependency(permission: str) -> Callable:
    def _dep(
        x_role: str | None = Header(default="dev_lead"),
        authorization: str | None = Header(default=None),
    ) -> Role:
        return require_permission(permission, x_role, authorization)

    return _dep
