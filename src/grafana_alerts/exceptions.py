class AlertManagerError(Exception):
    """Base error for expected, user-facing failures."""


class ConfigError(AlertManagerError):
    """Raised when a site file or rendered rule group is invalid."""


class AuditConflictError(ConfigError):
    """Raised when an immutable audit identifier has already been used."""


class GrafanaApiError(AlertManagerError):
    """Raised when Grafana returns an unsuccessful response."""


class ProxyApiError(AlertManagerError):
    """Raised when the deployment proxy rejects or cannot complete a mutation."""

    def __init__(
        self,
        message: str,
        *,
        audit_id: str | None = None,
        audit_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.audit_id = audit_id
        self.audit_sha256 = audit_sha256
