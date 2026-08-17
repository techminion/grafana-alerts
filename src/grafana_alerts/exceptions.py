class AlertManagerError(Exception):
    """Base error for expected, user-facing failures."""


class ConfigError(AlertManagerError):
    """Raised when a site file or rendered rule group is invalid."""


class GrafanaApiError(AlertManagerError):
    """Raised when Grafana returns an unsuccessful response."""

