"""IP Information Tool for Version 2 — reuses the Version 1 module."""

from app.modules import _v1  # noqa: F401

from ip_information import (  # noqa: E402
    format_ip_information,
    get_ip_information,
    identify_ip_type,
    reverse_dns_lookup,
    validate_ip,
)
