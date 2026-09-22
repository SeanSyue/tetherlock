"""Tetherlock: access control for a protected workspace, tied to a physical device."""

from tetherlock.access import (
    DEFAULT_SCOPE,
    AccessGrant,
    AccessTokenError,
    TrustedKeyEntry,
    TrustStore,
    VerifiedAccessToken,
    discover_verified_tokens,
    issue_token_document,
    revalidate_token,
    token_filename_for_scope,
    unlock_verified_token,
    verify_token_file,
)
from tetherlock.monitor import WorkspaceMonitor

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_SCOPE",
    "AccessGrant",
    "AccessTokenError",
    "TrustStore",
    "TrustedKeyEntry",
    "VerifiedAccessToken",
    "WorkspaceMonitor",
    "discover_verified_tokens",
    "issue_token_document",
    "revalidate_token",
    "token_filename_for_scope",
    "unlock_verified_token",
    "verify_token_file",
]
