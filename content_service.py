"""
ContentAccessService — the single seam between the EC2 Gatekeeper and AWS.

It turns a content *object key* into a temporary, expiring access URL. Today it
runs in "mock" mode and returns a clearly-fake placeholder URL, so the whole
login -> list -> request-access flow can be demonstrated WITHOUT provisioning
any AWS resources. When the private S3 bucket and/or CloudFront distribution
are later created, flip CONTENT_ACCESS_MODE and the same call site begins
producing real signed URLs — no route or template changes required.

Modes:
  - mock              : fake local placeholder URL (default, no AWS)
  - s3-presigned      : real boto3 S3 presigned GET URL
  - cloudfront-signed : real CloudFront signed URL (CDN + OAI; required prod path)

Design notes:
  * boto3 / cryptography are imported lazily inside the AWS code paths so that
    "mock" mode runs with only Flask installed.
  * No AWS credentials are ever read from source — boto3 resolves them from the
    EC2 instance's IAM Role (least privilege).
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import config


class ConfigurationError(RuntimeError):
    """Raised when a mode is selected but its required config is missing."""


@dataclass
class AccessGrant:
    """A temporary grant of access to one content object."""

    url: str
    expires_at: datetime  # timezone-aware UTC
    mode: str
    object_key: str

    def to_dict(self) -> dict:
        """JSON-serializable form returned by the access-url API."""
        return {
            "url": self.url,
            # ISO-8601 UTC, truncated to whole seconds, e.g. "2026-05-29T12:34:56Z"
            "expiresAt": self.expires_at.replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "expiresInSeconds": config.SIGNED_URL_EXPIRY_SECONDS,
            "mode": self.mode,
        }


class AccessGrantCache:
    """
    Process-local cache of active AccessGrants so that repeated requests for the
    same content reuse one URL until it expires, instead of minting a brand-new
    URL on every click.

    Keyed by an arbitrary string (the app uses "<username>:<resourceId>"). A
    cached grant is returned while it is still valid; once past its expiry it is
    discarded and the caller mints a fresh one.

    NOTE: this lives in a single worker's memory. With multiple gunicorn workers
    each worker has its own cache, so a user's repeat clicks that land on a
    different worker could still see a different URL. For strict single-URL
    behaviour run one worker (gunicorn -w 1) for the demo, or back this with a
    shared store (e.g. Redis / DynamoDB) in production.
    """

    def __init__(self) -> None:
        self._store: Dict[str, AccessGrant] = {}
        self._lock = threading.Lock()

    def get_valid(self, key: str) -> Optional[AccessGrant]:
        """Return the cached grant if it exists and has not expired, else None."""
        now = datetime.now(timezone.utc)
        with self._lock:
            grant = self._store.get(key)
            if grant is None:
                return None
            if grant.expires_at > now:
                return grant
            # Expired — drop it so the caller regenerates.
            del self._store[key]
            return None

    def put(self, key: str, grant: AccessGrant) -> None:
        with self._lock:
            self._store[key] = grant

    def clear(self) -> None:
        """Drop all cached grants (used by tests)."""
        with self._lock:
            self._store.clear()


class ContentAccessService:
    """Generates temporary access URLs according to CONTENT_ACCESS_MODE."""

    def __init__(self, mode: Optional[str] = None, expiry_seconds: Optional[int] = None):
        self.mode = (mode or config.CONTENT_ACCESS_MODE).strip().lower()
        self.expiry_seconds = expiry_seconds or config.SIGNED_URL_EXPIRY_SECONDS

    def _expires_at(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=self.expiry_seconds)

    def generate_access_url(self, object_key: str, base_url: Optional[str] = None) -> AccessGrant:
        """Dispatch to the configured mode and return an AccessGrant."""
        if self.mode == "mock":
            return self._mock_url(object_key, base_url)
        if self.mode == "s3-presigned":
            return self._s3_presigned_url(object_key)
        if self.mode == "cloudfront-signed":
            return self._cloudfront_signed_url(object_key)
        raise ConfigurationError(
            f"Unknown CONTENT_ACCESS_MODE '{self.mode}'. "
            f"Expected one of {config.VALID_ACCESS_MODES}."
        )

    # --- mock mode ----------------------------------------------------------
    def _mock_url(self, object_key: str, base_url: Optional[str]) -> AccessGrant:
        """
        Return a clearly-fake placeholder URL. This is NOT a real S3/CloudFront
        endpoint — it points back at this app's /mock-cdn route, which renders a
        "this is a placeholder" page. Used only to demonstrate the flow locally.
        """
        expires_at = self._expires_at()
        token = secrets.token_urlsafe(16)
        base = (base_url or "https://mock-cdn.edustream.local").rstrip("/")
        url = (
            f"{base}/mock-cdn/{object_key}"
            f"?mock=true&token={token}&expires={int(expires_at.timestamp())}"
        )
        return AccessGrant(url=url, expires_at=expires_at, mode="mock", object_key=object_key)

    # --- s3 presigned mode --------------------------------------------------
    def _s3_presigned_url(self, object_key: str) -> AccessGrant:
        """
        Real S3 Presigned URL. Active only once the private content bucket
        exists and CONTENT_BUCKET_NAME is set (DEFERRED infrastructure).
        """
        if not config.CONTENT_BUCKET_NAME:
            raise ConfigurationError(
                "CONTENT_ACCESS_MODE=s3-presigned requires CONTENT_BUCKET_NAME. "
                "The private content bucket is deferred infrastructure — keep "
                "CONTENT_ACCESS_MODE=mock until it is provisioned."
            )
        expires_at = self._expires_at()
        # Lazy import so mock mode does not require boto3.
        import boto3  # noqa: PLC0415

        # No credentials passed: boto3 uses the EC2 IAM Role (least privilege).
        s3 = boto3.client("s3", region_name=config.AWS_REGION)
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": config.CONTENT_BUCKET_NAME, "Key": object_key},
            ExpiresIn=self.expiry_seconds,
        )
        return AccessGrant(url=url, expires_at=expires_at, mode="s3-presigned", object_key=object_key)

    # --- cloudfront signed mode --------------------------------------------
    def _cloudfront_signed_url(self, object_key: str) -> AccessGrant:
        """
        Real CloudFront Signed URL (canned policy) expiring in expiry_seconds.

        Content is delivered through CloudFront (the CDN) for global low-latency
        access; CloudFront reaches the private S3 origin via an Origin Access
        Identity (OAI), so the bucket itself stays fully private. Requires the
        distribution domain, the trusted key's Key-Pair-Id, and the matching RSA
        private key (.pem) at CLOUDFRONT_PRIVATE_KEY_PATH (kept off git, deployed
        out-of-band to the instance).
        """
        required = {
            "CLOUDFRONT_DOMAIN": config.CLOUDFRONT_DOMAIN,
            "CLOUDFRONT_KEY_PAIR_ID": config.CLOUDFRONT_KEY_PAIR_ID,
            "CLOUDFRONT_PRIVATE_KEY_PATH": config.CLOUDFRONT_PRIVATE_KEY_PATH,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ConfigurationError(
                "CONTENT_ACCESS_MODE=cloudfront-signed requires: "
                + ", ".join(missing)
                + "."
            )

        expires_at = self._expires_at()

        # Lazy imports so mock / s3-presigned modes don't require these libs.
        from botocore.signers import CloudFrontSigner
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )

        with open(config.CLOUDFRONT_PRIVATE_KEY_PATH, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        def rsa_signer(message: bytes) -> bytes:
            # CloudFront signed URLs require SHA-1 with RSA (PKCS#1 v1.5).
            return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

        signer = CloudFrontSigner(config.CLOUDFRONT_KEY_PAIR_ID, rsa_signer)
        resource_url = f"https://{config.CLOUDFRONT_DOMAIN}/{object_key}"
        signed_url = signer.generate_presigned_url(
            resource_url, date_less_than=expires_at
        )
        return AccessGrant(
            url=signed_url,
            expires_at=expires_at,
            mode="cloudfront-signed",
            object_key=object_key,
        )
