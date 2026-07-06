"""
EduStream — centralized configuration.

All runtime configuration comes from environment variables so that NO secrets
or environment-specific values are hardcoded in source. See `.env.example` for
the complete list and safe placeholder values.

Nothing in this module provisions or contacts AWS; it only *reads* config. The
actual AWS calls live in `content_service.py` and only run when the matching
CONTENT_ACCESS_MODE is selected AND the required variables are provided.
"""

import os


def _get_int(name: str, default: int) -> int:
    """Read an int env var, falling back to `default` if unset/invalid."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# --- Flask ------------------------------------------------------------------
# Session signing key. A random fallback keeps local dev working, but it MUST
# be set explicitly in any real deployment (see README / .env.example), or
# sessions break across gunicorn workers and reboots.
SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32)

# --- AWS / region -----------------------------------------------------------
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# --- Private content storage (S3) -------------------------------------------
# Bucket that will eventually hold course videos/PDFs (private). Empty until
# the bucket is provisioned (DEFERRED). `S3_BUCKET_NAME` is accepted as a
# legacy alias so older user-data scripts keep working.
CONTENT_BUCKET_NAME = (
    os.environ.get("CONTENT_BUCKET_NAME")
    or os.environ.get("S3_BUCKET_NAME")
    or ""
)

# --- CloudFront (DEFERRED infrastructure) -----------------------------------
CLOUDFRONT_DOMAIN = os.environ.get("CLOUDFRONT_DOMAIN", "")
CLOUDFRONT_KEY_PAIR_ID = os.environ.get("CLOUDFRONT_KEY_PAIR_ID", "")
# Filesystem path to the CloudFront private key (.pem). NEVER commit this file.
CLOUDFRONT_PRIVATE_KEY_PATH = os.environ.get("CLOUDFRONT_PRIVATE_KEY_PATH", "")
# Separate bucket for CloudFront access logs / audit trail (DEFERRED).
CLOUDFRONT_LOG_BUCKET_NAME = os.environ.get("CLOUDFRONT_LOG_BUCKET_NAME", "")

# --- Temporary access URL behaviour -----------------------------------------
# How temporary access URLs are generated:
#   "mock"              -> clearly-fake local placeholder URL (default; no AWS)
#   "s3-presigned"      -> real S3 Presigned URL (needs CONTENT_BUCKET_NAME)
#   "cloudfront-signed" -> real CloudFront Signed URL (needs CLOUDFRONT_* vars)
CONTENT_ACCESS_MODE = os.environ.get("CONTENT_ACCESS_MODE", "mock").strip().lower()

# Temporary URL lifetime. 900 seconds = 15 minutes (EduStream requirement).
SIGNED_URL_EXPIRY_SECONDS = _get_int("SIGNED_URL_EXPIRY_SECONDS", 900)

VALID_ACCESS_MODES = ("mock", "s3-presigned", "cloudfront-signed")

# --- Users / auth -----------------------------------------------------------
# Where registered users live:
#   "memory"   -> in-process, seeded with demo accounts (default; local dev +
#                 tests, no AWS). Per-process and resets on restart — NOT for
#                 the multi-instance ASG deployment.
#   "dynamodb" -> shared DynamoDB table (production / ASG; set in userdata.sh).
USERS_BACKEND = os.environ.get("USERS_BACKEND", "memory").strip().lower()
USERS_TABLE_NAME = os.environ.get("USERS_TABLE_NAME", "edustream-users-group3")
