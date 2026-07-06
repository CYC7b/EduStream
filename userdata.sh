#!/bin/bash
###############################################################################
# EduStream — EC2 User Data Script (Amazon Linux 2)
#
# Runs once at instance launch. Installs dependencies, pulls the app code from
# S3, configures environment variables, and starts the Flask app via gunicorn
# behind a systemd service (so it auto-restarts on reboot/crash).
#
# Logs from this script land in /var/log/cloud-init-output.log on the instance.
###############################################################################

set -xe

# --------------------------------------------------------------------------- #
# 1. Update the system
# --------------------------------------------------------------------------- #
yum update -y

# --------------------------------------------------------------------------- #
# 2. Install Python 3, pip, git, and the AWS CLI (CLI ships on AL2 already)
# --------------------------------------------------------------------------- #
yum install -y python3 python3-pip git

# --------------------------------------------------------------------------- #
# 3. Copy the application code from S3
#    Pulls from s3://edustream-code-group3/edustream-ec2/. The IAM Role attached
#    to this instance must allow s3:GetObject (and s3:ListBucket) on that bucket.
# --------------------------------------------------------------------------- #
APP_DIR="/opt/edustream"
mkdir -p "${APP_DIR}"

aws s3 cp s3://edustream-code-group3/edustream-ec2/ "${APP_DIR}/" --recursive

# --------------------------------------------------------------------------- #
# 4. Install Python dependencies
#    Prefer requirements.txt if it was copied down; otherwise install directly.
# --------------------------------------------------------------------------- #
if [ -f "${APP_DIR}/requirements.txt" ]; then
  pip3 install -r "${APP_DIR}/requirements.txt"
else
  pip3 install flask boto3 gunicorn
fi

# --------------------------------------------------------------------------- #
# 5. Environment variables
#    >>> REPLACE the placeholder values below with your real configuration. <<<
#    Do NOT put AWS access keys here — the instance IAM Role handles auth.
# --------------------------------------------------------------------------- #

# How temporary access URLs are generated:
#   cloudfront-signed -> through CloudFront (CDN) + OAI  ← REQUIRED final mode
#   s3-presigned      -> direct from S3 (bypasses the CDN; allowed fallback)
# Set to "cloudfront-signed" once the CloudFront stack (infra/cloudfront-s3-oai.yaml)
# is deployed and the CLOUDFRONT_* values below are filled in. Until then,
# "s3-presigned" keeps the app serving content directly from S3.
CONTENT_ACCESS_MODE="s3-presigned"

# Private bucket that stores course content (S3 Block Public Access = ON).
# Requires the instance IAM Role to allow s3:GetObject on it, in AWS_REGION.
CONTENT_BUCKET_NAME="edustream-video-vault-group3"

# Temporary URL lifetime: 900 seconds = 15 minutes (project requirement).
SIGNED_URL_EXPIRY_SECONDS="900"

# --- CloudFront (fill in from the CloudFormation stack outputs) -------------
# Required when CONTENT_ACCESS_MODE=cloudfront-signed.
CLOUDFRONT_DOMAIN=""                              # e.g. d1234abcd.cloudfront.net
CLOUDFRONT_KEY_PAIR_ID=""                         # CloudFront public key ID (Kxxxx)
# RSA private key (.pem) for signing. Stored encrypted in SSM Parameter Store
# (SecureString) and fetched at boot by step 5b below — NEVER baked into the
# code bucket or git. Local path it's written to, and the SSM parameter name:
CLOUDFRONT_PRIVATE_KEY_PATH="/etc/edustream/cloudfront_private_key.pem"
CLOUDFRONT_PRIVATE_KEY_SSM_PARAM="/edustream/cloudfront_private_key"
# Separate bucket that receives CloudFront access logs (audit trail).
CLOUDFRONT_LOG_BUCKET_NAME="edustream-vault-logs-group3"   # CloudFront access-log bucket (audit)

# --- Users / auth ----------------------------------------------------------
# Registered users live in DynamoDB so all ASG instances share them and they
# survive instance refresh. Run scripts/init_users_table.py ONCE (e.g. from
# CloudShell) to create the table + seed the demo accounts. The instance role
# needs dynamodb GetItem/PutItem on this table.
USERS_BACKEND="dynamodb"
USERS_TABLE_NAME="edustream-users-group3"

# Flask session signing key. Fixed value so sessions survive reboots/redeploys.
# (We run a single gunicorn worker, -w 1, so the in-memory access-URL reuse
# cache is consistent — repeat clicks return the same URL within 15 min.)
# Regenerate with:  python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY="7103050ecb012c16ab1ad0c367e7aedd780af5dcc0d3ecf603ee879ea2dfcdf0"
AWS_REGION="us-east-1"                            # must match the bucket's region

# --------------------------------------------------------------------------- #
# 5b. CloudFront signing key — fetch from SSM Parameter Store (SecureString).
#     Only runs in cloudfront-signed mode. Needs the instance role to allow
#     ssm:GetParameter (+ kms:Decrypt for the SecureString's KMS key).
# --------------------------------------------------------------------------- #
if [ "${CONTENT_ACCESS_MODE}" = "cloudfront-signed" ]; then
  mkdir -p "$(dirname "${CLOUDFRONT_PRIVATE_KEY_PATH}")"
  aws ssm get-parameter \
      --name "${CLOUDFRONT_PRIVATE_KEY_SSM_PARAM}" \
      --with-decryption --region "${AWS_REGION}" \
      --query Parameter.Value --output text > "${CLOUDFRONT_PRIVATE_KEY_PATH}"
  chmod 600 "${CLOUDFRONT_PRIVATE_KEY_PATH}"
  chown ec2-user:ec2-user "${CLOUDFRONT_PRIVATE_KEY_PATH}"
fi

# --------------------------------------------------------------------------- #
# 6 & 7. Create a systemd service so gunicorn starts on boot and restarts on
#        failure. Binds to 0.0.0.0:5000 so the ALB can reach it.
# --------------------------------------------------------------------------- #
cat > /etc/systemd/system/edustream.service <<EOF
[Unit]
Description=EduStream Gatekeeper (gunicorn)
After=network.target

[Service]
User=ec2-user
WorkingDirectory=${APP_DIR}
Environment="CONTENT_ACCESS_MODE=${CONTENT_ACCESS_MODE}"
Environment="CONTENT_BUCKET_NAME=${CONTENT_BUCKET_NAME}"
Environment="SIGNED_URL_EXPIRY_SECONDS=${SIGNED_URL_EXPIRY_SECONDS}"
Environment="CLOUDFRONT_DOMAIN=${CLOUDFRONT_DOMAIN}"
Environment="CLOUDFRONT_KEY_PAIR_ID=${CLOUDFRONT_KEY_PAIR_ID}"
Environment="CLOUDFRONT_PRIVATE_KEY_PATH=${CLOUDFRONT_PRIVATE_KEY_PATH}"
Environment="CLOUDFRONT_LOG_BUCKET_NAME=${CLOUDFRONT_LOG_BUCKET_NAME}"
Environment="USERS_BACKEND=${USERS_BACKEND}"
Environment="USERS_TABLE_NAME=${USERS_TABLE_NAME}"
Environment="SECRET_KEY=${SECRET_KEY}"
Environment="AWS_REGION=${AWS_REGION}"
ExecStart=/usr/local/bin/gunicorn -w 1 -b 0.0.0.0:5000 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Make sure ec2-user owns the app directory.
chown -R ec2-user:ec2-user "${APP_DIR}"

# Enable + start the service.
systemctl daemon-reload
systemctl enable edustream.service
systemctl start edustream.service

# --------------------------------------------------------------------------- #
# NOTE: gunicorn install path can vary (/usr/local/bin or /usr/bin). If the
# service fails to start, check `which gunicorn` and update ExecStart above.
# Troubleshoot with:  journalctl -u edustream.service -n 50 --no-pager
# --------------------------------------------------------------------------- #
