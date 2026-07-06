# EduStream — CloudFront + OAI Setup Runbook

Turns on the required production delivery path: **CloudFront (global CDN) →
Origin Access Identity (OAI) → private S3**, with the EC2 Gatekeeper minting
**CloudFront Signed URLs** (15-min) and **access logs to a separate bucket**.

> ⛔ **Requires a CloudFront-permitted AWS account.** The AWS Academy Learner Lab
> (`voclabs`) used for Group 3 **denies all `cloudfront:*` actions** (confirmed:
> `aws cloudfront list-distributions` → AccessDenied) and IAM is locked, so these
> steps **cannot run in that lab**. The live lab deployment therefore uses
> `s3-presigned`; follow this runbook in an account where CloudFront is allowed.
> See `../GAP_ANALYSIS.md` §4.

This runbook assumes the **buckets already exist** (so we do NOT recreate them):

- Content: `s3://edustream-video-vault-group3` (Block Public Access ON)
- Logs:    `s3://edustream-vault-logs-group3`
- Region:  `us-east-1`

> The app code (`content_service.py` `cloudfront-signed` mode) is already
> implemented. This runbook is the AWS side + wiring it to the ASG.
> `cloudfront-s3-oai.yaml` is a *from-scratch* CloudFormation reference (it
> **creates** buckets, so it would clash with your existing ones — follow the
> steps below instead, which reuse them).

---

## 1. Generate the signing key pair (offline; keep the private key secret)

```bash
openssl genrsa -out cloudfront_private_key.pem 2048      # SECRET — never commit
openssl rsa -pubout -in cloudfront_private_key.pem -out cloudfront_public_key.pem
```

## 2. Store the private key in SSM Parameter Store (SecureString)

Each ASG instance fetches it at boot (see `userdata.sh` step 5b) — no key in git
or the code bucket.

```bash
aws ssm put-parameter \
  --region us-east-1 \
  --name /edustream/cloudfront_private_key \
  --type SecureString \
  --value file://cloudfront_private_key.pem
```

## 3. Create a CloudFront public key + key group (Console is easiest)

CloudFront console → **Key management → Public keys → Create public key**:
- Name: `edustream-signing-key`
- Key: paste the contents of `cloudfront_public_key.pem`
- **Save the Public key ID** it returns — this is your `CLOUDFRONT_KEY_PAIR_ID` (`K...`).

Then **Key management → Key groups → Create key group**: name it
`edustream-key-group`, add the public key above.

## 4. Create the distribution with OAI (Console)

CloudFront → **Create distribution**:
- **Origin domain:** `edustream-video-vault-group3.s3.us-east-1.amazonaws.com`
- **Origin access:** choose **Legacy access identities → Origin access identity →
  Create new OAI**, and **"Yes, update the bucket policy"**.
  (The console writes the OAI read grant into the bucket policy for you; Block
  Public Access stays ON because the OAI principal is not public.)
- **Viewer → Restrict viewer access:** **Yes** → Trusted authorization type:
  **Trusted key groups** → select `edustream-key-group`.
- **Viewer protocol policy:** Redirect HTTP to HTTPS.
- **Allowed methods:** GET, HEAD.
- **Price class:** Use all edge locations (best performance) → **global**.
- **Standard logging:** On → S3 bucket `edustream-vault-logs-group3`, log prefix
  `cloudfront-access-logs/`.
- Create, then wait until **Status = Deployed** (~5–15 min). **Note the
  Distribution domain name** (`dXXXX.cloudfront.net`) → this is `CLOUDFRONT_DOMAIN`.

### If logging fails to enable (log bucket ACLs)
CloudFront *standard* logging needs ACLs enabled on the log bucket. If you get an
ownership/ACL error: S3 → `edustream-vault-logs-group3` → **Permissions → Object
Ownership → Edit → ACLs enabled → Bucket owner preferred → Save**, then re-enable
logging. (Public Access Block can stay ON.)

## 5. Point the Gatekeeper at CloudFront

Edit `userdata.sh` and set:

```bash
CONTENT_ACCESS_MODE="cloudfront-signed"
CLOUDFRONT_DOMAIN="dXXXX.cloudfront.net"      # from step 4
CLOUDFRONT_KEY_PAIR_ID="KXXXXXXXXXXXXX"       # from step 3
# CLOUDFRONT_PRIVATE_KEY_PATH / _SSM_PARAM and CLOUDFRONT_LOG_BUCKET_NAME are
# already set; step 5b in userdata.sh fetches the key from SSM at boot.
```

Re-upload the code (so the bucket has the latest `userdata.sh` etc.), then roll
it out with a **new launch-template version + instance refresh** (same as before):

```bash
aws s3 cp ./ s3://edustream-code-group3/edustream-ec2/ --recursive   # from edustream-ec2/

aws ec2 create-launch-template-version \
  --launch-template-id lt-086be2246e87cb989 --source-version '$Latest' \
  --version-description "cloudfront-signed" \
  --launch-template-data "{\"UserData\":\"$(base64 -w0 userdata.sh)\"}"
# note the new VersionNumber, then:
aws ec2 modify-launch-template --launch-template-id lt-086be2246e87cb989 --default-version <N>

aws autoscaling start-instance-refresh \
  --auto-scaling-group-name <your-asg-name> \
  --preferences '{"MinHealthyPercentage":50,"InstanceWarmup":60}'
```

> IAM (Learner Lab): the instance role (`LabInstanceProfile`/`LabRole`) needs
> `ssm:GetParameter` + `kms:Decrypt` (for the SecureString) and `s3:GetObject`
> on the code bucket. LabRole is usually broad enough; if step 5b fails, that's
> the thing to check (`journalctl -u edustream.service` / cloud-init logs).

## 6. Verify

After the refresh, against the **ALB DNS**: log in → click **Open**. Expect:

- `mode: cloudfront-signed` and a URL like
  `https://dXXXX.cloudfront.net/courses/cloud-computing/week1.mp4?Expires=...&Signature=...&Key-Pair-Id=KXXXX` — and the **video plays** (served from the CDN edge).
- The **plain** S3 object URL (no signature) returns **403** — content is private.
- After a few minutes, log files appear under
  `s3://edustream-vault-logs-group3/cloudfront-access-logs/`.

---

## How this maps to the requirements

| Requirement | Realized by |
|---|---|
| S3 — all public access blocked | existing bucket keeps Block Public Access ON; only the OAI bucket policy grants read |
| CloudFront distribution with **OAI** | step 4 (legacy OAI + auto bucket-policy update) |
| Global low-latency CDN | distribution PriceClass = all edge locations, HTTPS |
| EC2 generates 15-min Signed URLs | `content_service.py._cloudfront_signed_url` + the key group (step 3) |
| Access logs to a **separate** bucket | step 4 standard logging → `edustream-vault-logs-group3` |

## Notes
- Moving to `cloudfront-signed` also sidesteps the S3 SigV2/SigV4 quirk — the
  CloudFront signed URL uses its own RSA `Key-Pair-Id`/`Signature`/`Expires`.
- To roll back to the working `s3-presigned` path, set
  `CONTENT_ACCESS_MODE="s3-presigned"` and repeat the launch-template + refresh.
- Never commit `cloudfront_private_key.pem` (`.gitignore` excludes `*.pem`).
