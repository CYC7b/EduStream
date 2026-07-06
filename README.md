# EduStream — EC2 Gatekeeper

**Secure Educational Content Delivery**

The EC2 component of EduStream. A Flask "Gatekeeper" web app that authenticates
students and issues **temporary, expiring access URLs** (15 minutes) for
protected course content. Content is never exposed publicly: the browser
receives only a time-limited access URL produced server-side.

> **Status.** All three URL strategies are implemented — `mock` (local, no AWS),
> `s3-presigned` (direct from S3), and `cloudfront-signed` (through the CloudFront
> CDN via OAI, the required production path). The mode is one env var
> (`CONTENT_ACCESS_MODE`). The AWS infrastructure (private S3, CloudFront + OAI,
> signed-URL key group, access logging) is provided as CloudFormation in
> [`infra/`](infra/) — review/deploy it, then set `CONTENT_ACCESS_MODE=cloudfront-signed`.
> See [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md), [`API_CONTRACT.md`](API_CONTRACT.md),
> and [`ARCHITECTURE_NOTES.md`](ARCHITECTURE_NOTES.md).

---

## File structure

```
edustream-ec2/
├── app.py               # Flask app: routing + auth/session + API
├── config.py            # All configuration, read from environment variables
├── content_service.py   # ContentAccessService: mock / s3-presigned / cloudfront-signed
├── users.py             # User store (in-memory / DynamoDB) + password hashing
├── resources.py         # Course resource metadata + role-based access control
├── requirements.txt     # Runtime deps (flask, werkzeug, boto3, gunicorn, cryptography)
├── requirements-dev.txt # Test deps (pytest)
├── userdata.sh          # EC2 launch script (systemd-managed gunicorn)
├── infra/               # CloudFormation: private S3 + CloudFront(OAI) + logs + runbook
├── scripts/             # init_users_table.py — create+seed the DynamoDB users table
├── .env.example         # Sample env config (copy to .env; never commit .env)
├── .gitignore           # Ignores .env, *.pem/*.key, build outputs, caches
├── README.md            # This file
├── API_CONTRACT.md      # API contract: endpoints, schemas, AWS integration points
├── ARCHITECTURE_NOTES.md# Intended final AWS architecture
├── GAP_ANALYSIS.md      # Requirement-by-requirement gap analysis
├── templates/
│   ├── login.html       # Login form
│   ├── register.html    # Registration form
│   ├── resources.html   # Resource list + JS that calls the access-url API
│   ├── mock_cdn.html    # Mock content origin placeholder (mock mode only)
│   └── expired.html     # Invalid key / denied / expired link page
└── tests/
    └── test_app.py      # pytest suite (runs in mock mode, Flask only)
```

---

## Routes

| Method | Path                                  | Auth | Purpose                                            |
|--------|---------------------------------------|------|----------------------------------------------------|
| GET    | `/`                                   | no   | Redirect to `/login`                               |
| GET    | `/health`                             | no   | ALB health check → `200 {"status": "ok"}`          |
| GET    | `/login`                              | no   | Render login form                                  |
| POST   | `/login`                              | no   | Validate credentials (hashed), set session, → `/resources` |
| GET    | `/register`                           | no   | Render registration form                           |
| POST   | `/register`                           | no   | Create a student account, auto-login, → `/resources` |
| GET    | `/logout`                             | yes  | Clear session                                      |
| GET    | `/resources`                          | yes  | List resources the current role may access         |
| GET    | `/videos`                             | —    | Legacy alias → redirects to `/resources`           |
| GET    | `/admin/users`                        | admin| User-admin console: list/search users, set authz   |
| POST   | `/admin/users/<username>/authorization`| admin| Authorize/revoke a user (`action=authorize\|revoke`)|
| GET    | `/api/resources/<id>/access-url`      | yes  | **JSON**: validate + return `{url, expiresAt, ...}` (requires an **authorized** account) |
| GET    | `/watch/<id>`                         | yes  | No-JS fallback: validate + redirect to temp URL    |
| GET    | `/mock-cdn/<key>`                     | no\* | Mock content origin placeholder (mock mode only)   |

\* `/mock-cdn` only exists to make mock mode demonstrable; it serves no real
content and disappears in production (CloudFront/S3 serve content instead).

**Accounts.** Users register at `/register` (creates a `student` account) and
log in at `/login`. Passwords are stored **hashed** (werkzeug pbkdf2). The store
is in-memory locally (`USERS_BACKEND=memory`, seeded with the accounts below) or
a shared **DynamoDB** table in production (`USERS_BACKEND=dynamodb`). Seeded demo
accounts:

| Username  | Password      | Role    | Authorized? | Can access                       |
|-----------|---------------|---------|-------------|----------------------------------|
| `student` | `password123` | student | yes         | The two course videos            |
| `admin`   | `password123` | admin   | yes         | Courses + the user-admin console |

**Authorization (only approved students may view content).** Every account has
an `authorized` flag. **New self-registered users start UNauthorized** — they can
log in and browse the catalogue but cannot open any content (the access-URL API
returns `403 account_not_authorized`) until an admin approves them. The seeded
accounts above are authorized. Admins manage this at **`/admin/users`** (linked
from the course page header): a searchable user list where each account can be
**Authorize**d or **Revoke**d. Revocation takes effect on the user's next
request (the flag is read live from the user store, not the session).

---

## Environment variables

All configuration is environment-driven (see [`.env.example`](.env.example)).
**No AWS access keys** — boto3 uses the EC2 instance's IAM Role.

| Variable                      | Required | Default          | Description                                              |
|-------------------------------|----------|------------------|----------------------------------------------------------|
| `SECRET_KEY`                  | yes\*    | random per-boot  | Flask session signing key                                |
| `CONTENT_ACCESS_MODE`         | no       | `mock`           | `mock` \| `s3-presigned` \| `cloudfront-signed`          |
| `SIGNED_URL_EXPIRY_SECONDS`   | no       | `900`            | Temp URL lifetime (900 = 15 min)                         |
| `USERS_BACKEND`               | no       | `memory`         | `memory` (local/tests) \| `dynamodb` (production)        |
| `USERS_TABLE_NAME`            | no       | `edustream-users` | DynamoDB users table (when `USERS_BACKEND=dynamodb`) |
| `AWS_REGION`                  | no       | `us-east-1`      | AWS region for the S3/CloudFront/DynamoDB clients        |
| `CONTENT_BUCKET_NAME`         | deferred | `""`             | Private content bucket (needed for `s3-presigned`)       |
| `CLOUDFRONT_DOMAIN`           | deferred | `""`             | CloudFront distribution domain                           |
| `CLOUDFRONT_KEY_PAIR_ID`      | deferred | `""`             | CloudFront trusted key-pair / key-group id               |
| `CLOUDFRONT_PRIVATE_KEY_PATH` | deferred | `""`             | Path to CloudFront private key `.pem` (never committed)  |
| `CLOUDFRONT_LOG_BUCKET_NAME`  | deferred | `""`             | Separate bucket for CloudFront access logs (audit)       |

\* If unset, a random key is generated at boot so the app still runs, but
sessions won't survive a restart or be shared across gunicorn workers. **Always
set it in any real deployment.** `S3_BUCKET_NAME` is still accepted as a legacy
alias for `CONTENT_BUCKET_NAME`.

---

## Running the prototype locally

```bash
cd edustream-ec2
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt

# Configure (mock mode needs no AWS at all)
cp .env.example .env          # then edit if you like
export CONTENT_ACCESS_MODE=mock
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# Run it
python3 app.py                # dev server on http://localhost:5000
# ...or the way production runs it:
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```

> **Note on the access-URL reuse cache:** it lives in worker memory. With
> `gunicorn -w 2`, a user's repeat clicks can hit different workers and see
> different URLs. For strict "one URL per resource per 15 min" behaviour, run
> `gunicorn -w 1` for the demo (or back the cache with Redis/DynamoDB later).
> Local `python app.py` is a single process and already behaves correctly.

Then open <http://localhost:5000>, log in as `student` / `password123`, and
click **Open** on a resource.

### Current mock-mode behaviour

- `/api/resources/<id>/access-url` returns a **clearly-fake** URL pointing at
  this app's `/mock-cdn/...` route (host `mock-cdn.edustream.local` if no host
  is known), with a `token` and an `expires` epoch.
- Opening that URL shows a "MOCK CONTENT ORIGIN — placeholder, not real content"
  page. If `expires` is in the past, it returns **410 Gone**, demonstrating the
  15-minute expiry.
- **Repeat clicks reuse the same link.** Within the 15-minute window, asking for
  the same resource again returns the *same* URL (response shows `cached: true`)
  rather than minting a new one; after it expires, the next click mints a fresh
  one. This holds in all modes, not just mock.
- No bucket, no CloudFront, no AWS credentials are touched.

### The AWS modes

Set `CONTENT_ACCESS_MODE` to switch the URL generator with **no code changes**:

- **`s3-presigned`** — requires `CONTENT_BUCKET_NAME`. `content_service.py`
  calls boto3 `generate_presigned_url("get_object", ..., ExpiresIn=900)`. Serves
  content **directly from S3** (bypasses the CDN). Implemented.
- **`cloudfront-signed`** *(required production path — CDN + OAI)* — requires
  `CLOUDFRONT_DOMAIN`, `CLOUDFRONT_KEY_PAIR_ID`, `CLOUDFRONT_PRIVATE_KEY_PATH`.
  `content_service.py` signs the URL with `botocore.signers.CloudFrontSigner`
  (RSA-SHA1 via `cryptography`), so content is delivered globally through
  CloudFront while S3 stays private behind an OAI. Implemented; needs the
  CloudFront stack from [`infra/`](infra/) deployed and the key pair in place.

If a mode is selected before its config exists, the API fails safe with
`503 access_url_unavailable` rather than crashing.

### Where the 15-minute expiry lives

A single config value: `SIGNED_URL_EXPIRY_SECONDS` (default `900`) in
`config.py`, used by `ContentAccessService` for every mode. Change the env var
to adjust it everywhere.

---

## Running the tests

```bash
cd edustream-ec2
pip3 install -r requirements.txt -r requirements-dev.txt
pytest -q
```

The suite (mock mode, Flask only — no AWS) covers:

- unauthenticated users **cannot** request an access URL (401);
- authenticated **and authorized** users **can**, and the response contains
  `url` + `expiresAt`;
- a **newly registered user is unauthorized** by default → `403
  account_not_authorized`; after an admin authorizes them they get `200`;
- an admin can **revoke** a user (immediate effect) and **search** users;
- **non-admins cannot** reach the admin console or change authorization;
- expiry defaults to **900** seconds;
- invalid resource id → 404;
- the role-based `role_can_access` logic enforces allowed roles (unit-tested);
- the mock URL is not a real S3 URL, and templates contain no direct S3 URLs.

### Manual demo checklist

1. Visit `/resources` while logged out → redirected to `/login`.
2. Log in with bad credentials → 401, error shown.
3. Log in as `student` → see the 2 course videos.
4. Click **Open** → a temporary URL + expiry appears and opens in a new tab.
5. Request an unknown resource (e.g.
   `curl -b cookies http://localhost:5000/api/resources/no-such-id/access-url`)
   → `404 resource_not_found`.
6. **Register a new account** → you land on `/resources` with a "pending
   authorization" banner; clicking **Open** fails (`403 account_not_authorized`).
7. **Log in as `admin` → Manage users** (header link) → search the new
   username → **Authorize**. Log back in as that user → **Open** now works.

---

## What needs to be done before deploying to EC2

1. **Set `SECRET_KEY`** to a fixed random value (already templated in `userdata.sh`).
2. Upload the app files to the **code bucket** (`s3://edustream-code/edustream-ec2/`,
   pre-filled in `userdata.sh`).
3. `CONTENT_ACCESS_MODE=s3-presigned` with `CONTENT_BUCKET_NAME=edustream-video-vault`
   is the current setting (serves direct from S3). To meet the CloudFront + OAI
   requirement, deploy `infra/` and switch to `cloudfront-signed` (see `infra/README.md`).
4. Attach an **IAM Role** to the instance with least-privilege `s3:GetObject`
   on the content bucket (and the code bucket for the deploy copy).
5. Point the **ALB Target Group health check** at `GET /health`.
6. Roll the update to the fleet via **Launch Template update + ASG Instance Refresh**
   (uploading to S3 alone does not update running instances).

See [`API_CONTRACT.md`](API_CONTRACT.md) for the full endpoint/response contract
and AWS integration points, [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md) for the
P0/P1/P2/Deferred breakdown, and [`ARCHITECTURE_NOTES.md`](ARCHITECTURE_NOTES.md)
for the intended final AWS architecture.
