"""
EduStream — EC2 Gatekeeper (Member 2)

A Flask app that authenticates students and issues temporary, expiring access
URLs for protected course content. The URL generation itself is delegated to
ContentAccessService, which runs in "mock" mode by default (no AWS required)
and can later switch to real S3 Presigned or CloudFront Signed URLs simply by
changing CONTENT_ACCESS_MODE — no route/template changes needed.

Access flow:
  1. Student logs in (session cookie, role-aware).
  2. Student sees the resources their role is allowed to access.
  3. Student clicks "Open"; the browser calls GET /api/resources/<id>/access-url.
  4. Backend validates the session, that the resource exists, and that the
     user's role may access it.
  5. Backend returns a temporary URL + expiry timestamp (JSON).
  6. Browser opens/redirects to the temporary URL.

Layered for clean separation of concerns:
  - templates/         : UI
  - app.py (this file) : routing + auth/session
  - resources.py       : content metadata + access control
  - content_service.py : AWS integration / signed-URL abstraction
  - config.py          : environment-driven configuration

No AWS credentials are hardcoded anywhere. On EC2, boto3 resolves credentials
from the attached IAM Role.
"""

import functools
import time

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import config
import resources
import users
from content_service import (
    AccessGrantCache,
    ConfigurationError,
    ContentAccessService,
)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Users (registration + login) live in the `users` module, backed by an
# in-memory store (local/tests) or DynamoDB (production). Passwords are hashed,
# never stored in plaintext. Demo accounts admin/student are seeded there.

# Single shared service instance; mode is read from config (default "mock").
access_service = ContentAccessService()

# Caches active access URLs so repeat clicks reuse one URL until it expires.
grant_cache = AccessGrantCache()


def grant_for_resource(user, resource):
    """
    Return (grant, cached) for this user + resource.

    Reuses a still-valid cached grant (so within the 15-minute window every
    click yields the SAME URL); only mints — and caches — a new one once the
    previous grant has expired. Cache is per (username, resourceId).

    May raise ConfigurationError / NotImplementedError from the access service;
    callers handle those.
    """
    cache_key = f"{user['username']}:{resource['id']}"
    grant = grant_cache.get_valid(cache_key)
    if grant is not None:
        return grant, True
    grant = access_service.generate_access_url(
        resource["object_key"], base_url=request.host_url
    )
    grant_cache.put(cache_key, grant)
    return grant, False


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #

def current_user():
    """Return {'username', 'role'} for the logged-in user, or None."""
    username = session.get("username")
    if not username:
        return None
    return {"username": username, "role": session.get("role", "student")}


def is_authorized(username):
    """
    Whether this user is currently authorized to view content.

    Read live from the user store (not the session) so an admin revoking access
    takes effect immediately on the user's next request. Unknown users and
    users explicitly marked unauthorized return False.
    """
    record = users.get_user_store().get(username)
    return bool(record and record.get("authorized", False))


def login_required(view):
    """For HTML pages: redirect to /login when not authenticated."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def api_login_required(view):
    """For JSON APIs: return 401 JSON when not authenticated."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "authentication_required"}), 401
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """For admin pages: redirect anonymous users to login, others to /resources."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            return redirect(url_for("resources_page"))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------- #
# Routes — UI
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    """Send visitors straight to the login page."""
    return redirect(url_for("login"))


@app.route("/health")
def health():
    """ALB Target Group health check: 200 with a small JSON body."""
    return {"status": "ok"}, 200


@app.route("/login", methods=["GET", "POST"])
def login():
    """Render the login form (GET) or validate credentials (POST)."""
    if request.method == "POST":
        username = users.normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        user = users.get_user_store().get(username)
        if user and users.verify_password(user["password_hash"], password):
            session["username"] = username
            session["role"] = user.get("role", "student")
            return redirect(url_for("resources_page"))
        # Generic message — don't reveal whether the username exists.
        return render_template("login.html", error="Invalid username or password."), 401
    return render_template("login.html", error=None)


def _validate_registration(username, password, confirm):
    """Return an error string if the registration input is invalid, else None."""
    if not username or not password:
        return "Username and password are required."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if not username.replace("_", "").isalnum():
        return "Username may only contain letters, numbers, and underscores."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if password != confirm:
        return "Passwords do not match."
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    """Render the registration form (GET) or create a new student account (POST)."""
    if request.method == "POST":
        username = users.normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = _validate_registration(username, password, confirm)
        if error:
            return render_template("register.html", error=error, username=username), 400

        try:
            users.get_user_store().create(
                username, users.hash_password(password), role="student"
            )
        except users.UserExistsError:
            return (
                render_template(
                    "register.html",
                    error="That username is already taken.",
                    username=username,
                ),
                409,
            )

        # Auto-login the new user.
        session["username"] = username
        session["role"] = "student"
        return redirect(url_for("resources_page"))

    return render_template("register.html", error=None, username=None)


@app.route("/logout")
def logout():
    """Clear the session and return to the login page."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/resources")
@login_required
def resources_page():
    """Login-required: list resources the current role may access."""
    user = current_user()
    visible = resources.list_resources_for_role(user["role"])
    return render_template(
        "resources.html",
        resources=visible,
        user=user,
        authorized=is_authorized(user["username"]),
    )


@app.route("/videos")
def videos_alias():
    """Legacy alias — redirect to the canonical /resources route."""
    return redirect(url_for("resources_page"))


@app.route("/watch/<resource_id>")
@login_required
def watch(resource_id):
    """
    Server-side fallback (works without JavaScript): validate access and
    redirect straight to the temporary URL. Keyed by resource id — never by a
    raw object key — so arbitrary keys can't be requested.
    """
    user = current_user()
    if not is_authorized(user["username"]):
        return render_template("expired.html"), 403
    resource = resources.get_resource(resource_id)
    if resource is None:
        return render_template("expired.html"), 404
    if not resources.role_can_access(resource, user["role"]):
        return render_template("expired.html"), 403
    try:
        grant, _cached = grant_for_resource(user, resource)
    except (ConfigurationError, NotImplementedError):
        return render_template("expired.html"), 503
    return redirect(grant.url)


# --------------------------------------------------------------------------- #
# Routes — Admin (user authorization management)
# --------------------------------------------------------------------------- #

@app.route("/admin/users")
@admin_required
def admin_users():
    """
    Admin console: list all users with their authorization status, with an
    optional case-insensitive username search (?q=...). Each user can be
    authorized or revoked from here.
    """
    query = request.args.get("q", "").strip()
    user_list = users.get_user_store().list_users(search=query or None)
    return render_template(
        "admin_users.html",
        users=user_list,
        query=query,
        current=current_user(),
    )


@app.route("/admin/users/<username>/authorization", methods=["POST"])
@admin_required
def admin_set_authorization(username):
    """Authorize or revoke a single user, then return to the (filtered) list."""
    username = users.normalize_username(username)
    authorize = request.form.get("action") == "authorize"
    users.get_user_store().set_authorized(username, authorize)
    query = request.form.get("q", "").strip()
    return redirect(url_for("admin_users", q=query) if query else url_for("admin_users"))


# --------------------------------------------------------------------------- #
# Routes — JSON API (the canonical Gatekeeper access flow)
# --------------------------------------------------------------------------- #

@app.route("/api/resources/<resource_id>/access-url")
@api_login_required
def api_access_url(resource_id):
    """
    Validate session + resource + role, then return a temporary access URL and
    its expiry. The browser never sees the underlying object key/storage URL —
    only the (mock or signed) access URL produced by ContentAccessService.
    """
    user = current_user()
    # Account-level gate: only authorized students may obtain access URLs. New
    # self-registered users are unauthorized until an admin approves them.
    if not is_authorized(user["username"]):
        return jsonify({"error": "account_not_authorized"}), 403
    resource = resources.get_resource(resource_id)
    if resource is None:
        return jsonify({"error": "resource_not_found", "resourceId": resource_id}), 404
    if not resources.role_can_access(resource, user["role"]):
        return jsonify({"error": "access_denied", "resourceId": resource_id}), 403

    try:
        grant, cached = grant_for_resource(user, resource)
    except (ConfigurationError, NotImplementedError) as exc:
        # AWS mode selected but not ready/activated. Fail safe; don't leak
        # internal details to the client.
        app.logger.error("Access URL generation failed: %s", exc)
        return jsonify({"error": "access_url_unavailable"}), 503

    body = grant.to_dict()
    body.update(
        {
            "resourceId": resource_id,
            "title": resource["title"],
            "type": resource["type"],
            "cached": cached,
        }
    )
    return jsonify(body), 200


# --------------------------------------------------------------------------- #
# Mock content origin (only used while CONTENT_ACCESS_MODE=mock)
# --------------------------------------------------------------------------- #

@app.route("/mock-cdn/<path:object_key>")
def mock_cdn(object_key):
    """
    Stand-in for the future CloudFront/S3 origin while running in mock mode.
    Renders a clearly-marked placeholder instead of streaming real content, and
    honours the `expires` query param to demonstrate the 15-minute expiry.

    This route does NOT exist in production — CloudFront/S3 will serve content.
    """
    expires = request.args.get("expires", type=int)
    if expires is not None and expires < int(time.time()):
        return render_template("expired.html"), 410
    return render_template(
        "mock_cdn.html",
        object_key=object_key,
        token=request.args.get("token", ""),
        expires=expires,
    )


# --------------------------------------------------------------------------- #
# Local development entrypoint
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    # Bind to 0.0.0.0 so the app is reachable behind an ALB / from other hosts.
    # In production gunicorn runs the app (see userdata.sh); this block is only
    # for `python3 app.py` local testing.
    app.run(host="0.0.0.0", port=5000, debug=False)
