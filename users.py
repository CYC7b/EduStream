"""
EduStream — user store + password hashing for the login / registration module.

Backends (CONFIG: USERS_BACKEND):
  - "memory"   : in-process dict, seeded with the demo accounts. Default for
                 local dev + tests (no AWS). Per-process, resets on restart —
                 NOT suitable for the multi-instance ASG deployment.
  - "dynamodb" : shared DynamoDB table (production / ASG). Consistent across all
                 instances behind the ALB and survives instance refresh.

Passwords are always stored **hashed** (werkzeug pbkdf2), never in plaintext.
"""

from __future__ import annotations

import time
from typing import List, Optional

from werkzeug.security import check_password_hash, generate_password_hash

import config

# Demo accounts seeded into the store. The password is hashed before storage;
# real users are added through /register. Seeded accounts are authorized so the
# admin can manage the system and the demo student can view content out of the box.
_SEED_USERS = [
    ("admin", "password123", "admin"),
    ("student", "password123", "student"),
]


def _normalize_authorized(user: Optional[dict]) -> Optional[dict]:
    """
    Ensure a user record has an explicit `authorized` flag.

    Users created via /register always store `authorized=False`; this only
    affects rows that predate the authorization feature. Per the project rule
    "existing users are authorized", a missing flag is treated as authorized.
    """
    if user is not None:
        user.setdefault("authorized", True)
    return user


class UserExistsError(Exception):
    """Raised when creating a user whose username already exists."""


def hash_password(password: str) -> str:
    # Pin the algorithm so hashes are portable across werkzeug versions: a newer
    # werkzeug (e.g. in CloudShell when seeding) defaults to scrypt, which the
    # pinned werkzeug 2.2.3 on the instances cannot verify. pbkdf2:sha256 is
    # supported by every werkzeug version.
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(password_hash: str, password: str) -> bool:
    return check_password_hash(password_hash, password)


def normalize_username(username: str) -> str:
    """Usernames are case-insensitive and trimmed."""
    return username.strip().lower()


class InMemoryUserStore:
    """Process-local user store, seeded with the demo accounts."""

    def __init__(self, seed: bool = True):
        self._users: dict[str, dict] = {}
        if seed:
            for username, password, role in _SEED_USERS:
                self._users[username] = {
                    "username": username,
                    "password_hash": hash_password(password),
                    "role": role,
                    "authorized": True,  # seeded/existing users are authorized
                }

    def get(self, username: str) -> Optional[dict]:
        return _normalize_authorized(self._users.get(username))

    def create(
        self, username: str, password_hash: str, role: str, authorized: bool = False
    ) -> None:
        if username in self._users:
            raise UserExistsError(username)
        self._users[username] = {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            # New self-registered users start UNauthorized by default; an admin
            # must approve them before they can view content.
            "authorized": bool(authorized),
        }

    def set_authorized(self, username: str, authorized: bool) -> bool:
        """Set a user's authorization flag. Returns False if no such user."""
        user = self._users.get(username)
        if user is None:
            return False
        user["authorized"] = bool(authorized)
        return True

    def list_users(self, search: Optional[str] = None) -> List[dict]:
        """All users (optionally filtered by a case-insensitive username substring)."""
        users = [_normalize_authorized(u) for u in self._users.values()]
        if search:
            needle = search.strip().lower()
            users = [u for u in users if needle in u["username"].lower()]
        return sorted(users, key=lambda u: u["username"])


class DynamoDBUserStore:
    """Shared user store backed by a DynamoDB table (partition key: username)."""

    def __init__(self, table_name: str, region: str):
        import boto3  # lazy: the memory backend doesn't need boto3

        self._table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    def get(self, username: str) -> Optional[dict]:
        return _normalize_authorized(
            self._table.get_item(Key={"username": username}).get("Item")
        )

    def create(
        self, username: str, password_hash: str, role: str, authorized: bool = False
    ) -> None:
        from botocore.exceptions import ClientError

        try:
            # ConditionExpression makes "create" atomic — fails if the username
            # already exists, so concurrent signups can't clobber each other.
            self._table.put_item(
                Item={
                    "username": username,
                    "password_hash": password_hash,
                    "role": role,
                    # New self-registered users start UNauthorized by default.
                    "authorized": bool(authorized),
                    "created_at": int(time.time()),
                },
                ConditionExpression="attribute_not_exists(username)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise UserExistsError(username)
            raise

    def set_authorized(self, username: str, authorized: bool) -> bool:
        """Set a user's authorization flag. Returns False if no such user."""
        from botocore.exceptions import ClientError

        try:
            # `authorized` is referenced via an alias to avoid any reserved-word
            # clash; the condition makes this a no-op (False) for unknown users.
            self._table.update_item(
                Key={"username": username},
                UpdateExpression="SET #auth = :a",
                ExpressionAttributeNames={"#auth": "authorized"},
                ExpressionAttributeValues={":a": bool(authorized)},
                ConditionExpression="attribute_exists(username)",
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def list_users(self, search: Optional[str] = None) -> List[dict]:
        """All users (optionally filtered by a case-insensitive username substring)."""
        items: List[dict] = []
        scan_kwargs: dict = {}
        while True:
            resp = self._table.scan(**scan_kwargs)
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" not in resp:
                break
            scan_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

        users = [_normalize_authorized(u) for u in items]
        if search:
            needle = search.strip().lower()
            users = [u for u in users if needle in u["username"].lower()]
        return sorted(users, key=lambda u: u["username"])


_store = None


def get_user_store():
    """Return the configured user store (singleton)."""
    global _store
    if _store is None:
        if config.USERS_BACKEND == "dynamodb":
            _store = DynamoDBUserStore(config.USERS_TABLE_NAME, config.AWS_REGION)
        else:
            _store = InMemoryUserStore()
    return _store


def set_user_store(store) -> None:
    """Override the active store (used by tests)."""
    global _store
    _store = store
