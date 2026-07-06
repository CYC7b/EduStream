"""
EduStream — course resource metadata + access control.

Resources are described as metadata only. The frontend NEVER receives raw S3
object keys or storage URLs; it asks the backend Gatekeeper for a temporary
access URL by resource id. Object keys live here, server-side.

This is the demo catalogue (no database). Each entry maps a stable public id to
a private object key plus the roles allowed to access it.
"""

from typing import List, Optional

# Each resource:
#   id            : stable identifier used in URLs/API (safe to expose)
#   title         : human-readable display name
#   type          : "video" | "pdf"
#   object_key    : private S3 object key (NEVER sent to the browser directly)
#   allowed_roles : roles permitted to access this resource (least privilege)
#   description   : short blurb shown in the UI
RESOURCES = [
    {
        "id": "cloud-week1",
        "title": "Week 1 — Introduction to Cloud Computing",
        "type": "video",
        "object_key": "courses/cloud-computing/week1.mp4",
        "allowed_roles": ["student", "admin"],
        "description": "Cloud service models (IaaS/PaaS/SaaS) and deployment models.",
    },
    {
        "id": "cloud-week2",
        "title": "Week 2 — Networking & Security",
        "type": "video",
        "object_key": "courses/cloud-computing/week2.mp4",
        "allowed_roles": ["student", "admin"],
        "description": "VPCs, subnets, security groups, and the shared responsibility model.",
    },
]

_BY_ID = {resource["id"]: resource for resource in RESOURCES}


def list_resources_for_role(role: str) -> List[dict]:
    """Return the resources a given role is allowed to see (metadata only)."""
    return [r for r in RESOURCES if role in r["allowed_roles"]]


def get_resource(resource_id: str) -> Optional[dict]:
    """Return the resource dict for an id, or None if it does not exist."""
    return _BY_ID.get(resource_id)


def role_can_access(resource: Optional[dict], role: str) -> bool:
    """Authorize a role against a resource. False for unknown resources."""
    return bool(resource) and role in resource["allowed_roles"]
