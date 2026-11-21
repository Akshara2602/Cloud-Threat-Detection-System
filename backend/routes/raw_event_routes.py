from flask import Blueprint, current_app, jsonify, request

from backend.models import SecurityEvent


raw_event_bp = Blueprint(
    "raw_events",
    __name__,
    url_prefix="/api/events"
)


def extract_event_fields(event):
    """
    Extract readable fields from both the database columns and the
    nested EventBridge / CloudTrail event_data JSON.
    """
    payload = event.event_data or {}

    if not isinstance(payload, dict):
        payload = {}

    detail = payload.get("detail") or {}

    if not isinstance(detail, dict):
        detail = {}

    identity = detail.get("userIdentity") or {}

    if isinstance(identity, dict):
        user_identity = (
            identity.get("arn")
            or identity.get("userName")
            or identity.get("principalId")
            or "Unknown"
        )
    else:
        user_identity = str(identity) if identity else "Unknown"

    source_ip = (
        event.source_ip
        or detail.get("sourceIPAddress")
        or "Unknown"
    )

    event_name = (
        event.event_name
        or detail.get("eventName")
        or payload.get("eventName")
        or "Unknown"
    )

    event_source = (
        event.event_source
        or detail.get("eventSource")
        or payload.get("source")
        or "Unknown"
    )

    region = (
        event.region
        or payload.get("region")
        or detail.get("awsRegion")
        or "Unknown"
    )

    resource_name = event.resource_name

    if not resource_name:
        request_parameters = detail.get("requestParameters") or {}

        if isinstance(request_parameters, dict):
            resource_keys = (
                "groupId",
                "userName",
                "roleName",
                "bucketName",
                "instanceId",
                "trailName",
                "policyArn"
            )

            for key in resource_keys:
                if request_parameters.get(key):
                    resource_name = str(request_parameters[key])
                    break

    if not resource_name:
        resources = detail.get("resources") or payload.get("resources") or []
        if isinstance(resources, list) and resources:
            first_resource = resources[0]
            if isinstance(first_resource, dict):
                resource_name = (
                    first_resource.get("ARN")
                    or first_resource.get("arn")
                    or first_resource.get("resourceName")
                )

    return {
        "id": event.id,
        "event_id": (
            event.event_id
            or payload.get("id")
            or "Unknown"
        ),
        "event_source": event_source,
        "event_name": event_name,
        "user_identity": (
            event.user_identity
            if event.user_identity and event.user_identity != "Unknown"
            else user_identity
        ),
        "source_ip": source_ip,
        "region": region,
        "resource_name": resource_name or "Not specified",
        "event_status": event.event_status or "UNKNOWN",
        "detail_type": payload.get("detail-type", "Unknown"),
        "cloudtrail_source": payload.get("source", "Unknown"),
        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),
        "event_data": payload
    }


@raw_event_bp.route("/", methods=["GET"])
def get_raw_events():
    """
    Return the latest raw security events stored in the database.

    Optional query parameter:
        limit: number of records to return (1 to 500; default 100)
    """
    try:
        limit = request.args.get("limit", default=100, type=int)

        if limit is None:
            limit = 100

        limit = max(1, min(limit, 500))

        query = SecurityEvent.query.order_by(
            SecurityEvent.created_at.desc()
        )

        total_events = query.count()
        events = query.limit(limit).all()

        results = [
            extract_event_fields(event)
            for event in events
        ]

        return jsonify({
            "total": total_events,
            "returned": len(results),
            "limit": limit,
            "events": results
        }), 200

    except Exception:
        current_app.logger.exception(
            "Failed to retrieve raw security events"
        )
        return jsonify({
            "error": "Unable to retrieve security events"
        }), 500
