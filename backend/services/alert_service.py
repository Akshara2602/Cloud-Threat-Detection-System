
from backend.database import db
from backend.models import Alert, SecurityEvent

from datetime import datetime


def save_security_event(event, event_id, alerts):

    try:

        # Check for duplicate event
        existing_event = SecurityEvent.query.filter_by(
            event_id=event_id
        ).first()

        if existing_event:
            return {
                "saved": False,
                "alerts": []
            }

        detail = event.get("detail", {})

        identity = detail.get("userIdentity", {})
        request_parameters = detail.get("requestParameters", {})

        # Extract CloudTrail information
        event_name = detail.get("eventName")
        event_source = detail.get("eventSource")
        source_ip = detail.get("sourceIPAddress")
        region = detail.get("awsRegion")

        security_event = SecurityEvent(
            event_id=event_id,
            event_source=event_source,
            event_name=event_name,
            user_identity=identity.get("arn", "Unknown"),
            source_ip=source_ip,
            region=region,
            resource_name=request_parameters.get("groupId"),
            event_data=event,
            event_status="PROCESSED",
            created_at=datetime.utcnow()
        )

        db.session.add(security_event)

        saved_alerts = []

        # Save detected alerts
        for item in alerts:

            alert = Alert(
                event_id=event_id,
                threat_type=item["threat_type"],
                description=item["description"],
                severity=item["severity"],
                risk_score=item["risk_score"],
                source_ip=item.get("source_ip"),
                affected_resource=item.get("event_name"),
                status="OPEN",
                created_at=datetime.utcnow()
            )

            db.session.add(alert)
            saved_alerts.append(alert)

        # Commit before returning generated IDs
        db.session.commit()

        return {
            "saved": True,
            "alerts": [
                {
                    "id": alert.id,
                    "event_id": alert.event_id,
                    "threat_type": alert.threat_type,
                    "description": alert.description,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "source_ip": alert.source_ip,
                    "event_name": alert.affected_resource,
                    "timestamp": alert.created_at.isoformat()
                }
                for alert in saved_alerts
            ]
        }

    except Exception:

        db.session.rollback()
        raise
