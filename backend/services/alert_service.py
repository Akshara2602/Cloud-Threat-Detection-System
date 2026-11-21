from backend.database import db

from backend.models import Alert, SecurityEvent

from datetime import datetime


def save_security_event(event, event_id, alerts):

    try:

        security_event = SecurityEvent.query.filter_by(
            event_id=event_id
        ).first()

        if security_event:
            return False

        identity = event.get("userIdentity", {})

        event_name = event.get("eventName")

        source_ip = event.get("sourceIPAddress")

        security_event = SecurityEvent(

            event_id=event_id,

            event_source=event.get("eventSource"),

            event_name=event_name,

            user_identity=identity.get(
                "arn",
                "Unknown"
            ),

            source_ip=source_ip,

            region=event.get("awsRegion"),

            resource_name=event.get(
                "requestParameters", {}
            ).get("groupId"),

            event_data=event,

            event_status="PROCESSED"
        )

        db.session.add(security_event)

        for item in alerts:

            alert = Alert(

                event_id=event_id,

                threat_type=item["threat_type"],

                description=item["description"],

                severity=item["severity"],

                risk_score=item["risk_score"],

                source_ip=item["source_ip"],

                affected_resource=(
                    item.get("event_name")
                ),

                status="OPEN",

                created_at=datetime.utcnow()
            )

            db.session.add(alert)

        db.session.commit()

        return True

    except Exception:

        db.session.rollback()

        raise