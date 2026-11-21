
import hmac
import os
import uuid
import logging

from datetime import datetime

from flask import Blueprint, request, jsonify

from backend.database import db
from backend.models import Notification

from backend.services.alert_service import save_security_event
from backend.services.email_service import EmailNotificationService

from detection_engine.detector import CloudThreatDetector


logger = logging.getLogger(__name__)

event_bp = Blueprint(
    "events",
    __name__,
    url_prefix="/api/events"
)

detector = CloudThreatDetector()
notification_service = EmailNotificationService()


@event_bp.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "online",
        "service": "Cloud Threat Detection API"
    }), 200


@event_bp.route("/ingest", methods=["POST"])
def ingest_event():

    # Validate API secret
    expected_secret = os.getenv("API_SECRET", "")

    supplied_secret = request.headers.get(
        "X-API-KEY",
        ""
    )

    if not expected_secret or not hmac.compare_digest(
        supplied_secret,
        expected_secret
    ):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    # Read incoming event
    event = request.get_json(silent=True)

    if not isinstance(event, dict):

        return jsonify({
            "error": "Invalid JSON event"
        }), 400

    event_id = event.get("id") or str(uuid.uuid4())

    try:

        # Step 1: Detect suspicious activity
        alerts = detector.analyze_event(event)

        # Step 2: Save event and generated alerts
        result = save_security_event(
            event,
            event_id,
            alerts
        )

        if not result["saved"]:

            return jsonify({
                "message": "Duplicate event ignored",
                "event_id": event_id
            }), 200

        saved_alerts = result["alerts"]

        notification_results = []

        # Step 3: Send SNS notifications and record results
        for alert in saved_alerts:

            notification = notification_service.send_alert(
                alert
            )

            notification_success = notification.get(
                "success",
                False
            )

            notification_record = Notification(
                alert_id=alert["id"],

                recipient=os.getenv(
                    "SNS_NOTIFICATION_RECIPIENT",
                    "SNS Topic Subscribers"
                ),

                notification_type="SNS",

                message=str(notification),

                delivery_status=(
                    "SENT" if notification_success
                    else "FAILED"
                ),

                sent_at=datetime.utcnow()
            )

            db.session.add(notification_record)

            notification_results.append({
                "alert_id": alert["id"],
                "success": notification_success,
                "message": notification.get("message"),
                "message_id": notification.get("message_id")
            })

        # Step 4: Commit notification records
        db.session.commit()

        # Step 5: Return processing result
        return jsonify({
            "message": "Event processed successfully",
            "event_id": event_id,
            "threat_detected": len(saved_alerts) > 0,
            "total_alerts": len(saved_alerts),
            "alerts": saved_alerts,
            "notifications": notification_results
        }), 201

    except Exception:

        db.session.rollback()

        logger.exception(
            "Event processing failed for event ID: %s",
            event_id
        )

        return jsonify({
            "error": "Event processing failed",
            "event_id": event_id
        }), 500
