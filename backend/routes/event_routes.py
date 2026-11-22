
import hmac
import os
import uuid

from flask import Blueprint, request, jsonify

from backend.database import db

from backend.services.alert_service import save_security_event

from backend.services.email_service import EmailNotificationService

from detection_engine.detector import CloudThreatDetector


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
    })


@event_bp.route("/ingest", methods=["POST"])
def ingest_event():

    expected_secret = os.getenv("API_SECRET", "")

    print("Backend API_SECRET loaded:", bool(expected_secret))
    print("Backend secret length:", len(expected_secret))

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

    event = request.get_json(silent=True)

    if not isinstance(event, dict):

        return jsonify({
            "error": "Invalid JSON event"
        }), 400

    event_id = event.get("id") or str(uuid.uuid4())

    try:

        alerts = detector.analyze_event(event)

        saved = save_security_event(
            event,
            event_id,
            alerts
        )

        if not saved:

            return jsonify({
                "message": "Duplicate event ignored"
            }), 200

        notification_results = []

        for alert in alerts:

            notification = notification_service.send_alert(
                alert
            )

            notification_results.append(notification)

        return jsonify({
            "message": "Event processed",
            "event_id": event_id,
            "threat_detected": len(alerts) > 0,
            "total_alerts": len(alerts),
            "alerts": alerts,
            "notifications": notification_results
        }), 201

    except Exception as error:

        db.session.rollback()

        return jsonify({
            "error": "Event processing failed",
            "details": str(error)
        }), 500
