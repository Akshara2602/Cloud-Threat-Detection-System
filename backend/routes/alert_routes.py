from flask import Blueprint, jsonify, request

from backend.models import Alert

from backend.database import db

from datetime import datetime


alert_bp = Blueprint(
    "alerts",
    __name__,
    url_prefix="/api/alerts"
)


@alert_bp.route("/", methods=["GET"])
def get_alerts():

    severity = request.args.get("severity")

    status = request.args.get("status")

    query = Alert.query

    if severity:

        query = query.filter_by(
            severity=severity.upper()
        )

    if status:

        query = query.filter_by(
            status=status.upper()
        )

    alerts = query.order_by(
        Alert.created_at.desc()
    ).limit(200).all()

    results = []

    for alert in alerts:

        results.append({

            "id": alert.id,

            "threat_type": alert.threat_type,

            "description": alert.description,

            "severity": alert.severity,

            "risk_score": alert.risk_score,

            "source_ip": alert.source_ip,

            "status": alert.status,

            "created_at": str(alert.created_at)

        })

    return jsonify(results)


@alert_bp.route("/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):

    alert = Alert.query.get_or_404(alert_id)

    return jsonify({

        "id": alert.id,

        "threat_type": alert.threat_type,

        "description": alert.description,

        "severity": alert.severity,

        "risk_score": alert.risk_score,

        "source_ip": alert.source_ip,

        "status": alert.status,

        "created_at": str(alert.created_at)

    })


@alert_bp.route("/<int:alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):

    alert = Alert.query.get_or_404(alert_id)

    data = request.get_json(silent=True) or {}

    new_status = data.get("status", "").upper()

    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:

        return jsonify({
            "error": "Invalid alert status"
        }), 400

    alert.status = new_status

    if new_status == "RESOLVED":

        alert.resolved_at = datetime.utcnow()

    db.session.commit()

    return jsonify({

        "message": "Alert status updated",

        "alert_id": alert.id,

        "status": alert.status

    })