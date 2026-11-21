from flask import Blueprint, jsonify

from backend.models import Alert, SecurityEvent

from sqlalchemy import func


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/api/dashboard"
)


@dashboard_bp.route("/summary", methods=["GET"])
def summary():

    total_events = SecurityEvent.query.count()

    total_alerts = Alert.query.count()

    open_alerts = Alert.query.filter_by(
        status="OPEN"
    ).count()

    critical_alerts = Alert.query.filter_by(
        severity="CRITICAL"
    ).count()

    high_alerts = Alert.query.filter_by(
        severity="HIGH"
    ).count()

    medium_alerts = Alert.query.filter_by(
        severity="MEDIUM"
    ).count()

    low_alerts = Alert.query.filter_by(
        severity="LOW"
    ).count()

    severity_distribution = {

        "CRITICAL": critical_alerts,

        "HIGH": high_alerts,

        "MEDIUM": medium_alerts,

        "LOW": low_alerts

    }

    recent_alerts = Alert.query.order_by(
        Alert.created_at.desc()
    ).limit(10).all()

    return jsonify({

        "total_events": total_events,

        "total_alerts": total_alerts,

        "open_alerts": open_alerts,

        "severity_distribution": (
            severity_distribution
        ),

        "recent_alerts": [

            {

                "id": alert.id,

                "type": alert.threat_type,

                "severity": alert.severity,

                "risk_score": alert.risk_score,

                "status": alert.status

            }

            for alert in recent_alerts

        ]

    })