
from flask import Blueprint, jsonify, request

from backend.database import db

from backend.models import Incident, Alert


incident_bp = Blueprint(
    "incidents",
    __name__,
    url_prefix="/api/incidents"
)


@incident_bp.route("/", methods=["GET"])
def get_incidents():

    incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    results = []

    for incident in incidents:

        results.append({

            "id": incident.id,

            "alert_id": incident.alert_id,

            "title": incident.incident_title,

            "assigned_to": incident.assigned_to,

            "status": incident.incident_status,

            "notes": incident.investigation_notes,

            "created_at": str(incident.created_at)

        })

    return jsonify(results)


@incident_bp.route("/", methods=["POST"])
def create_incident():

    data = request.get_json(silent=True) or {}

    alert_id = data.get("alert_id")

    title = data.get("incident_title")

    if not alert_id or not title:

        return jsonify({
            "error": "Alert ID and title are required"
        }), 400

    alert = Alert.query.get(alert_id)

    if not alert:

        return jsonify({
            "error": "Alert not found"
        }), 404

    incident = Incident(

        alert_id=alert_id,

        incident_title=title,

        assigned_to=data.get("assigned_to"),

        investigation_notes="",

        incident_status="OPEN"

    )

    db.session.add(incident)

    db.session.commit()

    return jsonify({

        "message": "Incident created",

        "incident_id": incident.id

    }), 201


@incident_bp.route(
    "/<int:incident_id>",
    methods=["PUT"]
)
def update_incident(incident_id):

    incident = Incident.query.get_or_404(
        incident_id
    )

    data = request.get_json(silent=True) or {}

    status = data.get("status")

    if status:

        allowed = [
            "OPEN",
            "IN_PROGRESS",
            "CLOSED"
        ]

        if status not in allowed:

            return jsonify({
                "error": "Invalid status"
            }), 400

        incident.incident_status = status

    if "notes" in data:

        incident.investigation_notes = (
            data["notes"]
        )

    if "assigned_to" in data:

        incident.assigned_to = (
            data["assigned_to"]
        )

    db.session.commit()

    return jsonify({

        "message": "Incident updated",

        "incident_id": incident.id,

        "status": incident.incident_status

    })
