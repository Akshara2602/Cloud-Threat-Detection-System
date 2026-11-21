from datetime import datetime
from backend.database import db


class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="viewer"
    )

    is_active = db.Column(
        db.Boolean,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class SecurityEvent(db.Model):

    __tablename__ = "security_events"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    event_id = db.Column(
        db.String(255),
        unique=True
    )

    event_source = db.Column(db.String(100))

    event_name = db.Column(db.String(150))

    user_identity = db.Column(db.String(255))

    source_ip = db.Column(db.String(50))

    region = db.Column(db.String(100))

    resource_name = db.Column(db.String(255))

    event_data = db.Column(db.JSON)

    event_status = db.Column(db.String(50))

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Alert(db.Model):

    __tablename__ = "alerts"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    event_id = db.Column(db.String(255))

    threat_type = db.Column(db.String(150))

    description = db.Column(db.Text)

    severity = db.Column(db.String(20))

    risk_score = db.Column(db.Integer)

    source_ip = db.Column(db.String(50))

    affected_resource = db.Column(
        db.String(255)
    )

    status = db.Column(
        db.String(30),
        default="OPEN"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    resolved_at = db.Column(db.DateTime)


class Incident(db.Model):

    __tablename__ = "incidents"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    alert_id = db.Column(
        db.BigInteger,
        db.ForeignKey("alerts.id"),
        nullable=False
    )

    assigned_to = db.Column(
        db.Integer,
        db.ForeignKey("users.id")
    )

    incident_title = db.Column(
        db.String(255)
    )

    investigation_notes = db.Column(
        db.Text
    )

    incident_status = db.Column(
        db.String(30),
        default="OPEN"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


class Notification(db.Model):

    __tablename__ = "notifications"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    alert_id = db.Column(
        db.BigInteger,
        db.ForeignKey("alerts.id"),
        nullable=False
    )

    recipient = db.Column(db.String(255))

    notification_type = db.Column(
        db.String(50)
    )

    message = db.Column(db.Text)

    delivery_status = db.Column(
        db.String(50)
    )

    sent_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class AuditLog(db.Model):

    __tablename__ = "audit_logs"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id")
    )

    action = db.Column(db.String(255))

    details = db.Column(db.Text)

    ip_address = db.Column(db.String(50))

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )