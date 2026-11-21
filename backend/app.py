
from flask import Flask, jsonify

from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

from backend.config import Config

from backend.database import (
    db,
    initialize_database
)

from backend.routes.event_routes import event_bp
from backend.routes.incident_routes import incident_bp
from backend.routes.auth_routes import auth_bp
from backend.routes.alert_routes import alert_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.raw_event_routes import raw_event_bp


def create_app():

    app = Flask(__name__)

    # Load application configuration
    app.config.from_object(Config)

    # Enable CORS for the local Streamlit dashboard
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://localhost:8501"
            ]
        }
    })

    # Initialize database
    db.init_app(app)

    # Initialize JWT
    jwt = JWTManager(app)

    # Register API routes
    app.register_blueprint(event_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(raw_event_bp)

    # Home route
    @app.route("/", methods=["GET"])
    def home():

        return jsonify({
            "project": "Cloud Threat Detection and Alert System",
            "status": "Running",
            "version": "1.0.0"
        }), 200

    # Database health check
    @app.route("/health", methods=["GET"])
    def health():

        try:
            with db.engine.connect() as connection:
                connection.execute(text("SELECT 1"))

            return jsonify({
                "database": "connected",
                "status": "healthy"
            }), 200

        except Exception:
            app.logger.exception("Database health check failed")

            return jsonify({
                "database": "disconnected",
                "status": "unhealthy"
            }), 503

    return app


# Create Flask application
app = create_app()


# Run locally
if __name__ == "__main__":

    with app.app_context():
        initialize_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
