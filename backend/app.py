from flask import Flask, jsonify

from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv

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

    app.config.from_object(Config)

    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://localhost:8501"
            ]
        }
    })

    db.init_app(app)

    jwt = JWTManager(app)

    app.register_blueprint(event_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(raw_event_bp)

    @app.route("/", methods=["GET"])
    def home():

        return jsonify({

            "project": (
                "Cloud Threat Detection "
                "and Alert System"
            ),

            "status": "Running",

            "version": "1.0.0"

        })

    @app.route("/health", methods=["GET"])
    def health():

        return jsonify({
            "database": "Application connection configured",
            "status": "healthy"
        })

    return app


app = create_app()


if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
