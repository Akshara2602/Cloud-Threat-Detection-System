from flask import Blueprint, request, jsonify

from flask_bcrypt import Bcrypt

from flask_jwt_extended import (
    create_access_token
)

from backend.database import db

from backend.models import User

from datetime import timedelta


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/api/auth"
)

bcrypt = Bcrypt()


@auth_bp.route("/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    username = data.get("username")

    email = data.get("email")

    password = data.get("password")

    if not username or not email or not password:

        return jsonify({
            "error": "All fields are required"
        }), 400

    if len(password) < 12:

        return jsonify({
            "error": "Password must contain at least 12 characters"
        }), 400

    existing = User.query.filter(
        (User.username == username) |
        (User.email == email)
    ).first()

    if existing:

        return jsonify({
            "error": "User already exists"
        }), 409

    password_hash = bcrypt.generate_password_hash(
        password
    ).decode("utf-8")

    user = User(

        username=username,

        email=email,

        password_hash=password_hash,

        role="viewer"

    )

    db.session.add(user)

    db.session.commit()

    return jsonify({
        "message": "User registered successfully"
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    username = data.get("username")

    password = data.get("password")

    user = User.query.filter_by(
        username=username
    ).first()

    if not user or not user.is_active:

        return jsonify({
            "error": "Invalid credentials"
        }), 401

    if not bcrypt.check_password_hash(
        user.password_hash,
        password
    ):

        return jsonify({
            "error": "Invalid credentials"
        }), 401

    token = create_access_token(

        identity=str(user.id),

        expires_delta=timedelta(minutes=30),

        additional_claims={
            "role": user.role
        }

    )

    return jsonify({

        "message": "Login successful",

        "access_token": token,

        "user": {

            "id": user.id,

            "username": user.username,

            "role": user.role

        }

    })