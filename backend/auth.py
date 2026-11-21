from functools import wraps

from flask import jsonify

from flask_jwt_extended import (
    verify_jwt_in_request,
    get_jwt_identity
)

from backend.models import User


def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            verify_jwt_in_request()

            identity = get_jwt_identity()

            user = User.query.get(identity)

            if not user or not user.is_active:

                return jsonify({
                    "error": "Account unavailable"
                }), 403

            if user.role not in allowed_roles:

                return jsonify({
                    "error": "Insufficient permissions"
                }), 403

            return function(*args, **kwargs)

        return wrapper

    return decorator