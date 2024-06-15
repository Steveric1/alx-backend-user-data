#!/usr/bin/env python3
"""Set up a basic flask app
"""
from flask import (Flask, jsonify, request,
                   abort, redirect, url_for)
from user import User
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound

app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def index():
    """
    Return json respomse
    {"message": "Bienvenue"}
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """
    route to register new user
    """
    email = request.form.get("email")
    passwd = request.form.get("password")

    try:
        user = AUTH.register_user(email, passwd)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """Login route"""
    email = request.form.get("email")
    passwd = request.form.get("password")

    if not AUTH.valid_login(email, passwd):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_d", session_id)

    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """logout function implementation"""
    session_id = request.cookies.get("session_id", None)
    user = AUTH._db.find_user_by(session_id=session_id)
    if user is None or session_id is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """profile route"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": "{}".format(user.email)}), 200
    abort(403)


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """route to get reset password token"""
    email = request.form.get("email")

    user = AUTH._db.find_user_by(email=email)
    if user is None:
        abort(403)
    token = AUTH.get_reset_password_token(email)
    return jsonify({"email": f"{user.email}", "reset_token": f"{token}"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
