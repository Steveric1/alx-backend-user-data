#!/usr/bin/env python3
"""Set up a basic flask app
"""
from flask import (Flask, jsonify, request,
                   abort, redirect, url_for)
from user import User
from auth import Auth

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
def logout() -> str:
    """logout function implementation"""
    session_id = request.cookies.get("session_id", None)

    if session_id is None:
        abort(403)
    try:
        user = AUTH._db.find_user_by(session_id=session_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect("/")
        else:
            abort(403)
    except Exception as e:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
