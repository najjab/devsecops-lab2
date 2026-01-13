from flask import Flask, request, jsonify
import os
import re
import subprocess
import bcrypt

from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

app = Flask(__name__)

# ----------------------------
# Config / Secrets (NO HARDCODED DEFAULTS)
# ----------------------------
# ✅ Bandit-friendly: pas de secret "par défaut" en dur
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # doit exister dans l'env

csrf = CSRFProtect(app)

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]    # doit exister dans l'env
ADMIN_HASH = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt())

HOST_REGEX = re.compile(r"^([a-zA-Z0-9\-\.]{1,253}|\d{1,3}(\.\d{1,3}){3})$")


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"error": "CSRF detected"}), 403


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing credentials"}), 400

    if username == "admin" and bcrypt.checkpw(password.encode(), ADMIN_HASH):
        return jsonify({"status": "success", "message": "Logged in"}), 200

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()

    if not host or not HOST_REGEX.match(host):
        return jsonify({"status": "error", "message": "Invalid host"}), 400

    try:
        # ✅ Pas de shell=True + run() + check=True
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        return jsonify({"output": result.stdout}), 200
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Ping timeout"}), 408
    except subprocess.CalledProcessError:
        return jsonify({"status": "error", "message": "Ping failed"}), 400


@app.route("/hello", methods=["GET"])
def hello():
    name = (request.args.get("name") or "user").strip()
    return jsonify({"message": f"Hello {name}"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
