from flask import Flask, request, jsonify
import os
import re
import subprocess
import bcrypt

from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

app = Flask(__name__)

# ----------------------------
# Config / Secrets
# ----------------------------
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-me-please")

# ✅ Active la protection CSRF globale (reconnu par SonarQube)
csrf = CSRFProtect(app)

# ✅ Admin password via variable d'environnement
# Linux/Mac: export ADMIN_PASSWORD="StrongPass123!"
# Windows: setx ADMIN_PASSWORD "StrongPass123!"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeMeNow!")
ADMIN_HASH = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt())

HOST_REGEX = re.compile(r"^([a-zA-Z0-9\-\.]{1,253}|\d{1,3}(\.\d{1,3}){3})$")


# ----------------------------
# Gestion erreur CSRF (propre)
# ----------------------------
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"error": "CSRF detected", "details": str(e)}), 403


# ----------------------------
# Routes corrigées
# ----------------------------

# ✅ Login (POST) + bcrypt
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


# ✅ Ping (POST) sans shell=True + validation host
@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "127.0.0.1").strip()

    if not HOST_REGEX.match(host):
        return jsonify({"status": "error", "message": "Invalid host"}), 400

    try:
        out = subprocess.check_output(["ping", "-c", "1", host], timeout=3)
        return jsonify({"output": out.decode(errors="ignore")}), 200
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Ping timeout"}), 408
    except subprocess.CalledProcessError:
        return jsonify({"status": "error", "message": "Ping failed"}), 400


# ✅ Hello : JSON (évite XSS)
@app.route("/hello", methods=["GET"])
def hello():
    name = (request.args.get("name") or "user").strip()
    return jsonify({"message": f"Hello {name}"}), 200


if __name__ == "__main__":
    # ✅ debug OFF (exigé)
    app.run(host="0.0.0.0", port=5000, debug=False)
