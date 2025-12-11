from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os

app = Flask(__name__)

# Secret en dur (mauvaise pratique volontaire)
SECRET_KEY = "dev-secret-key-12345"  # Hardcoded secret


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnérabilité : SQL Injection (f-string directe)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    result = cursor.fetchone()

    if result:
        return {"status": "success", "user": username}

    return {"status": "error", "message": "Invalid credentials"}


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")
    cmd = f"ping -c 1 {host}"

    # Vulnérabilité : Command Injection via shell=True
    output = subprocess.check_output(cmd, shell=True)
    return {"output": output.decode()}


@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")

    # Vulnérabilité CRITIQUE : utilisation de eval()
    result = eval(expression)
    return {"result": result}


@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")

    # Mauvaise pratique : MD5 non sécurisé
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    return {"md5": hashed}


@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")

    # Vulnérabilité : File Read arbitraire (Path Traversal possible)
    with open(filename, "r") as f:
        content = f.read()

    return {"content": content}


@app.route("/debug", methods=["GET"])
def debug():
    # Exposition d'infos sensibles : très mauvaise pratique
    return {
        "debug": True,
        "secret_key": SECRET_KEY,
        "environment": dict(os.environ),
    }


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps vulnerable API"}


if __name__ == "__main__":
    # Application exposée sur toutes les interfaces, port 5000
    app.run(host="0.0.0.0", port=5000)
