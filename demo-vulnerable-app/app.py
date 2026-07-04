from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, request, Response

app = Flask(__name__)

# Intentional vulnerability for SAST demo: hard-coded secret.
API_KEY = "sk_demo_hardcoded_secret_do_not_use"
BASE_DIR = Path(__file__).parent / "files"
DB_PATH = Path(__file__).parent / "demo.db"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.executemany("INSERT INTO users(id, name, role) VALUES (?, ?, ?)", [(1, "Alice", "admin"), (2, "Bob", "user")])
    conn.commit()
    conn.close()


@app.route("/")
def index() -> str:
    return "Demo vulnerable app. Try /user?id=1, /search?q=test, /download?file=sample.txt"


@app.route("/user")
def user_lookup() -> str:
    # Intentional SQL injection for portfolio scanner demo only.
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, name, role FROM users WHERE id = {user_id}"
    rows = cur.execute(query).fetchall()
    conn.close()
    return {"query": query, "rows": rows}


@app.route("/search")
def search() -> Response:
    # Intentional reflected XSS for portfolio scanner demo only.
    q = request.args.get("q", "")
    html = f"<html><body><h1>Search</h1><p>You searched for: {q}</p></body></html>"
    return Response(html, mimetype="text/html")


@app.route("/download")
def download() -> Response:
    # Intentional path traversal for portfolio scanner demo only.
    filename = request.args.get("file", "sample.txt")
    path = BASE_DIR / filename
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        content = f"Could not read file: {exc}"
    return Response(content, mimetype="text/plain")


if __name__ == "__main__":
    BASE_DIR.mkdir(exist_ok=True)
    (BASE_DIR / "sample.txt").write_text("This file is safe to read.\n", encoding="utf-8")
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
