"""Flask routes for SecureVault's in-memory file workflow."""

from io import BytesIO

from flask import Flask, jsonify, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

from .crypto import InvalidEncryptedFile, decrypt_file, encrypt_file

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MIN_PASSWORD_LENGTH = 8

app = Flask(__name__, static_folder="../frontend", static_url_path="/assets")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 1024 * 1024


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    return response


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


def _error(message: str, status: int):
    return jsonify(error=message), status


def _process_file(encrypt: bool):
    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    if uploaded_file is None or not uploaded_file.filename:
        return _error("Choose a file to continue.", 400)
    if not password:
        return _error("Enter your password to continue.", 400)
    if encrypt and len(password) < MIN_PASSWORD_LENGTH:
        return _error("Use a password with at least 8 characters.", 400)

    original_name = secure_filename(uploaded_file.filename) or "file"
    data = uploaded_file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        return _error("Files must be 50 MiB or smaller.", 413)

    try:
        if encrypt:
            result = encrypt_file(data, password)
            download_name = f"{original_name}.svlt"
        else:
            result = decrypt_file(data, password)
            if original_name.lower().endswith(".svlt"):
                download_name = original_name[:-5] or "decrypted-file"
            else:
                download_name = f"{original_name}.decrypted"
    except InvalidEncryptedFile as error:
        return _error(str(error), 400)
    except (UnicodeEncodeError, ValueError):
        return _error("Unable to process this file.", 400)

    return send_file(
        BytesIO(result),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=download_name,
        max_age=0,
    )


@app.post("/api/encrypt")
def encrypt():
    return _process_file(encrypt=True)


@app.post("/api/decrypt")
def decrypt():
    return _process_file(encrypt=False)


@app.errorhandler(413)
def file_too_large(_exception):
    return _error("Files must be 50 MiB or smaller.", 413)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
