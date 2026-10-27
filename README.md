# SecureVault

SecureVault is a small Flask web application for encrypting and decrypting files with password-derived AES-256-GCM keys. Files are processed in memory and are not saved to the server.

## Requirements

- Python 3.10 or newer
- pip

## Install

From the project directory, create and activate a virtual environment:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run

```powershell
python -m backend.app
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Choose **Encrypt** or **Decrypt**, select or drop a file, enter the password, and submit. Encrypted downloads use the `.svlt` suffix. The upload limit is 50 MiB.

## Test

```powershell
python -m unittest backend.test_app -v
```

The tests cover encrypted downloads, byte-for-byte recovery, independent salts/nonces, invalid containers, password validation, and incorrect-password handling.

## Encryption format and security

Each `.svlt` file contains a four-byte format marker, a version byte, a fresh 16-byte random salt, a fresh 12-byte random nonce, and the AES-GCM ciphertext with its 16-byte authentication tag. Scrypt derives a 256-bit key from the password and salt. The header is authenticated as additional data. Decryption only returns plaintext after AES-GCM authentication succeeds; wrong passwords and damaged files produce the same generic authentication error.

The password is sent to the local Flask backend for key derivation, but passwords and derived keys are not written to disk or retained by the application. Use a unique, strong passphrase and keep a separate backup of important originals. The built-in Flask development server is intended for local use only. Any production deployment must use HTTPS and a production WSGI server.

## Deploy to Render

1. Push this project to a GitHub repository.
2. In Render, choose **New → Blueprint**, connect the repository, and confirm the settings from `render.yaml`.
3. Wait for the service to build, then open its `onrender.com` URL. Render provides HTTPS for the hosted service.

The public service has no user accounts or per-user quotas. Its operator can access uploaded data while it is being processed in memory; use it only if you trust the host. For private single-user use, run it locally instead.