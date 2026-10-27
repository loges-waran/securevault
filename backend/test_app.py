"""End-to-end tests for SecureVault's file API."""

import io
import unittest

from backend.app import app
from backend.crypto import MAGIC, decrypt_file, encrypt_file


class SecureVaultTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_encrypted_download_round_trips_original_bytes(self):
        original = b"\x00SecureVault test\xff\n" * 32
        password = "correct horse battery staple"

        encrypted_response = self.client.post(
            "/api/encrypt",
            data={
                "password": password,
                "file": (io.BytesIO(original), "report.bin"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(encrypted_response.status_code, 200)
        encrypted = encrypted_response.data
        self.assertTrue(encrypted.startswith(MAGIC))
        self.assertNotEqual(encrypted, original)
        self.assertIn("report.bin.svlt", encrypted_response.headers["Content-Disposition"])

        decrypted_response = self.client.post(
            "/api/decrypt",
            data={
                "password": password,
                "file": (io.BytesIO(encrypted), "report.bin.svlt"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(decrypted_response.status_code, 200)
        self.assertEqual(decrypted_response.data, original)
        self.assertTrue(
            decrypted_response.headers["Content-Disposition"].endswith(
                "filename=report.bin"
            )
        )

    def test_each_encryption_uses_a_fresh_salt_and_nonce(self):
        first = encrypt_file(b"same content", "long enough password")
        second = encrypt_file(b"same content", "long enough password")

        self.assertNotEqual(first, second)
        self.assertEqual(decrypt_file(first, "long enough password"), b"same content")

    def test_wrong_password_returns_generic_authentication_error(self):
        encrypted = encrypt_file(b"secret", "correct password")
        response = self.client.post(
            "/api/decrypt",
            data={
                "password": "incorrect password",
                "file": (io.BytesIO(encrypted), "secret.svlt"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "Wrong password or encrypted file is damaged.",
        )

    def test_encryption_rejects_short_password(self):
        response = self.client.post(
            "/api/encrypt",
            data={
                "password": "short",
                "file": (io.BytesIO(b"data"), "file.txt"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("at least 8", response.get_json()["error"])

    def test_server_rejects_files_over_the_size_limit(self):
        from unittest.mock import patch

        with patch("backend.app.MAX_UPLOAD_BYTES", 4):
            response = self.client.post(
                "/api/encrypt",
                data={
                    "password": "long enough password",
                    "file": (io.BytesIO(b"12345"), "file.txt"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 413)
        self.assertIn("50 MiB", response.get_json()["error"])

    def test_oversized_multipart_request_returns_json_error(self):
        from unittest.mock import patch

        with patch.dict(app.config, {"MAX_CONTENT_LENGTH": 128}):
            response = self.client.post(
                "/api/encrypt",
                data={
                    "password": "long enough password",
                    "file": (io.BytesIO(b"x" * 256), "file.txt"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 413)
        self.assertIn("50 MiB", response.get_json()["error"])

    def test_invalid_container_is_rejected(self):
        with self.assertRaises(ValueError):
            decrypt_file(b"not a SecureVault container", "any password")


if __name__ == "__main__":
    unittest.main()
