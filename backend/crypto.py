"""Authenticated file encryption for SecureVault."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SVLT"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE


class InvalidEncryptedFile(ValueError):
    """The input is not a valid SecureVault container or did not authenticate."""


def _derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=KEY_SIZE, n=2**14, r=8, p=1).derive(
        password.encode("utf-8")
    )


def encrypt_file(data: bytes, password: str) -> bytes:
    """Encrypt bytes into a versioned SecureVault container."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, header)
    return header + ciphertext


def decrypt_file(container: bytes, password: str) -> bytes:
    """Authenticate and decrypt a SecureVault container."""
    if len(container) < HEADER_SIZE + TAG_SIZE:
        raise InvalidEncryptedFile("This is not a valid SecureVault file.")

    if container[: len(MAGIC)] != MAGIC or container[len(MAGIC)] != VERSION:
        raise InvalidEncryptedFile("This is not a supported SecureVault file.")

    header = container[:HEADER_SIZE]
    salt_start = len(MAGIC) + 1
    salt = container[salt_start : salt_start + SALT_SIZE]
    nonce = container[salt_start + SALT_SIZE : HEADER_SIZE]
    key = _derive_key(password, salt)

    try:
        return AESGCM(key).decrypt(nonce, container[HEADER_SIZE:], header)
    except InvalidTag as error:
        raise InvalidEncryptedFile(
            "Wrong password or encrypted file is damaged."
        ) from error
