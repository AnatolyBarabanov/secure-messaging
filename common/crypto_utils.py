# This file contains all cryptographic utilities used by both the client and the server
# It implements RSA key exchange, AES encryption, and HMAC integrity checks

import os
import hmac
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# RSA KEY FUNCTIONS
def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    # Generates an RSA private key
    # The public key is derived from this private key
    # RSA is used only for exchanging the AES session key
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def save_private_key_pem(private_key: rsa.RSAPrivateKey, path: str):
    # Saves the RSA private key to a PEM file
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key_pem(public_key: rsa.RSAPublicKey, path: str):
    # Saves the RSA public key to a PEM file
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    # Loads an RSA private key from a PEM file
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(
        data,
        password=None,
        backend=default_backend()
    )

# AES ENCRYPTION
def generate_aes_key(length: int = 32) -> bytes:
    # Generates a random AES session key (32 bytes = AES-256)
    return os.urandom(length)


def encrypt_message_aes(key: bytes, plaintext: str) -> Tuple[bytes, bytes]:
    # Encrypts a plaintext message using AES-256 in CBC mode and returns the IV and the encrypted ciphertext
    iv = os.urandom(16)  # Random initialization vector

    # Pad plaintext to AES block size
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def decrypt_message_aes(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    # Decrypts AES-256-CBC encrypted data and removes padding
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# RSA SESSION KEY HANDLING
def encrypt_session_key(public_key, session_key: bytes) -> bytes:
    # Encrypts the AES session key using the server's RSA public key
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_session_key(private_key, encrypted_session_key: bytes) -> bytes:
    # Decrypts the AES session key using the RSA private key
    return private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# HMAC INTEGRITY CHECK
def compute_hmac(key: bytes, data: bytes) -> bytes:
    # Computes HMAC-SHA256 for integrity verification.
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, mac: bytes) -> bool:
    # Verifies the HMAC to ensure the message was not modified.
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, mac)
