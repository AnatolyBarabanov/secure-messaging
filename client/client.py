# Command-line client that encrypts messages and sends them securely to the server

import base64
import json
import requests
from cryptography.hazmat.primitives import serialization

from common.crypto_utils import (
    generate_aes_key,
    encrypt_session_key,
    encrypt_message_aes,
    compute_hmac
)

SERVER_URL = "http://127.0.0.1:5000"


def get_server_public_key():
    # Retrieves the server's RSA public key
    response = requests.get(f"{SERVER_URL}/public_key")
    response.raise_for_status()
    pem = response.json()["public_key_pem"].encode()
    return serialization.load_pem_public_key(pem)


def send_message(public_key, message: str):
    # Encrypts and sends a message to the server
    aes_key = generate_aes_key()
    encrypted_key = encrypt_session_key(public_key, aes_key)
    iv, ciphertext = encrypt_message_aes(aes_key, message)
    mac = compute_hmac(aes_key, iv + ciphertext)

    payload = {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac).decode()
    }

    # Serialize encrypted message payload into JSON format
    return requests.post(
        f"{SERVER_URL}/message",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload)
    )


def main():
    print("🔐 Secure Messaging Client")

    public_key = get_server_public_key()
    print("Connected to server.\n")

    while True:
        msg = input("Enter message (or 'quit'): ")
        if msg.lower() == "quit":
            break

        response = send_message(public_key, msg)
        print("Server response:", response.json())


if __name__ == "__main__":
    main()
