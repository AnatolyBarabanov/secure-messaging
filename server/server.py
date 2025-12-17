# Flask server that receives encrypted messages,
# verifies integrity, decrypts content, and runs AI detection

import base64
from pathlib import Path
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization

from common.crypto_utils import (
    load_private_key,
    decrypt_session_key,
    decrypt_message_aes,
    verify_hmac
)
from common.anomaly_detection import AnomalyDetector

app = Flask(__name__)

# Load RSA private key
BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_PATH = BASE_DIR / "keys" / "private_key.pem"

private_key = load_private_key(str(PRIVATE_KEY_PATH))
public_key = private_key.public_key()

# Initialize AI anomaly detector
detector = AnomalyDetector()


@app.get("/public_key")
def get_public_key():
    # Sends the server's public RSA key to the client
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return jsonify({"public_key_pem": pem})


@app.post("/message")
def receive_message():
    # Receives encrypted message payload from client, validates integrity, decrypts content, and checks for anomalies

    # Deserialize incoming JSON payload from client
    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "reason": "Invalid JSON"}), 400

    try:
        encrypted_key = base64.b64decode(data["encrypted_key"])
        iv = base64.b64decode(data["iv"])
        ciphertext = base64.b64decode(data["ciphertext"])
        mac = base64.b64decode(data["hmac"])

        # Decrypt AES key using RSA
        aes_key = decrypt_session_key(private_key, encrypted_key)

        # Verify message integrity using HMAC
        if not verify_hmac(aes_key, iv + ciphertext, mac):
            return jsonify({"status": "error", "reason": "HMAC failed"}), 400

        # Decrypt message
        plaintext = decrypt_message_aes(aes_key, iv, ciphertext)

        # Run AI anomaly detection
        anomalous, score = detector.score_message(plaintext)

        print("Decrypted message:", plaintext)

        return jsonify({
            "status": "ok",
            "plaintext_echo": plaintext,
            "anomalous": bool(anomalous),
            "score": float(score)
        })

    except Exception as e:
        return jsonify({"status": "error", "reason": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
