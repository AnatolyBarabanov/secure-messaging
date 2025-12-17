# Secure Messaging Application

This project is a secure client-server messaging application implemented in Python.  
It demonstrates secure network communication using modern cryptographic techniques and basic AI-based anomaly detection.

## Features
- RSA public-key cryptography for secure key exchange
- AES-256 encryption for fast message confidentiality
- HMAC-SHA256 for message integrity and authentication
- JSON serialization for data transmission
- AI-based anomaly detection using Isolation Forest
- Flask-based server API
- Command-line client application

## Technologies Used
- Python
- Flask
- Cryptography library
- Requests
- Scikit-learn
- NumPy

## How to Run
1. Install dependencies:
   ```bash
   pip install -r requirements.txt

Generate RSA keys:

python server/generate_keys.py


Start the server:

python server/server.py


Run the client:

python client/client.py

Project Structure
secure_messaging/

├── common/

├── client/

├── server/

└── requirements.txt

Author

Anatoly Barabanov

