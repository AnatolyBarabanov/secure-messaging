from pathlib import Path

from common.crypto_utils import (
    generate_rsa_keypair,
    save_private_key_pem,
    save_public_key_pem
)


def main():
    base_dir = Path(__file__).resolve().parent
    keys_dir = base_dir / "keys"
    keys_dir.mkdir(exist_ok=True)

    private_key_path = keys_dir / "private_key.pem"
    public_key_path = keys_dir / "public_key.pem"

    print("Generating RSA keypair (2048-bit)...")
    private_key = generate_rsa_keypair(2048)
    public_key = private_key.public_key()

    save_private_key_pem(private_key, str(private_key_path))
    save_public_key_pem(public_key, str(public_key_path))

    print(f"Private key saved to: {private_key_path}")
    print(f"Public key saved to:  {public_key_path}")


if __name__ == "__main__":
    main()
