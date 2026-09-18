import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"
PRIVATE_KEY_FILE = KEYS_DIR / "ed25519_private_key.pem"
PUBLIC_KEY_FILE = KEYS_DIR / "ed25519_public_key.pem"
KEY_ROTATION_POLICY = "Offline keys only; live key rotation is not supported."


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    if PRIVATE_KEY_FILE.exists() or PUBLIC_KEY_FILE.exists():
        raise FileExistsError("Key material already exists; refusing to overwrite it")
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    descriptor = os.open(PRIVATE_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(private_pem)
    with PUBLIC_KEY_FILE.open("xb") as stream:
        stream.write(public_pem)
    return private_key, public_key


def load_private_key() -> ed25519.Ed25519PrivateKey | None:
    if not PRIVATE_KEY_FILE.exists():
        return None
    key = serialization.load_pem_private_key(PRIVATE_KEY_FILE.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    return key


def load_public_key() -> ed25519.Ed25519PublicKey | None:
    if not PUBLIC_KEY_FILE.exists():
        return None
    key = serialization.load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key")
    return key


def get_or_generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = load_private_key()
    public_key = load_public_key()
    if private_key is None and public_key is None:
        return generate_keypair()
    if private_key is None or public_key is None:
        raise ValueError("Incomplete keypair; restore the original key material")
    expected = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    actual = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if expected != actual:
        raise ValueError("Stored public and private keys do not match")
    return private_key, public_key


def sign_data(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.sign(data)


def verify_signature(
    data: bytes, signature: bytes, public_key: ed25519.Ed25519PublicKey | None
) -> bool:
    if public_key is None:
        return False
    try:
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
