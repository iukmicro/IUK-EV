import hashlib
import hmac

SALT = "ev_platform_fixed_salt_2026"

def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt_bytes = SALT.encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000)
    return key.hex()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    expected_hash = hash_password(plain_password)
    return hmac.compare_digest(expected_hash, hashed_password)