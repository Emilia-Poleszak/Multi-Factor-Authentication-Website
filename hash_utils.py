import bcrypt


def create_hash(plain_text: str) -> bytes:
    salt = bcrypt.gensalt()
    text_hash = bcrypt.hashpw(plain_text.encode('utf-8'), salt)
    return text_hash


def check(plain_text: str, reference_hash: bytes) -> bool:
    return bcrypt.checkpw(plain_text.encode('utf-8'), reference_hash)
