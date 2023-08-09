import base64

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from nacl.hash import sha256

def gen_keys() -> tuple[SigningKey, VerifyKey]:
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key

def store_keys(signing_key:SigningKey) -> None:
    with open("files/key.bin", "wb") as f:
        f.write(signing_key.encode())

def get_keys() -> tuple[SigningKey, VerifyKey]:
    with open("files/key.bin", "rb") as f:
        data = f.read()
    signing_key = SigningKey(data)
    return signing_key, signing_key.verify_key

def sign(message:bytes, signing_key:SigningKey) -> str:
    signature = signing_key.sign(message)
    return base64.urlsafe_b64encode(signature.signature).decode("utf-8")

def verify(signature:str, message:bytes, key:VerifyKey|SigningKey) -> bool:
    if isinstance(key, SigningKey):
        key = key.verify_key
    try:
        key.verify(message, base64.urlsafe_b64decode(signature.encode("utf-8")))
        return True
    except BadSignatureError: 
        return False

def hash(data:bytes) -> str:
    return base64.urlsafe_b64encode(sha256(data)).decode("utf-8")


if __name__ == "__main__":
    import random
    random.seed(12)
    signing_key, verify_key = gen_keys()
    signature = sign(b"hello world!", signing_key)
    print(signature, len(signature))
    print(verify(signature, b"hello world!", signing_key))
    print(hash(b"Hello world!"), len(hash(b"Hello world!")))