import base64

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from nacl.hash import sha256

def gen_keys() -> tuple[SigningKey, VerifyKey]:
    """Generates keys for signing (Ed25519)

    Returns:
        tuple[SigningKey, VerifyKey]: Returns a signing key and a verify key
    """
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key

def store_keys(signing_key:SigningKey, file:str = "key.bin") -> None:
    """Stores the keys in a file.

    Args:
        signing_key (SigningKey): The signing key that needs to be stored. (Verify key is not needed because it derives from the signing key).
        file (str, optional): Name of the file where the keys should be stored. Defaults to "key.bin".
    """
    with open(f"files/{file}", "wb") as f:
        f.write(signing_key.encode())

def get_keys(file:str = "key.bin") -> tuple[SigningKey, VerifyKey]:
    """Gets keys from stored file.

    Args:
        file (str, optional): Name of the file where the keys are stored. Defaults to "key.bin".

    Returns:
        tuple[SigningKey, VerifyKey]: Signing and Verifing key (Ed25519)
    """
    with open(f"files/{file}", "rb") as f:
        data = f.read()
    signing_key = SigningKey(data)
    return signing_key, signing_key.verify_key

def sign(message:bytes, signing_key:SigningKey) -> str:
    """Creates signatre of a message (Ed25519)

    Args:
        message (bytes): Message that needs to be signed
        signing_key (SigningKey): The key with which the message will be signed

    Returns:
        str: Signature encoded in urlsafe_b64 (base64.urlsafe_b64encode)
    """
    signature = signing_key.sign(message)
    return base64.urlsafe_b64encode(signature.signature).decode("utf-8")

def verify(signature:str, message:bytes, key:VerifyKey|SigningKey) -> bool:
    """Verifies if the signature of a message is correct (Ed25519)

    Args:
        signature (str): Signature of the message encoded in urlsafe_b64 (base64.urlsafe_b64encode) 
        message (bytes): MEssage tht needs to be verified
        key (VerifyKey | SigningKey): Key to verify the message

    Returns:
        bool: If the signature is correct it will return true else it will return false
    """
    if isinstance(key, SigningKey):
        key = key.verify_key
    try:
        key.verify(message, base64.urlsafe_b64decode(signature.encode("utf-8")))
        return True
    except BadSignatureError: 
        return False

def hash(data:bytes) -> str:
    """Creates Hash of some data (SHA255)

    Args:
        data (bytes): Data that needs to be hashed

    Returns:
        str: hash encoded in urlsafe_b64 (base64.urlsafe_b64encode)
    """
    return base64.urlsafe_b64encode(sha256(data)).decode("utf-8")


if __name__ == "__main__":
    import random
    random.seed(12)
    signing_key, verify_key = gen_keys()
    signature = sign(b"hello world!", signing_key)
    print(signature, len(signature))
    print(verify(signature, b"hello world!", signing_key))
    print(hash(b"Hello world!"), len(hash(b"Hello world!")))