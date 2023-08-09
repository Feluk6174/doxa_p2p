import pytest

import src.encryption as encryption

def test_save(keys):
    encryption.store_keys(keys[0])
    with open("files/key.bin", "rb") as f:
        assert f.read() == keys[0].encode()

def test_load():
    keys = encryption.get_keys()
    with open("files/key.bin", "rb") as f:
        assert f.read() == keys[0].encode()

def test_verify():
    signing_key, verify_key = encryption.get_keys()
    signature = encryption.sign(b"Hello world!", signing_key)
    assert encryption.verify(signature, b"Hello world!", verify_key)
    assert encryption.verify(signature, b"Hello world!", signing_key)

def test_hash():
    hashed = encryption.hash(b"Hello world!")
    assert hashed == "YzA1MzVlNGJlMmI3OWZmZDkzMjkxMzA1NDM2YmY4ODkzMTRlNGEzZmFlYzA1ZWNmZmNiYjdkZjMxYWQ5ZTUxYQ=="

