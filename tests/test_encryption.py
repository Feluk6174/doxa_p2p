import pytest

import src.encryption as encryption

key_file = "test_key.bin"

def test_save(keys):
    global key_file
    encryption.store_keys(keys[0], file = key_file)
    with open(f"files/{key_file}", "rb") as f:
        assert f.read() == keys[0].encode()

def test_load():
    global key_file
    keys = encryption.get_keys(file = key_file)
    with open(f"files/{key_file}", "rb") as f:
        assert f.read() == keys[0].encode()

def test_verify():
    global key_file
    signing_key, verify_key = encryption.get_keys(file = key_file)
    signature = encryption.sign(b"Hello world!", signing_key)
    assert encryption.verify(signature, b"Hello world!", verify_key)
    assert encryption.verify(signature, b"Hello world!", signing_key)

def test_hash():
    hashed = encryption.hash(b"Hello world!")
    assert hashed == "YzA1MzVlNGJlMmI3OWZmZDkzMjkxMzA1NDM2YmY4ODkzMTRlNGEzZmFlYzA1ZWNmZmNiYjdkZjMxYWQ5ZTUxYQ=="

