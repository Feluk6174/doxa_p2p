import pytest
import src.encryption

@pytest.fixture
def keys():
    return src.encryption.gen_keys()
