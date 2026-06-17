from src.crypto.sha256 import sha256, sha256_hex


def test_sha256_empty_message():
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )


def test_sha256_abc():
    assert sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_long_message():
    message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

    assert sha256_hex(message) == (
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1"
    )


def test_sha256_returns_32_bytes():
    digest = sha256(b"Majd")

    assert isinstance(digest, bytes)
    assert len(digest) == 32