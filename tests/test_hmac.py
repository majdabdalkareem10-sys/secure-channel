from src.crypto.hmac import hmac_sha256, hmac_sha256_hex, verify_hmac_sha256


def test_hmac_sha256_rfc4231_case_1():
    key = bytes.fromhex("0b" * 20)
    message = b"Hi There"

    assert hmac_sha256_hex(key, message) == (
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )


def test_hmac_sha256_rfc4231_case_2():
    key = b"Jefe"
    message = b"what do ya want for nothing?"

    assert hmac_sha256_hex(key, message) == (
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843"
    )


def test_hmac_sha256_rfc4231_case_3():
    key = bytes.fromhex("aa" * 20)
    message = bytes.fromhex("dd" * 50)

    assert hmac_sha256_hex(key, message) == (
        "773ea91e36800e46854db8ebd09181a7"
        "2959098b3ef8c122d9635514ced565fe"
    )


def test_hmac_verify_success():
    key = b"secret key"
    message = b"important handshake data"

    tag = hmac_sha256(key, message)

    assert verify_hmac_sha256(key, message, tag)


def test_hmac_verify_failure_when_message_changes():
    key = b"secret key"
    message = b"important handshake data"

    tag = hmac_sha256(key, message)

    assert not verify_hmac_sha256(key, b"changed data", tag)