from src.crypto.poly1305 import poly1305_mac, verify_poly1305_tag


def test_poly1305_official_vector():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )

    message = b"Cryptographic Forum Research Group"

    expected_tag = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")

    assert poly1305_mac(message, key) == expected_tag


def test_poly1305_verify_success():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )

    message = b"hello poly1305"
    tag = poly1305_mac(message, key)

    assert verify_poly1305_tag(message, key, tag)


def test_poly1305_verify_failure_when_message_changes():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )

    message = b"hello poly1305"
    tag = poly1305_mac(message, key)

    tampered_message = b"Hello poly1305"

    assert not verify_poly1305_tag(tampered_message, key, tag)