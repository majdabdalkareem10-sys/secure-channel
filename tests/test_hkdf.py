from src.crypto.hkdf import hkdf_extract, hkdf_expand, hkdf


def test_hkdf_rfc5869_case_1_extract():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")

    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )

    assert hkdf_extract(salt, ikm) == expected_prk


def test_hkdf_rfc5869_case_1_expand():
    prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42

    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    assert hkdf_expand(prk, info, length) == expected_okm


def test_hkdf_rfc5869_case_1_full():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    assert hkdf(ikm, 42, salt, info) == expected_okm


def test_hkdf_output_length():
    key_material = b"shared secret from x25519"
    output = hkdf(key_material, 96, salt=b"psk", info=b"secure-channel")

    assert isinstance(output, bytes)
    assert len(output) == 96