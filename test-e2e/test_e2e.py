import base64
from Crypto.Cipher import AES
import requests
import pytest


@pytest.fixture
def base_url(request):
    return request.config.getoption("--url")


@pytest.fixture
def msg():
    return b"foobar 123"


def test_ping(base_url):
    assert requests.get(f"{base_url}/ping").json() == "pong"


@pytest.mark.parametrize("mode", ["128", "192", "256"])
@pytest.mark.parametrize("aad", [b"aad123", None])
def test_answer(mode, aad, base_url, msg):
    enc = requests.post(
        f"{base_url}/aes-gcm/encrypt?bits={mode}",
        json={"msg": base64.b64encode(msg).decode()}
        | ({"aad": base64.b64encode(aad).decode()} if aad else {}),
    ).json()
    enc = {k: base64.b64decode(v) for k, v in enc.items()}
    cipher = AES.new(enc["key"], AES.MODE_GCM, nonce=enc["nonce"])
    if aad:
        cipher.update(aad)

    assert cipher.decrypt_and_verify(enc["ciphertext"], enc["tag"]) == msg

    dec = requests.post(
        f"{base_url}/aes-gcm/decrypt?bits={mode}",
        json={k: base64.b64encode(v).decode() for k, v in enc.items()}
        | ({"aad": base64.b64encode(aad).decode()} if aad else {}),
    ).json()
    dec = {k: base64.b64decode(v) for k, v in dec.items()}
    assert dec["msg"] == msg
