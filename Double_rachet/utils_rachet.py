import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519

def b64_encode(msg):
    # base64 encoding helper function
    return base64.b64encode(msg)

def b64_decode(msg):
	# base64 decoding helper function
	return base64.b64decode(msg)


def pad(msg):
    # pkcs7 padding
    msg = bytes(msg,'ascii')
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]


def hkdf(inp, length):
    # use HKDF on an input to derive a key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)


def pk_to_bytes(pk_obj):
    return  pk_obj.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)


def byte_to_pk(byte):
    return x25519.X25519PublicKey.from_public_bytes(byte)
