from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class derived_func:
    @staticmethod
    def derive_key(shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def sign_message(private_key, message):
        return private_key.sign(message)

    @staticmethod
    def verify_signature(public_key, signature, message):
        public_key.verify(signature, message)

    @staticmethod
    def aes_encrypt(key, data):
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(b"")
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    @staticmethod
    def aes_decrypt(key, data):
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(b"")
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def encode_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PEM
        )

    @staticmethod
    def decode_public_key(public_bytes):
        return Ed25519PublicKey.from_public_bytes(public_bytes)
