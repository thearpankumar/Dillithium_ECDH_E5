from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

class DoubleRatchet:
    def __init__(self, shared_secret, priv_key, pub_key):
        self.rk = shared_secret
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.ck = self.rk  # Initialize chain key with root key
        self.mk = None

    def ratchet_step(self):
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ratchet step',
            backend=default_backend()
        ).derive(
            self.priv_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ) + self.pub_key.public_bytes()
        )
        self.rk = shared_secret
        self.ck = self.rk  # Reset chain key with new root key

    def derive_message_key(self):
        # Derive message key
        hkdf_mk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'message key',
            backend=default_backend()
        )
        self.mk = hkdf_mk.derive(self.ck)

        # Update chain key
        hkdf_ck = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chain key',
            backend=default_backend()
        )
        self.ck = hkdf_ck.derive(self.ck)

        return self.mk


"""class DoubleRatchet:
    def __init__(self, shared_secret, priv_key, pub_key):
        self.rk = shared_secret
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.ck = self.rk  # Initialize chain key with root key
        self.mk = None

    def ratchet_step(self):
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ratchet step',
            backend=default_backend()
        ).derive(
            self.priv_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ) + self.pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )
        self.rk = shared_secret
        self.ck = self.rk  # Reset chain key with new root key

    def derive_message_key(self):
        # Derive message key
        hkdf_mk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'message key',
            backend=default_backend()
        )
        self.mk = hkdf_mk.derive(self.ck)

        # Update chain key
        hkdf_ck = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chain key',
            backend=default_backend()
        )
        self.ck = hkdf_ck.derive(self.ck)

        return self.mk
"""