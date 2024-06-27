import hashlib
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class DoubleRatchet:
    def __init__(self, shared_secret):
        self.rk = shared_secret
        self.skipped_message_keys = []
        self.previous_chain_key = b'\x00' * 32
        self.chain_key = b'\x00' * 32
        self.send_message_keys = []
        self.recv_message_keys = []
        self.Ns = 0
        self.Nr = 0
        self.encryptor = None
        self.decryptor = None

    def derive_message_key(self):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'message key',
            backend=default_backend()
        )
        return hkdf.derive(self.chain_key)

    def next_send(self):
        if len(self.send_message_keys) == 0:
            self.ratchet_step()
        mk = self.send_message_keys.pop(0)
        self.Ns += 1
        return mk

    def next_recv(self):
        if len(self.recv_message_keys) == 0:
            self.ratchet_step()
        mk = self.recv_message_keys.pop(0)
        self.Nr += 1
        return mk

    def ratchet_step(self):
        rk = hashlib.sha256(self.rk).digest()
        mk = self.derive_message_key()
        ck = self.chain_key
        self.chain_key = hashlib.sha256(ck).digest()
        if self.Ns > 0:
            self.send_message_keys.append(mk)
        if self.Nr == 0:
            self.previous_chain_key = ck
        elif self.Nr > 0 and self.Ns > 0:
            self.skipped_message_keys.append(mk)
        self.Ns = 0
        self.Nr = 0

    def encrypt_message(self, message):
        if self.encryptor is None:
            mk = self.next_send()
            iv = os.urandom(12)
            encryptor = Cipher(algorithms.AES(mk), modes.GCM(iv), backend=default_backend()).encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag
            self.encryptor = (iv, tag)
        else:
            iv, tag = self.encryptor
            encryptor = Cipher(algorithms.AES(mk), modes.GCM(iv, tag), backend=default_backend()).encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag
            self.encryptor = (iv, tag)
        return iv + tag + ciphertext

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        if self.decryptor is None:
            mk = self.next_recv()
            decryptor = Cipher(algorithms.AES(mk), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            self.decryptor = (iv, tag)
        else:
            iv, tag = self.decryptor
            decryptor = Cipher(algorithms.AES(mk), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            self.decryptor = (iv, tag)
        return plaintext
