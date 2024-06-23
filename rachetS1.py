import base64
import socket
import json
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def deserialize_key(serialized_key):
    key_data = json.loads(serialized_key)
    if key_data.get("protocol") != "X25519":
        raise ValueError("Unsupported key protocol")
    return serialization.load_pem_public_key(bytes.fromhex(key_data.get("publicKey")),
                                             backend=default_backend())


def pad(msg):
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)


def unpad(msg):
    return msg[:-msg[-1]]


def b64(msg):
    return base64.encodebytes(msg).decode('utf-8').strip()


def hkdf(inp, length):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


class Alice(object):
    def __init__(self):
        self.base64cipher = None
        self.IKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()
        self.DHratchet = None

    def serialize_public_keys(self):
        self.IKa_public_bytes = json.dumps({
            "protocol": "X25519",
            "publicKey": self.IKa.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        })
        self.EKa_public_bytes = json.dumps({
            "protocol": "X25519",
            "publicKey": self.EKa.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        })
        self.DHratchet_bytes = json.dumps({
            "protocol": "X25519",
            "publicKey": self.DHratchet.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        })

    def x3dh(self, SPKb, IKb, OPKb):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.IKa.exchange(SPKb)
        dh2 = self.EKa.exchange(IKb)
        dh3 = self.EKa.exchange(SPKb)
        dh4 = self.EKa.exchange(OPKb)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key:', b64(self.sk))

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, bob_public):
        # perform a DH ratchet rotation using Bob's public key
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(bob_public)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(bob_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))
        return self.DHratchet.public_key()

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        return b64(cipher)
        # bob.recv(cipher, self.DHratchet.public_key())

    def recv(self, cipher, bob_public_key):
        self.dh_ratchet(bob_public_key)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message:', msg)


alice = Alice()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server listening on ('localhost', 12345)")


def recv_exactly(sock, num_bytes):
    buf = b''
    while len(buf) < num_bytes:
        data = sock.recv(num_bytes - len(buf))
        if not data:
            raise ConnectionError("Socket connection closed unexpectedly")
        buf += data
    return buf


while True:
    print('Waiting for connection...')
    connection, client_address = server_socket.accept()
    try:
        print('Connection from', client_address)

        serialized_keys = []
        for _ in range(4):
            length_bytes = recv_exactly(connection, 4)
            length = int.from_bytes(length_bytes, byteorder='big')
            key_bytes = recv_exactly(connection, length)
            serialized_keys.append(key_bytes.decode())

        alice.IKb, alice.SPKb, alice.OPKb, alice.DHratchetb = [deserialize_key(k) for k in serialized_keys]
        """print(
            f"Ikb : {alice.IKb.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        print(
            f"Spkb : {alice.SPKb.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        print(
            f"Opkb : {alice.OPKb.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        print(
            f"DHratchetb : {alice.DHratchetb.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        print("Received Bob's serialized keys:")"""
        # print(serialized_keys)


        alice.x3dh(alice.SPKb, alice.IKb, alice.OPKb)
        alice.init_ratchets()
        alice.dh_ratchet(alice.DHratchetb)
        alice.serialize_public_keys()

        serialized_keys = [
            alice.IKa_public_bytes,
            alice.EKa_public_bytes,
            alice.DHratchet_bytes
        ]
        #print("Sending Alice's serialized keys:")
        for key_bytes in serialized_keys:
            length_bytes = len(key_bytes).to_bytes(4, byteorder='big')
            connection.sendall(length_bytes + key_bytes.encode())

        """print(
            f"Ika : {alice.IKa.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        print(
            f"EKa : {alice.EKa.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        print(f"DHratcheta : {alice.DHratchet.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
        """
        sending = alice.send(b'Hello Bob!')
        connection.sendall(sending.encode())
        print(f"Sent message: {sending}")

        message = connection.recv(4096)
        #print(f"Received message: {message.decode()}")
        #print(f"b64 decoded message: {base64.b64decode(message.decode())}")
        alice.recv(base64.b64decode(message.decode()), alice.DHratchetb)

    finally:
        connection.close()
