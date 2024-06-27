import socket
import json
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Crypto.Cipher import AES

CYPHER = None


def serialize_key(key):
    return json.dumps({
        "protocol": "X25519",
        "publicKey": key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
    })


def deserialize_key(serialized_key):
    key_data = json.loads(serialized_key)
    if key_data.get("protocol") != "X25519":
        raise ValueError("Unsupported key protocol")
    public_key_hex = key_data.get("publicKey")
    if public_key_hex == "NO":
        return None
    return serialization.load_pem_public_key(bytes.fromhex(public_key_hex),
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


class Bob(object):
    def __init__(self):
        self.IKb_public_bytes = None
        self.IKb = X25519PrivateKey.generate()
        self.SPKb = X25519PrivateKey.generate()
        self.OPKb = X25519PrivateKey.generate()
        self.DHratchet = X25519PrivateKey.generate()
        self.base64cypher = None

    def serialize_public_keys(self):
        self.IKb_public_bytes = serialize_key(self.IKb)
        self.SPKb_public_bytes = serialize_key(self.SPKb)
        self.OPKb_public_bytes = serialize_key(self.OPKb)
        self.DHratchet_public_bytes = serialize_key(self.DHratchet)

    def x3dh(self, Ika, Eka):
        dh1 = self.SPKb.exchange(Ika)
        dh2 = self.IKb.exchange(Eka)
        dh3 = self.SPKb.exchange(Eka)
        dh4 = self.OPKb.exchange(Eka)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key:', b64(self.sk))

    def init_ratchets(self):
        self.root_ratchet = SymmRatchet(self.sk)
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, alice_public):
        if alice_public is None:
            return
        dh_recv = self.DHratchet.exchange(alice_public)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        return b64(cipher)

    def recv(self, cipher, alice_public_key):
        self.dh_ratchet(alice_public_key)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message:', msg)


bob = Bob()
bob.serialize_public_keys()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

serialized_keys = [
    bob.IKb_public_bytes,
    bob.SPKb_public_bytes,
    bob.OPKb_public_bytes,
    bob.DHratchet_public_bytes
]
#print("Sending Bob's serialized keys:")

for key_bytes in serialized_keys:
    length_bytes = len(key_bytes).to_bytes(4, byteorder='big')
    client_socket.sendall(length_bytes + key_bytes.encode())
"""print(f"Ikb : {bob.IKb.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
print(f"SPKb : {bob.SPKb.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
print(f"DHratchet : {bob.DHratchet.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
print(f"Opkb : {bob.OPKb.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
"""

def recv_exactly(sock, num_bytes):
    buf = b''
    while len(buf) < num_bytes:
        data = sock.recv(num_bytes - len(buf))
        if not data:
            raise ConnectionError("Socket connection closed unexpectedly")
        buf += data
    return buf


received_keys = []
for _ in range(3):
    length_bytes = recv_exactly(client_socket, 4)
    length = int.from_bytes(length_bytes, byteorder='big')
    key_bytes = recv_exactly(client_socket, length)
    received_keys.append(key_bytes.decode())

#print("Received Alice's serialized keys:")

try:
    bob.Ika, bob.Eka, bob.DHratcheta = [deserialize_key(key) for key in received_keys]
except ValueError as e:
    print(f"Deserialization error: {e}")

"""print("Deserialized keys:")
print(f"Ika: {bob.Ika.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
print(f"Eka: {bob.Eka.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
print(f"DHratcheta: {bob.DHratcheta.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}")
"""
bob.x3dh(bob.Ika, bob.Eka)
bob.init_ratchets()
message = client_socket.recv(4096).decode()

if message == "NONE":
    print("No message received from the server")
else:
    print(f"Received message: {message}")
    bob.recv(base64.b64decode(message), bob.DHratcheta)
sending = bob.send(b'Hello to you too, Alice!')
print(f"without base64 encoded message: {base64.b64decode(sending)}")
client_socket.sendall(sending.encode())
print(f"Sent message: {sending}")
client_socket.close()
