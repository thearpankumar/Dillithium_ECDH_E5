import ast
import socket
import time

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from utils_rachet import *

PORT = 7976
SERVER = "127.0.0.1"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"
ROOT_KEY = b"o\x99\xa1\xdd@#\xc0\x0b \xec\xf5\x80GI\xbf\xca\x8b\x16}L;j\x02f\x07'\x88\x8f\x816e4"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)


class SymmetricRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey = output[32:64]
        iv = output[64:]
        return outkey, iv


class Client(object):
    def __init__(self):
        self.DHratchet = X25519PrivateKey.generate()
        self.sk = ROOT_KEY
        self.alice_pk = None

    def init_ratchets(self):
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self):
        if self.alice_pk is None:
            print("Error: alice_pk is not set.")
            return

        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(self.alice_pk)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print("\n** Key State **")
        print(f"Diffie Hellman Key: {str(b64_encode(dh_send), 'utf-8')}")
        print('Send ratchet seed:', str(b64_encode(shared_send), 'utf-8'))

    def receive_ratchet(self, alice_pk):
        dh_recv = self.DHratchet.exchange(alice_pk)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print("\n** Key State **")
        print(f"Diffie Hellman Key: {str(b64_encode(dh_recv), 'utf-8')}")
        print('Recv ratchet seed:', str(b64_encode(shared_recv), 'utf-8'))

    def enc(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print(f"\nSend Cipher: {str(b64_encode(cipher), 'utf-8')}")
        return cipher, self.DHratchet.public_key()

    def dec(self, cipher, alice_pk):
        print(f"\nRecv Cipher: {str(b64_encode(cipher), 'utf-8')}")

        self.receive_ratchet(alice_pk)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print(str(msg, 'utf-8'))
        return str(msg, 'utf-8')


alice = Client()
alice.init_ratchets()

pk_obj = alice.DHratchet.public_key()
init_pk = pk_obj.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

while True:
    try:
        message = client.recv(2048).decode(FORMAT)

        if message == 'NICKNAME':
            init_server_msg = input("Enter your name: ")
            client.send(init_server_msg.encode('utf-8'))
            client.send(init_pk)

        elif message[0:1] == "[":
            available_users = ast.literal_eval(message)
            print(available_users)

        elif message[0:2] == "b'" or message[0:2] == 'b"':
            if message[-2] == "=":
                byte_msg = ast.literal_eval(message)
                decode_msg = b64_decode(byte_msg)
                out = alice.dec(decode_msg, alice.alice_pk)
                print(out)
            else:
                mes = ast.literal_eval(message)
                alice.alice_pk = x25519.X25519PublicKey.from_public_bytes(mes)
                print("PK received")
        else:
            print(message)

        # Allow user to send messages
        user_input = input("Your message: ")
        alice.dh_ratchet()
        cipher, pk = alice.enc(user_input)
        pk_byte = pk_to_bytes(pk)
        client.send(str(pk_byte).encode('utf-8'))
        time.sleep(0.5)
        c = b64_encode(cipher)
        client.send(str(c).encode('utf-8'))

    except Exception as e:
        print("An error occurred:", e)
        client.close()
        break
