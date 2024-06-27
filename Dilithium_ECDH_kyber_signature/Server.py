import socket
import json
from dilithium.dilithium import Dilithium2
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from Kyber import Kyber1024


# Helper functions
def derive_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


def sign_message(private_key, message):
    return private_key.sign(message)


def verify_signature(public_key, countersignature, message):
    public_key.verify(countersignature, message)


def aes_encrypt(key, data):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(b"")
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext


def aes_decrypt(key, data):
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(b"")
    return decryptor.update(ciphertext) + decryptor.finalize()


# Generate server's keys
server_ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
server_ed25519_public_key = server_ed25519_private_key.public_key()

server_ecdh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
server_ecdh_public_key = server_ecdh_private_key.public_key()

# Assume Crystal Kyber and Crystal Dilithium keys are generated and handled similarly

server_kyber_public_key, server_kyber_private_key = Kyber1024.keygen()  # Replace with actual Kyber key generation
server_dilithium_private_key, server_dilithium_public_key = Dilithium2.keygen(
    os.urandom(32))  # Replace with actual Dilithium key generation
#print(server_dilithium_public_key)
# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 10000))
server_socket.listen(1)
print("Server listening on ('localhost', 10000)")

while True:
    connection, client_address = server_socket.accept()
    try:
        print(f"Connection established with {client_address}")

        # Step 1: Receive client's Ed25519 public key
        client_ed25519_data = json.loads(connection.recv(4096).decode())
        client_ed25519_public_key = serialization.load_pem_public_key(bytes.fromhex(client_ed25519_data["publicKey"]),
                                                                      backend=default_backend())
        print("Received client's Ed25519 public key")

        # Step 2: Send server's Ed25519 public key
        server_ed25519_data = json.dumps({
            "protocol": "Ed25519",
            "publicKey": server_ed25519_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
        })
        connection.sendall(server_ed25519_data.encode())
        print("Sent server's Ed25519 public key")

        # Step 3: Receive client's ECDH public key (signed with Ed25519)
        client_ecdh_data_signed = json.loads(connection.recv(4096).decode())
        client_ecdh_data = json.loads(client_ecdh_data_signed["data"])
        client_ecdh_public_key = serialization.load_pem_public_key(bytes.fromhex(client_ecdh_data["publicKey"]),
                                                                   backend=default_backend())
        client_signature = bytes.fromhex(client_ecdh_data_signed["signature"])
        client_ed25519_public_key.verify(client_signature, client_ecdh_data_signed["data"].encode())
        print("Received and verified client's ECDH public key")

        # Step 4: Send server's ECDH public key (signed with Ed25519)
        ecdh_data = json.dumps({
            "protocol": "ECDH",
            "publicKey": server_ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
        })
        signature = sign_message(server_ed25519_private_key, ecdh_data.encode())
        server_ecdh_data_signed = json.dumps({"data": ecdh_data, "signature": signature.hex()})
        connection.sendall(server_ecdh_data_signed.encode())
        print(f"Sent server's ECDH public key: {server_ecdh_data_signed}")

        # Derive shared secret 1 from ECDH
        shared_secret_1 = server_ecdh_private_key.exchange(ec.ECDH(), client_ecdh_public_key)
        shared_secret_1 = derive_key(shared_secret_1)
        print("Derived shared secret 1", shared_secret_1)

        # Step 5: Receive client's Kyber public key (signed with Ed25519 and encrypted with AES)
        encrypted_kyber_data = connection.recv(4096)
        decrypted_kyber_data = json.loads(aes_decrypt(shared_secret_1, encrypted_kyber_data).decode())
        client_kyber_data = json.loads(decrypted_kyber_data["data"])
        client_kyber_signature = bytes.fromhex(decrypted_kyber_data["signature"])
        client_ed25519_public_key.verify(client_kyber_signature, json.dumps(client_kyber_data).encode())
        client_kyber_public_key = bytes.fromhex(client_kyber_data["publicKey"])
        print("Received and verified client's Kyber public key")

        # Step 6: Send server's Kyber public key (signed with Ed25519 and encrypted with AES)
        kyber_data = json.dumps({
            "protocol": "CrystalKyber",
            "publicKey": server_kyber_public_key.hex()
        })
        signature = sign_message(server_ed25519_private_key, kyber_data.encode())
        encrypted_kyber_data = aes_encrypt(shared_secret_1,
                                           json.dumps({"data": kyber_data, "signature": signature.hex()}).encode())
        connection.sendall(encrypted_kyber_data)
        print("Sent server's Kyber public key")

        # Step 7 : Receive client's Kyber cipher (signed with Ed25519 and encrypted with AES)
        client_kyber_cipher_encrypted = connection.recv(4096)
        client_kyber_cipher_data_signed = aes_decrypt(shared_secret_1, client_kyber_cipher_encrypted)
        client_kyber_cipher_json = json.loads(client_kyber_cipher_data_signed)
        client_kyber_data = client_kyber_cipher_json["data"]
        client_kyber_cipher = bytes.fromhex(client_kyber_data["cipher"])
        client_signature = bytes.fromhex(client_kyber_cipher_json["signature"])
        client_ed25519_public_key.verify(client_signature, json.dumps(client_kyber_data).encode())
        print("Received and verified client's Kyber cipher")

        Cipher_kyber_Server, shared_secret_2 = Kyber1024.enc(client_kyber_public_key)
        # Step 8: Send server's Kyber cipher (signed with Ed25519 and encrypted with AES)
        print("Server kyber shared secret : ", shared_secret_2)
        kyber_cipher_data = json.dumps({
            "protocol": "CrystalKyber",
            "cipher": Cipher_kyber_Server.hex()  # Replace with actual Kyber encryption
        })
        signature = sign_message(server_ed25519_private_key, kyber_cipher_data.encode())
        encrypted_kyber_cipher_data = aes_encrypt(shared_secret_1, json.dumps(
            {"data": kyber_cipher_data, "signature": signature.hex()}).encode())
        connection.sendall(encrypted_kyber_cipher_data)
        print("Sent server's Kyber cipher")

        client_shared_secret = Kyber1024.dec(client_kyber_cipher, server_kyber_private_key)
        print("Derived client shared secret 2", client_shared_secret, "Cipher key is", client_kyber_cipher)

        # Step 9: Receive client's Dilithium signature (signed with Ed25519 and encrypted with AES)
        client_dilithium_encrypted = connection.recv(5500)
        print("Client dilithium encrypted data: ", client_dilithium_encrypted)
        client_dilithium_data_signed = aes_decrypt(shared_secret_1, client_dilithium_encrypted).decode()
        client_dilithium_publickey_json = json.loads(client_dilithium_data_signed)
        client_dilithium_data = client_dilithium_publickey_json["data"]
        client_dilithium_publickey = bytes.fromhex(client_dilithium_data["publicKey"])
        dilithium_client_signature = bytes.fromhex(client_dilithium_publickey_json["signature"])

        # Verify the signature
        client_ed25519_public_key.verify(
            dilithium_client_signature,
            json.dumps(client_dilithium_data).encode()
        )
        print("Received and verified client's Dilithium PublicKey")

        # Step 10: Send server's Dilithium signature (signed with Ed25519 and encrypted with new shared secret)
        dilithium_data = json.dumps({
            "protocol": "CrystalDilithium",
            "publicKey": server_dilithium_public_key.hex()  # Replace with actual Dilithium public key
        })
        signature = sign_message(server_ed25519_private_key, dilithium_data.encode())
        encrypted_dilithium_data = aes_encrypt(shared_secret_1, json.dumps(
            {"data": dilithium_data, "signature": signature.hex()}).encode())
        connection.sendall(encrypted_dilithium_data)
        print("Sent server's Dilithium public key")

        # Step 11: Receive data message (signed with both Ed25519 and Dilithium, encrypted with new shared secret)
        data_encrypted = connection.recv(4096)
        data_signed = aes_decrypt(shared_secret_1, data_encrypted)
        print(f"Server: decrypted data signed: {data_signed}")

        # Extract the actual data before verification
        data_json = json.loads(data_signed)
        data = json.loads(data_json["data"])
        signatures = data_json["signatures"]
        ed25519_signature = signatures["Ed25519"]
        print(f"Server: received data: {data}")
        print(f"Server: received Ed25519 signature: {ed25519_signature}")
        #verify_signature(client_ed25519_public_key, ed25519_signature, data)

        # Step 12: Send data response (signed with both Ed25519 and Dilithium, encrypted with new shared secret)
        response_data = json.dumps({"data": "Server response message"})
        ed25519_signature = sign_message(server_ed25519_private_key, response_data.encode())
        # Assume Dilithium signing function
        # dilithium_signature = sign_dilithium_message(server_dilithium_private_key, response_data.encode())
        response_json = json.dumps({
            "data": response_data,
            "signatures": {
                "Ed25519": ed25519_signature.hex(),
                # "Dilithium": dilithium_signature.hex()
            }
        })
        encrypted_response = aes_encrypt(shared_secret_1, response_json.encode())
        connection.sendall(encrypted_response)
        print("Sent data response")

    finally:
        connection.close()
        print("Connection closed")
