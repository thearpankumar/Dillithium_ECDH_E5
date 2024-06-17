import json
import os
import socket
#from cryptography.hazmat.primitives.asymmetric import kyber
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
#from pqcrypto.kem.kyber1024 import generate_keypair
from dilithium.dilithium import Dilithium2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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


def verify_signature(public_key, signature, message):
    public_key.verify(signature, message)


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


# Generate client's keys
client_ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
client_ed25519_public_key = client_ed25519_private_key.public_key()

client_ecdh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
client_ecdh_public_key = client_ecdh_private_key.public_key()

# Assume Crystal Kyber and Crystal Dilithium keys are generated and handled similarly
client_kyber_public_key, client_kyber_private_key = Kyber1024.keygen()   # Replace with actual Kyber key generation
print("kyber key pair : ", client_kyber_public_key, client_kyber_private_key)
client_dilithium_private_key, client_dilithium_public_key = Dilithium2.keygen(os.urandom(32))  # Replace with actual Dilithium key generation
print("dilithium public key  : ", client_dilithium_public_key)

# Connect to server
server_address = ('localhost', 10000)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)

try:
    # Step 1: Send client's Ed25519 public key
    client_ed25519_data = json.dumps({
        "protocol": "Ed25519",
        "publicKey": client_ed25519_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    })
    sock.sendall(client_ed25519_data.encode())
    print("Sent client's Ed25519 public key")

    # Step 2: Receive server's Ed25519 public key
    server_ed25519_data = json.loads(sock.recv(4096).decode())
    server_ed25519_public_key = serialization.load_pem_public_key(bytes.fromhex(server_ed25519_data["publicKey"]),
                                                                  backend=default_backend())
    print("Received server's Ed25519 public key")

    # Step 3: Send client's ECDH public key (signed with Ed25519)
    ecdh_data = json.dumps({
        "protocol": "ECDH",
        "publicKey": client_ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    })
    signature = sign_message(client_ed25519_private_key, ecdh_data.encode())
    client_ecdh_data_signed = json.dumps({"data": ecdh_data, "signature": signature.hex()})
    sock.sendall(client_ecdh_data_signed.encode())
    print("Sent client's ECDH public key")

    # Step 4: Receive server's ECDH public key (signed with Ed25519)
    server_ecdh_data_signed = json.loads(sock.recv(4096).decode())
    server_ecdh_data = json.loads(server_ecdh_data_signed["data"])
    server_ecdh_public_key = serialization.load_pem_public_key(bytes.fromhex(server_ecdh_data["publicKey"]),
                                                               backend=default_backend())
    server_signature = bytes.fromhex(server_ecdh_data_signed["signature"])
    server_ed25519_public_key.verify(server_signature, server_ecdh_data_signed["data"].encode())
    print("Received and verified server's ECDH public key")

    # Derive shared secret 1 from ECDH
    shared_secret_1 = client_ecdh_private_key.exchange(ec.ECDH(), server_ecdh_public_key)
    shared_secret_1 = derive_key(shared_secret_1)
    print("Derived shared secret 1", shared_secret_1)

    # Step 5: Send client's Kyber public key (signed with Ed25519 and encrypted with AES)
    kyber_data = json.dumps({
        "protocol": "CrystalKyber",
        "publicKey": client_kyber_public_key.hex()
    })
    signature = sign_message(client_ed25519_private_key, kyber_data.encode())
    print("signature : ", signature)
    encrypted_kyber_data = aes_encrypt(shared_secret_1, json.dumps({"data": kyber_data, "signature": signature.hex()}).encode())
    print("encrypted kyber data : ", encrypted_kyber_data)
    sock.sendall(encrypted_kyber_data)
    print("Sent client's Kyber public key")

    # Step 6: Receive server's Kyber public key
    encrypted_kyber_data = sock.recv(4096)
    decrypted_kyber_data = json.loads(aes_decrypt(shared_secret_1, encrypted_kyber_data).decode())
    server_kyber_data = json.loads(decrypted_kyber_data["data"])
    server_kyber_signature = bytes.fromhex(decrypted_kyber_data["signature"])
    server_ed25519_public_key.verify(server_kyber_signature, json.dumps(server_kyber_data).encode())
    server_kyber_public_key = bytes.fromhex(server_kyber_data["publicKey"])
    print("Received and verified server's Kyber public key")

    # Step 7: Send client's Kyber cipher (signed with Ed25519 and encrypted with AES)
    kyber_cipher_data = {
        "protocol": "CrystalKyber",
        "cipher": client_kyber_public_key.hex()  # Replace with actual Kyber encryption
    }
    kyber_cipher_data_json = json.dumps(kyber_cipher_data)
    signature = sign_message(client_ed25519_private_key, kyber_cipher_data_json.encode())
    encrypted_kyber_cipher_data = aes_encrypt(shared_secret_1, json.dumps(
        {"data": kyber_cipher_data, "signature": signature.hex()}).encode())
    sock.sendall(encrypted_kyber_cipher_data)
    print("Sent client's Kyber cipher")

    # Step 8: Receive server's Kyber cipher (signed with Ed25519 and encrypted with AES)
    server_kyber_cipher_encrypted = sock.recv(4096)
    server_kyber_cipher_data_signed = aes_decrypt(shared_secret_1, server_kyber_cipher_encrypted)
    server_kyber_cipher_json = json.loads(server_kyber_cipher_data_signed)

    # Ensure `server_kyber_cipher_json["data"]` is correctly parsed if it's a JSON string
    server_kyber_data = json.loads(server_kyber_cipher_json["data"]) if isinstance(server_kyber_cipher_json["data"],
                                                                                   str) else server_kyber_cipher_json["data"]

    # Extract the cipher and signature
    server_kyber_cipher = bytes.fromhex(server_kyber_data["cipher"])
    server_signature = bytes.fromhex(server_kyber_cipher_json["signature"])

    # Verify the signature
    server_ed25519_public_key.verify(server_signature, json.dumps(server_kyber_data).encode())
    print("Received and verified server's Kyber cipher")

    # Derive shared secret 2 from Kyber
    print(len(server_kyber_public_key))

    #shared_secret_2 = client_ecdh_private_key.exchange(ec.ECDH(), server_ecdh_public_key)  # This should be replaced with actual Kyber key exchange
    #shared_secret_2 = derive_key(shared_secret_2)
    shared_secret_2 =shared_secret_1
    print("Derived shared secret 2", shared_secret_2)

    # Step 9: Send client's Dilithium signature (signed with Ed25519 and encrypted with AES)
    dilithium_data = json.dumps({
        "protocol": "CrystalDilithium",
        "publicKey": client_dilithium_public_key.hex()
    })
    signature = sign_message(client_ed25519_private_key, dilithium_data.encode())
    print("signature: ", signature)
    encrypted_dilithium_data = aes_encrypt(shared_secret_2,
                                           json.dumps({"data": dilithium_data, "signature": signature}).encode())
    print("encrypted dilithium data: ", encrypted_dilithium_data)
    sock.sendall(encrypted_dilithium_data)
    print("Sent client's Dilithium signature")

    """# Step 10: Receive server's Dilithium signature (signed with Ed25519 and encrypted with new shared secret)
    server_dilithium_encrypted_data = sock.recv(4096)
    server_dilithium_data_signed = aes_decrypt(shared_secret_2, server_dilithium_encrypted_data)
    server_dilithium_json = json.loads(server_dilithium_data_signed)
    server_dilithium_signature = bytes.fromhex(server_dilithium_json["data"]["signature"])
    server_signature = bytes.fromhex(server_dilithium_json["signature"])
    server_ed25519_public_key.verify(server_signature, server_dilithium_json["data"].encode())
    print("Received and verified server's Dilithium signature")

    # Step 11: Send data message (signed with both Ed25519 and Dilithium, encrypted with new shared secret)
    data = json.dumps({"message": "Client message"})
    ed25519_signature = sign_message(client_ed25519_private_key, data.encode())
    # Assume Dilithium signing function
    # dilithium_signature = sign_dilithium_message(client_dilithium_private_key, data.encode())
    data_json = json.dumps({
        "data": data,
        "signatures": {
            "Ed25519": ed25519_signature.hex(),
            # "Dilithium": dilithium_signature.hex()
        }
    })
    encrypted_data = aes_encrypt(shared_secret_2, data_json.encode())
    sock.sendall(encrypted_data)
    print("Sent data message")

    # Step 12: Receive data response (signed with both Ed25519 and Dilithium, encrypted with new shared secret)
    response_encrypted = sock.recv(4096)
    response_signed = aes_decrypt(shared_secret_2, response_encrypted)
    response_json = json.loads(response_signed)
    response_data = json.loads(response_json["data"])
    signatures = response_json["signatures"]
    verify_signature(server_ed25519_public_key, bytes.fromhex(signatures["Ed25519"]), response_data["data"].encode())
    # Assume Dilithium verification function
    # verify_dilithium_signature(server_dilithium_public_key, bytes.fromhex(signatures["Dilithium"]), response_data["data"].encode())
    print(f"Received response: {response_data['data']}")"""

finally:
    sock.close()
    print("Connection closed")
