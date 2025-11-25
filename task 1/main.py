"""
Task 1 – Hybrid Encryption (RSA + AES)
--------------------------------------

Alice → Bob encrypted message flow:

1. Bob generates RSA key pair
2. Alice generates AES key
3. Alice encrypts message using AES-GCM
4. Alice encrypts AES key using Bob's RSA-OAEP
5. Bob decrypts AES key
6. Bob decrypts message
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --------------------------------------------------------------------
# 1. Bob generates RSA key pair
# --------------------------------------------------------------------

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # save private key
    with open("bob_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # save public key
    with open("bob_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("[+] Generated RSA key pair: bob_private.pem + bob_public.pem")
    return private_key, public_key


# --------------------------------------------------------------------
# 2. AES encryption (Alice encrypts message)
# --------------------------------------------------------------------

def aes_encrypt(plaintext: bytes):
    aes_key = os.urandom(32)      # AES-256 key
    nonce = os.urandom(12)        # GCM nonce

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return aes_key, nonce, ciphertext, encryptor.tag


# --------------------------------------------------------------------
# 3. Alice encrypts AES key using Bob's RSA public key
# --------------------------------------------------------------------

def encrypt_aes_key_with_rsa(aes_key: bytes, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


# --------------------------------------------------------------------
# 4. Bob decrypts AES key
# --------------------------------------------------------------------

def decrypt_aes_key_with_rsa(encrypted_key: bytes, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


# --------------------------------------------------------------------
# 5. Bob decrypts the AES-encrypted message
# --------------------------------------------------------------------

def aes_decrypt(aes_key, nonce, ciphertext, tag):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


# --------------------------------------------------------------------
# MAIN DEMO WORKFLOW
# --------------------------------------------------------------------

if __name__ == "__main__":
    # Step 1: Bob generates RSA keys
    bob_private, bob_public = generate_rsa_keys()

    # Step 2: Alice prepares message
    message = b"Hello Bob, this is a secure message using hybrid encryption."

    # Step 3: Alice encrypts using AES
    aes_key, nonce, ciphertext, tag = aes_encrypt(message)

    # Step 4: Alice encrypts AES key with RSA
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, bob_public)

    # Save encrypted outputs
    with open("encrypted_message.bin", "wb") as f:
        f.write(ciphertext)
    with open("aes_nonce.bin", "wb") as f:
        f.write(nonce)
    with open("aes_tag.bin", "wb") as f:
        f.write(tag)
    with open("encrypted_aes_key.bin", "wb") as f:
        f.write(encrypted_aes_key)

    print("[+] Encrypted message + encrypted AES key saved.")

    # Step 5: Bob decrypts AES key
    recovered_key = decrypt_aes_key_with_rsa(encrypted_aes_key, bob_private)

    # Step 6: Bob decrypts message
    decrypted_message = aes_decrypt(recovered_key, nonce, ciphertext, tag)

    print("[+] Decrypted message:", decrypted_message.decode())
