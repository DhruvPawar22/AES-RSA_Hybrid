from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    recipient_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def encrypt_with_aes(data, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    start_time = time.time()
    ciphertext = cipher_aes.encrypt(pad(data.encode(), AES.block_size))
    encryption_time = time.time() - start_time
    return ciphertext, encryption_time

def decrypt_with_aes(ciphertext, aes_key):
    decipher_aes = AES.new(aes_key, AES.MODE_CBC)
    start_time = time.time()
    decrypted_data = unpad(decipher_aes.decrypt(ciphertext), AES.block_size)
    decryption_time = time.time() - start_time
    return decrypted_data.decode(), decryption_time

# Example Usage:
if __name__ == "__main__":
    # Step 1: Generate RSA Key Pair
    private_key, public_key = generate_rsa_key_pair()

    # Step 2: Generate AES Key
    aes_key = get_random_bytes(16)  # 128 bits (16 bytes) key

    # Step 3: Encrypt AES Key with RSA Public Key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

    # Simulate transmitting the public key and encrypted AES key to the recipient
    # ...

    # Get plaintext data as input
    plaintext_data = input("Enter plaintext data: ")

    # Recipient's side:
    # Step 4: Decrypt AES Key with RSA Private Key
    recipient_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Step 5: Use AES Key for Encryption and Decryption
    encrypted_data, encryption_time = encrypt_with_aes(plaintext_data, decrypted_aes_key)
    decrypted_data, decryption_time = decrypt_with_aes(encrypted_data, decrypted_aes_key)

    print("\nOriginal Data:", plaintext_data)
    print("Encrypted Data:", encrypted_data)
    print("Decrypted Data:", decrypted_data)
    print("\nEncryption Time:", encryption_time, "seconds")
    print("Decryption Time:", decryption_time, "seconds")
