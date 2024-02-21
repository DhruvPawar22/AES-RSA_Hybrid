from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import timeit

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
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=get_random_bytes(AES.block_size))
    encryption_time = timeit.timeit(lambda: cipher_aes.encrypt(data.encode()), number=1)
    return cipher_aes.encrypt(data.encode()), encryption_time

def decrypt_with_aes(ciphertext, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=get_random_bytes(AES.block_size))
    decryption_time = timeit.timeit(lambda: cipher_aes.decrypt(ciphertext), number=1)
    return cipher_aes.decrypt(ciphertext), decryption_time

# Example Usage:
if __name__ == "__main__":
    
    #Generate RSA Key Pair
    private_key, public_key = generate_rsa_key_pair()

    #Generate AES Key
    aes_key = get_random_bytes(16)  # 128 bits (16 bytes) key

    #Encrypt AES Key with RSA Public Key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
  
    plaintext_data = input("Enter plaintext data: ")

    # Recipient's side:
    #Decrypt AES Key with RSA Private Key
    recipient_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Use AES Key for Encryption and Decryption
    encrypted_data, encryption_time = encrypt_with_aes(plaintext_data, decrypted_aes_key)

    if encrypted_data is not None:
        decrypted_data, decryption_time = decrypt_with_aes(encrypted_data, decrypted_aes_key)

        print("\nOriginal Data:", plaintext_data)
        print("Encrypted Data:", encrypted_data)
        print("Decrypted Data (Hex):", decrypted_data.hex())
        print("\nEncryption Time:", encryption_time, "seconds")
        print("Decryption Time:", decryption_time, "seconds")
