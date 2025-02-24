from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Function to encrypt a message
def encrypt_message(message: str, key: bytes) -> bytes:
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the message to make its length a multiple of block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    return iv + encrypted_message  # Returning IV + encrypted message (IV needed for decryption)

# Function to decrypt a message
def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    # Extract IV from the first 16 bytes
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the message
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(decrypted_message) + unpadder.finalize()
    
    return message.decode()

# Example usage
if __name__ == "__main__":
    # Generate a random key (16 bytes for AES-128)
    key = os.urandom(16)
    
    # Message to encrypt
    original_message = "This is a secret message!"
    print("Original message:", original_message)
    
    # Encrypt the message
    encrypted_message = encrypt_message(original_message, key)
    print("Encrypted message (in bytes):", encrypted_message)

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted message:", decrypted_message)
