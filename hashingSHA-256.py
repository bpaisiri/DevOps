import hashlib

# Function to generate SHA-256 hash of a message
def generate_sha256_hash(message):
    # Create a new SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the message encoded to bytes
    sha256_hash.update(message.encode('utf-8'))
    
    # Return the hexadecimal representation of the hash
    return sha256_hash.hexdigest()

# Function to check if a given message matches the expected hash
def verify_sha256_hash(message, expected_hash):
    # Generate the hash for the given message
    generated_hash = generate_sha256_hash(message)
    
    # Compare the generated hash with the expected hash
    return generated_hash == expected_hash

# Example Usage
if __name__ == "__main__":
    # Original message to be hashed
    message = "This is a secret message"
    
    # Generate the SHA-256 hash of the message
    hashed_message = generate_sha256_hash(message)
    print("Generated SHA-256 Hash:", hashed_message)
    
    # Verifying the hash by comparing it to the generated hash
    is_valid = verify_sha256_hash(message, hashed_message)
    
    if is_valid:
        print("The hash matches the message. Integrity is verified.")
    else:
        print("The hash does not match. Data integrity is compromised.")
