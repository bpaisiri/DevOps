from PIL import Image
import numpy as np

# Function to encode the message into the image
def encode_image(image_path, message, output_image_path):
    # Open the image
    img = Image.open(image_path)
    img = img.convert('RGB')
    
    # Convert the message into binary format
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    
    # Ensure the image is large enough to hold the message
    img_data = np.array(img)
    max_message_length = img_data.size // 8
    
    if len(binary_message) > max_message_length:
        raise ValueError("Message is too long to hide in this image.")
    
    # Encode the message in the image using LSB
    data_idx = 0
    for row in img_data:
        for pixel in row:
            for i in range(3):  # R, G, B channels
                if data_idx < len(binary_message):
                    pixel[i] = int(format(pixel[i], '08b')[:-1] + binary_message[data_idx], 2)
                    data_idx += 1
            if data_idx >= len(binary_message):
                break
        if data_idx >= len(binary_message):
            break

    # Save the modified image
    modified_img = Image.fromarray(img_data)
    modified_img.save(output_image_path)

# Function to decode the message from the image
def decode_image(image_path):
    # Open the image
    img = Image.open(image_path)
    img = img.convert('RGB')
    
    # Get image data
    img_data = np.array(img)
    
    # Extract binary data from the image using LSB
    binary_message = ""
    for row in img_data:
        for pixel in row:
            for i in range(3):  # R, G, B channels
                binary_message += format(pixel[i], '08b')[-1]  # Extract the LSB
    
    # Find the delimiter of the message (the null character '\0')
    message_end = binary_message.find('00000000')  # null byte
    if message_end != -1:
        binary_message = binary_message[:message_end]
    
    # Convert binary to string
    message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
    return message

# Example Usage
if __name__ == "__main__":
    # Message to encode
    secret_message = "This is a secret message!"
    
    # Encoding the message into an image
    encode_image('input_image.png', secret_message, 'encoded_image.png')
    print("Message encoded successfully.")
    
    # Decoding the message from the encoded image
    decoded_message = decode_image('encoded_image.png')
    print("Decoded Message:", decoded_message)
