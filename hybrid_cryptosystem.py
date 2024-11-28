from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# Create the Polybius square
def create_polybius_square():
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Exclude 'J'
    square = {}
    row, col = 1, 1
    for char in alphabet:
        square[char] = (row, col)
        col += 1
        if col > 5:
            col = 1
            row += 1
    return square

# Encrypt using the Polybius cipher
def polybius_encrypt(plaintext, square):
    polybius_text = ""
    for char in plaintext.upper():
        if char == "J":
            char = "I"  # Map 'J' to 'I'
        if char in square:
            row, col = square[char]
            polybius_text += str(row) + str(col) + " "
        elif char.isspace():
            polybius_text += "  "  # Preserve spaces by adding double space
        else:
            polybius_text += char  # Preserve other characters
    return polybius_text.strip()

# Decrypt using the Polybius cipher
def polybius_decrypt(polybius_text, square):
    reverse_square = {v: k for k, v in square.items()}
    plaintext = ""
    for pair in polybius_text.split(" "):
        if pair == "":  # Handle extra spaces
            plaintext += " "
        elif len(pair) == 2 and pair.isdigit():
            row, col = int(pair[0]), int(pair[1])
            char = reverse_square.get((row, col), "")
            plaintext += char
        else:
            plaintext += pair  # Preserve non-cipher characters
    return plaintext

# Vigenère Cipher Functions
def vigenere_encrypt(plaintext, key):
    encrypted_text = ""
    key = key.upper()
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            char_code = ord(char.upper()) - 65
            key_code = ord(key[key_index % len(key)].upper()) - 65
            encrypted_char = chr((char_code + key_code) % 26 + 65)
            encrypted_text += encrypted_char
            key_index += 1
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key = key.upper()
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            char_code = ord(char.upper()) - 65
            key_code = ord(key[key_index % len(key)].upper()) - 65
            decrypted_char = chr((char_code - key_code + 26) % 26 + 65)
            decrypted_text += decrypted_char
            key_index += 1
        else:
            decrypted_text += char
    return decrypted_text

# AES Encryption & Decryption
def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(encrypted_data, aes_key):
    raw_data = base64.b64decode(encrypted_data)
    nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# RSA Encryption & Decryption
def rsa_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message)
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(encrypted_message, private_key):
    encrypted = base64.b64decode(encrypted_message)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(encrypted)
    return decrypted

# Multi-Layer Hybrid Encryption
def hybrid_encrypt(plaintext, rsa_public_key, vigenere_key, aes_key):
    # Step 1: Polybius encryption
    square = create_polybius_square()
    polybius_encrypted = polybius_encrypt(plaintext, square)
    
    # Step 2: Vigenère encryption
    vigenere_encrypted = vigenere_encrypt(polybius_encrypted, vigenere_key)
    
    # Step 3: AES encryption
    aes_encrypted = aes_encrypt(vigenere_encrypted, aes_key)
    
    # Step 4: Encrypt AES key using RSA
    rsa_encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)
    
    return aes_encrypted, rsa_encrypted_aes_key, square

# Multi-Layer Hybrid Decryption
def hybrid_decrypt(encrypted_text, rsa_encrypted_aes_key, square, rsa_private_key, vigenere_key):
    # Step 1: Decrypt AES key using RSA
    aes_key = rsa_decrypt(rsa_encrypted_aes_key, rsa_private_key)
    
    # Step 2: AES decryption
    vigenere_encrypted = aes_decrypt(encrypted_text, aes_key)
    
    # Step 3: Vigenère decryption
    polybius_encrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
    
    # Step 4: Polybius decryption
    plaintext = polybius_decrypt(polybius_encrypted, square)
    
    return plaintext

# Main script - Interactive Mode
if __name__ == "__main__":
    print("Welcome to the Multi-Layer Hybrid Cryptographic System!")
    print("This system combines RSA, AES, Vigenère, and Polybius ciphers with advanced diffusion mechanisms.")
    
    while True:
        action = input("\nWould you like to [E]ncrypt or [D]ecrypt? (Enter 'E' or 'D'): ").strip().upper()
        
        if action == "E":
            plaintext = input("Enter the plaintext message to encrypt: ").strip()
            vigenere_key = input("Enter the Vigenère cipher key: ").strip()
            aes_key = get_random_bytes(16)  # Generate random AES key
            
            # Generate RSA Keys
            key = RSA.generate(2048)
            private_key = key
            public_key = key.publickey()
            
            print("\nEncrypting message...")
            encrypted_text, rsa_encrypted_aes_key, square = hybrid_encrypt(plaintext, public_key, vigenere_key, aes_key)
            
            print("\nEncrypted Text:")
            print(encrypted_text)
            print("\nRSA Encrypted AES Key:")
            print(rsa_encrypted_aes_key)
        
        elif action == "D":
            encrypted_text = input("Enter the encrypted message: ").strip()
            rsa_encrypted_aes_key = input("Enter the RSA encrypted AES key: ").strip()
            vigenere_key = input("Enter the Vigenère cipher key: ").strip()
            
            print("\nDecrypting message...")
            decrypted_text = hybrid_decrypt(encrypted_text, rsa_encrypted_aes_key, create_polybius_square(), private_key, vigenere_key)
            print("\nDecrypted Message:")
            print(decrypted_text)
        
        else:
            print("Invalid input. Please enter 'E' for encrypt or 'D' for decrypt.")
        
        cont = input("\nWould you like to perform another operation? (Y/N): ").strip().upper()
        if cont != "Y":
            print("Goodbye!")
            break
