'''import streamlit as st
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
            polybius_text += "  "  # Preserve spaces
        else:
            polybius_text += char
    return polybius_text.strip()

# Decrypt using the Polybius cipher
def polybius_decrypt(polybius_text, square):
    reverse_square = {v: k for k, v in square.items()}
    plaintext = ""
    for pair in polybius_text.split(" "):
        if pair == "":
            plaintext += " "
        elif len(pair) == 2 and pair.isdigit():
            row, col = int(pair[0]), int(pair[1])
            char = reverse_square.get((row, col), "")
            plaintext += char
        else:
            plaintext += pair
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
    square = create_polybius_square()
    polybius_encrypted = polybius_encrypt(plaintext, square)
    vigenere_encrypted = vigenere_encrypt(polybius_encrypted, vigenere_key)
    aes_encrypted = aes_encrypt(vigenere_encrypted, aes_key)
    rsa_encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)
    return aes_encrypted, rsa_encrypted_aes_key, square

def hybrid_decrypt(encrypted_text, rsa_encrypted_aes_key, square, rsa_private_key, vigenere_key):
    aes_key = rsa_decrypt(rsa_encrypted_aes_key, rsa_private_key)
    vigenere_encrypted = aes_decrypt(encrypted_text, aes_key)
    polybius_encrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
    plaintext = polybius_decrypt(polybius_encrypted, square)
    return plaintext

# Streamlit App
st.title("Multi-Layer Hybrid Cryptographic System")
st.write("This system uses RSA, AES, Vigenère, and Polybius ciphers.")

option = st.radio("Choose an action", ("Encrypt", "Decrypt"))

if option == "Encrypt":
    plaintext = st.text_area("Enter the plaintext message")
    vigenere_key = st.text_input("Enter the Vigenère cipher key")
    aes_key = get_random_bytes(16)

    if st.button("Encrypt"):
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()

        encrypted_text, rsa_encrypted_aes_key, square = hybrid_encrypt(
            plaintext, public_key, vigenere_key, aes_key
        )
        st.write("**Encrypted Text:**")
        st.code(encrypted_text)
        st.write("**RSA Encrypted AES Key:**")
        st.code(rsa_encrypted_aes_key)

        st.session_state["private_key"] = private_key
        st.session_state["square"] = square

elif option == "Decrypt":
    encrypted_text = st.text_area("Enter the encrypted text")
    rsa_encrypted_aes_key = st.text_area("Enter the RSA encrypted AES key")
    vigenere_key = st.text_input("Enter the Vigenère cipher key")

    if st.button("Decrypt"):
        if "private_key" in st.session_state and "square" in st.session_state:
            private_key = st.session_state["private_key"]
            square = st.session_state["square"]

            decrypted_text = hybrid_decrypt(
                encrypted_text, rsa_encrypted_aes_key, square, private_key, vigenere_key
            )
            st.write("**Decrypted Message:**")
            st.code(decrypted_text)
        else:
            st.error("Encryption keys are not available. Encrypt first.")


'''

import streamlit as st
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
            polybius_text += "  "  # Preserve spaces
        else:
            polybius_text += char
    return polybius_text.strip()

# Decrypt using the Polybius cipher
def polybius_decrypt(polybius_text, square):
    reverse_square = {v: k for k, v in square.items()}
    plaintext = ""
    for pair in polybius_text.split(" "):
        if pair == "":
            plaintext += " "
        elif len(pair) == 2 and pair.isdigit():
            row, col = int(pair[0]), int(pair[1])
            char = reverse_square.get((row, col), "")
            plaintext += char
        else:
            plaintext += pair
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
    square = create_polybius_square()
    polybius_encrypted = polybius_encrypt(plaintext, square)
    vigenere_encrypted = vigenere_encrypt(polybius_encrypted, vigenere_key)
    aes_encrypted = aes_encrypt(vigenere_encrypted, aes_key)
    rsa_encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)
    return aes_encrypted, rsa_encrypted_aes_key, square

def hybrid_decrypt(encrypted_text, rsa_encrypted_aes_key, square, rsa_private_key, vigenere_key):
    aes_key = rsa_decrypt(rsa_encrypted_aes_key, rsa_private_key)
    vigenere_encrypted = aes_decrypt(encrypted_text, aes_key)
    polybius_encrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
    plaintext = polybius_decrypt(polybius_encrypted, square)
    return plaintext

# Streamlit App
st.title("Multi-Layer Hybrid Cryptographic System")
st.write("A secure system using RSA, AES, Vigenère, and Polybius ciphers.")

with st.sidebar:
    st.header("Encryption & Decryption")
    option = st.radio("Choose an action:", ["Encrypt", "Decrypt"])

if option == "Encrypt":
    st.subheader("Encryption")
    plaintext = st.text_area("Enter the plaintext message", help="Message you want to encrypt")
    vigenere_key = st.text_input("Enter the Vigenère cipher key", help="Key for Vigenère encryption")
    aes_key = get_random_bytes(16)

    if st.button("Encrypt"):
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()

        encrypted_text, rsa_encrypted_aes_key, square = hybrid_encrypt(
            plaintext, public_key, vigenere_key, aes_key
        )
        st.write("**Encrypted Text:**")
        st.code(encrypted_text)
        st.write("**RSA Encrypted AES Key:**")
        st.code(rsa_encrypted_aes_key)

        st.session_state["private_key"] = private_key
        st.session_state["square"] = square

elif option == "Decrypt":
    st.subheader("Decryption")
    encrypted_text = st.text_area("Enter the encrypted text", help="Message to decrypt")
    rsa_encrypted_aes_key = st.text_area("Enter the RSA encrypted AES key")
    vigenere_key = st.text_input("Enter the Vigenère cipher key")

    if st.button("Decrypt"):
        if "private_key" in st.session_state and "square" in st.session_state:
            private_key = st.session_state["private_key"]
            square = st.session_state["square"]

            decrypted_text = hybrid_decrypt(
                encrypted_text, rsa_encrypted_aes_key, square, private_key, vigenere_key
            )
            st.write("**Decrypted Message:**")
            st.code(decrypted_text)
        else:
            st.error("Encryption keys are not available. Encrypt first.")
