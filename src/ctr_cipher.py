from Crypto.Cipher import AES
from src.utils import generate_aes_key, generate_iv

def encrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Cifra un mensaje usando AES en modo CTR.
    El modo CTR convierte un cifrador de bloque en un cifrador de flujo,
    por lo que no requiere padding del texto original.
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_aes_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Descifra un mensaje cifrado con AES en modo CTR usando el mismo nonce.
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
