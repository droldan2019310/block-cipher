from Crypto.Cipher import DES
from utils import generate_des_key, pkcs7_pad, pkcs7_unpad

def encrypt_des_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra el texto plano usando DES en modo ECB con padding manual PKCS#7.
    """
    if len(key) != 8:
        raise ValueError("La clave DES debe tener 8 bytes")
        
    padded_plaintext = pkcs7_pad(plaintext, DES.block_size)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(padded_plaintext)

def decrypt_des_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra el criptograma usando DES en modo ECB con unpadding manual PKCS#7.
    """
    if len(key) != 8:
        raise ValueError("La clave DES debe tener 8 bytes")
        
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded_plaintext, DES.block_size)
