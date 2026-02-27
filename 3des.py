from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from generacion_llaves import generate_3des_key, generate_iv

def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto para 3DES"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> len(ciphertext) % 8
        0  # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """
    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe tener 16 o 24 bytes")
    
    if len(iv) != DES3.block_size:
        raise ValueError(f"El IV debe tener {DES3.block_size} bytes (tamaño de bloque de DES)")

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_plaintext = pad(plaintext, DES3.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext


def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
        >>> decrypted == plaintext
        True
    """
    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe tener 16 o 24 bytes")
        
    if len(iv) != DES3.block_size:
        raise ValueError(f"El IV debe tener {DES3.block_size} bytes (tamaño de bloque de DES)")
        
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES3.block_size)
    
    return plaintext
