"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key() -> bytes:
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).

    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.
    """
    return secrets.token_bytes(8)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.
    """
    if block_size <= 0:
        raise ValueError("block_size must be > 0")
    return secrets.token_bytes(block_size)



def generate_aes_key(key_size: int = 256) -> bytes:
    """
    Genera una clave AES aleatoria.

    key_size está en bits y solo puede ser: 128, 192 o 256.
    """
    if key_size not in (128, 192, 256):
        raise ValueError("key_size must be 128, 192, or 256 bits")

    return secrets.token_bytes(key_size // 8)




def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.
    """
    if block_size <= 0:
        raise ValueError("block_size must be > 0")
    return secrets.token_bytes(block_size)


def apply_cbc_encrypt(plaintext_padded: bytes, key: bytes, iv: bytes, block_size: int = 8) -> bytes:
    """
    Aplica CBC para ENCRIPTAR.

    Requiere:
      - plaintext_padded primero paso por pkcs7_pad.
      - que cifra UN bloque de 8 bytes con DES.

    Retorna:
      - ciphertext mismo largo que plaintext_padded
    """

    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    if len(iv) != block_size:
        raise ValueError("IV length must equal block_size")
    if len(plaintext_padded) == 0 or (len(plaintext_padded) % block_size) != 0:
        raise ValueError("plaintext_padded must be non-empty and multiple of block_size")

    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    prev = iv
    out = bytearray()

    for i in range(0, len(plaintext_padded), block_size):
        block = plaintext_padded[i:i + block_size]
        x = xor_bytes(block, prev)
        c = des_encrypt_block(x, key)  
        if len(c) != block_size:
            raise ValueError("des_encrypt_block must return exactly block_size bytes")
        out.extend(c)
        prev = c

    return bytes(out)


def apply_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, block_size: int = 8) -> bytes:
    """
    Aplica CBC para DESENCRIPTAR.

    Requiere:
      - ciphertext debe ser múltiplo de block_size
      - Debes tener implementada: des_decrypt_block(block: bytes, key: bytes) -> bytes
        que descifra UN bloque de 8 bytes con DES.

    Retorna:
      - plaintext con padding (luego aplicas pkcs7_unpad)
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    if len(iv) != block_size:
        raise ValueError("IV length must equal block_size")
    if len(ciphertext) == 0 or (len(ciphertext) % block_size) != 0:
        raise ValueError("ciphertext must be non-empty and multiple of block_size")

    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    prev = iv
    out = bytearray()

    for i in range(0, len(ciphertext), block_size):
        cblock = ciphertext[i:i + block_size]
        x = des_decrypt_block(cblock, key)  
        if len(x) != block_size:
            raise ValueError("des_decrypt_block must return exactly block_size bytes")
        p = xor_bytes(x, prev)
        out.extend(p)
        prev = cblock

    return bytes(out)



def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    # implementar después
    
    return True


def generate_3des_key(key_option: int = 2) -> bytes:
    """
    Genera una clave 3DES aleatoria.

    key_option:
        2 -> 16 bytes (K1, K2, K1)
        3 -> 24 bytes (K1, K2, K3)
    """
    if key_option == 2:
        return secrets.token_bytes(16)
    elif key_option == 3:
        return secrets.token_bytes(24)
    else:
        raise ValueError("key_option must be 2 or 3")