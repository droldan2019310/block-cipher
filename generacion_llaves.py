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