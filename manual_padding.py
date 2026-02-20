"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Implementa padding PKCS#7 según RFC 5652.
    """
    
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255")

    padding_len = block_size - (len(data) % block_size)
    
    # Si ya es múltiplo exacto, agregar bloque completo
    if padding_len == 0:
        padding_len = block_size

    padding = bytes([padding_len] * padding_len)

    return data + padding

def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data:
        raise ValueError("Input data cannot be empty")

    if len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    padding_len = data[-1]  # último byte

    if padding_len == 0 or padding_len > block_size:
        raise ValueError("Invalid padding")

    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")

    return data[:-padding_len]