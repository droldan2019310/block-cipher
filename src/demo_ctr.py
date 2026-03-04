import sys
import os
import time

# Añadir el directorio raíz al path para importar src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from src.utils import generate_aes_key, generate_iv
from src.ctr_cipher import encrypt_aes_ctr, decrypt_aes_ctr

def demo_no_padding():
    print("--- Demostración de que CTR no requiere padding ---")
    key = generate_aes_key(256)
    nonce = generate_iv(8) # Para CTR el nonce suele ser de la mitad del bloque (8 bytes en AES)

    # Mensaje de longitud asimétrica (11 bytes, no es múltiplo de 16)
    mensaje = b"Hola Mundo!"
    print(f"Mensaje original: {mensaje} (Longitud: {len(mensaje)} bytes)")

    # Cifrar en CTR sin usar función de padding
    ciphertext = encrypt_aes_ctr(mensaje, key, nonce)
    print(f"Ciphertext (Hex): {ciphertext.hex()} (Longitud: {len(ciphertext)} bytes)")

    # Descifrar en CTR
    plaintext = decrypt_aes_ctr(ciphertext, key, nonce)
    print(f"Texto descifrado: {plaintext}")
    
    if plaintext == mensaje:
        print("¡El descifrado fue exitoso sin usar padding!\n")
    else:
        print("Error en el descifrado.\n")

def demo_rendimiento_10mb():
    print("--- Comparación de rendimiento (10MB) CBC vs CTR ---")
    key = generate_aes_key(256)
    
    # Generar 10MB de datos aleatorios en memoria
    # 10 MB = 10 * 1024 * 1024 bytes
    mb_size = 10
    print(f"Generando {mb_size}MB de datos para la prueba...")
    data = os.urandom(mb_size * 1024 * 1024)
    
    # Pruebas CBC
    iv_cbc = generate_iv(16)
    tiempo_inicio_cbc = time.time()
    # CBC requiere padding
    padded_data = pad(data, AES.block_size)
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv=iv_cbc)
    _ = cipher_cbc.encrypt(padded_data)
    tiempo_fin_cbc = time.time()
    
    tiempo_cbc = tiempo_fin_cbc - tiempo_inicio_cbc
    
    # Pruebas CTR
    nonce_ctr = generate_iv(8)
    tiempo_inicio_ctr = time.time()
    # CTR no requiere padding
    cipher_ctr = AES.new(key, AES.MODE_CTR, nonce=nonce_ctr)
    _ = cipher_ctr.encrypt(data)
    tiempo_fin_ctr = time.time()
    
    tiempo_ctr = tiempo_fin_ctr - tiempo_inicio_ctr

    print(f"Tiempo de cifrado usando CBC ({mb_size}MB): {tiempo_cbc:.6f} segundos")
    print(f"Tiempo de cifrado usando CTR ({mb_size}MB): {tiempo_ctr:.6f} segundos")

    if tiempo_ctr < tiempo_cbc:
        print(f"-> CTR fue más rápido que CBC por {tiempo_cbc - tiempo_ctr:.6f} segundos")
    else:
        print(f"-> CBC fue más rápido que CTR (inusualmente) por {tiempo_ctr - tiempo_cbc:.6f} segundos")

if __name__ == "__main__":
    demo_no_padding()
    demo_rendimiento_10mb()
