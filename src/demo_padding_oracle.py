import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from src.utils import generate_aes_key, generate_iv, pkcs7_unpad
from src.padding_oracle import PaddingOracle, padding_oracle_attack

def test_padding_oracle():
    print("--- Demostración de Padding Oracle Attack (Simplificada) ---")
    
    # 1. El servidor genera una llave secreta que el atacante (nosotros) NO conoce
    secreta_key = generate_aes_key(256)
    oracle = PaddingOracle(secreta_key)
    
    # 2. El servidor cifra un mensaje confidencial y lo envía por la red
    iv = generate_iv(16)
    mensaje_secreto = b"La clave de admin es P4ssw0rd_Super_Secr3ta!!"
    print(f"Mensaje original escondido: '{mensaje_secreto.decode()}'")
    
    cipher = AES.new(secreta_key, AES.MODE_CBC, iv=iv)
    # Servidor aplica padding y cifra el mensaje
    ciphertext = cipher.encrypt(pad(mensaje_secreto, AES.block_size))
    
    print("\n[!] Atacante intercepta la comunicación...")
    print(f"IV Interceptado (Hex): {iv.hex()}")
    print(f"Criptograma Interceptado (Hex): {ciphertext.hex()} (Bloques: {len(ciphertext) // 16})")
    print("[!] Iniciando ataque enviando cientos de falsificaciones al Servidor (Oráculo)...\n")
    
    # 3. El atacante utiliza SOLAMENTE el oráculo interceptado para descifrar el mensaje bruto
    try:
        texto_descifrado_crudo = padding_oracle_attack(oracle, ciphertext, iv)
        print("\n[+] Ataque finalizado con éxito.")
        
        # El atacante elimina manualmente el padding usando pkcs7_unpad (ya tiene el texto)
        mensaje_final = pkcs7_unpad(texto_descifrado_crudo, 16)
        print(f"[+] Mensaje descifrado recuperado: '{mensaje_final.decode()}'")
        
    except Exception as e:
        print(f"[-] Ataque falló: {e}")

if __name__ == "__main__":
    test_padding_oracle()
