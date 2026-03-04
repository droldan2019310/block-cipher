import sys
import os
import unittest

# Añadir el directorio src al PATH para importar desde allí
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from utils import generate_des_key, generate_3des_key, generate_iv
from des_cipher import encrypt_des_ecb, decrypt_des_ecb
from tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc

class TestCiphers(unittest.TestCase):
    
    def test_des_ecb_encryption_decryption(self):
        """Prueba de cifrado y descifrado DES en modo ECB con padding manual"""
        key = generate_des_key()
        
        # Test con mensaje de longitud que es múltiplo del bloque (8 bytes)
        plaintext_exact = b"12345678"
        ciphertext_exact = encrypt_des_ecb(plaintext_exact, key)
        self.assertNotEqual(plaintext_exact, ciphertext_exact)
        self.assertEqual(len(ciphertext_exact) % 8, 0)
        decrypted_exact = decrypt_des_ecb(ciphertext_exact, key)
        self.assertEqual(plaintext_exact, decrypted_exact)
        
        # Test con mensaje de longitud no exacta
        plaintext_unexact = b"Mensaje de longitud no exacta para DES. Se deben anadir bytes adicionales para padding."
        ciphertext_unexact = encrypt_des_ecb(plaintext_unexact, key)
        self.assertNotEqual(plaintext_unexact, ciphertext_unexact)
        self.assertEqual(len(ciphertext_unexact) % 8, 0)
        decrypted_unexact = decrypt_des_ecb(ciphertext_unexact, key)
        self.assertEqual(plaintext_unexact, decrypted_unexact)

    def test_3des_cbc_encryption_decryption(self):
        """Prueba de cifrado y descifrado 3DES en modo CBC"""
        # Test con clave de 16 bytes (opción 2)
        key_16 = generate_3des_key(2)
        iv_16 = generate_iv(8)
        plaintext = b"Prueba con clave 3DES de 16 bytes y un texto mas largo."
        
        ciphertext_16 = encrypt_3des_cbc(plaintext, key_16, iv_16)
        self.assertNotEqual(plaintext, ciphertext_16)
        
        # El IV asegura un texto cifrado diferente incluso si la llave y plaintext son el mismo
        iv2_16 = generate_iv(8)
        ciphertext2_16 = encrypt_3des_cbc(plaintext, key_16, iv2_16)
        self.assertNotEqual(ciphertext_16, ciphertext2_16)
        
        decrypted_16 = decrypt_3des_cbc(ciphertext_16, key_16, iv_16)
        self.assertEqual(plaintext, decrypted_16)

        # Test con clave de 24 bytes (opción 3)
        key_24 = generate_3des_key(3)
        iv_24 = generate_iv(8)
        
        ciphertext_24 = encrypt_3des_cbc(plaintext, key_24, iv_24)
        decrypted_24 = decrypt_3des_cbc(ciphertext_24, key_24, iv_24)
        self.assertEqual(plaintext, decrypted_24)

if __name__ == '__main__':
    unittest.main()
