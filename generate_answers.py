import time
from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad
from src.utils import pkcs7_pad, pkcs7_unpad, generate_des_key, generate_3des_key, generate_aes_key, generate_iv

# 2.1 Análisis de Tamaños de Clave
des_key = generate_des_key()
print(f"DES: {len(des_key)} bytes ({len(des_key)*8} bits efectivos 56 + paridad)")

des3_key = generate_3des_key(3) # Using 24 bytes option
print(f"3DES: {len(des3_key)} bytes ({len(des3_key)*8} bits efectivos 168 + paridad)")

aes_key = generate_aes_key(256)
print(f"AES: {len(aes_key)} bytes ({len(aes_key)*8} bits)")

# Brute force times calculation
sec_per_year = 60 * 60 * 24 * 365
# Assuming modern hardware can test 10^12 keys per second (1 trillion)
rate = 1_000_000_000_000
combinations = 2**56
seconds = combinations / rate
years = seconds / sec_per_year
print(f"Tiempo fuerza bruta DES (10^12 claves/s): {seconds:.2f} segundos = {years:.2f} años")
# Assuming very powerful cluster 10^14 keys/sec (100 trillion)
rate2 = 100_000_000_000_000
seconds2 = combinations / rate2
print(f"Tiempo fuerza bruta DES (10^14 claves/s): {seconds2:.2f} segundos = {seconds2 / 3600:.2f} horas")

print("\n--- 2.3 Vulnerabilidad ECB ---")
# ECB Vulnerability
msg = b"ATAQUE ATAQUE ATAQUE " 
# Padding to match blocks. Let's make it EXACTLY blocks for AES (16 bytes)
msg = b"ATAQUE ATAQUE ATAQUE ATAQUE ATAQUE ATAQUE "
#  use 16 bytes blocks
block1 = b"ATAQUE_ATAQUE___"
block2 = b"ATAQUE_ATAQUE___"
msg_vuln = block1 + block2 + b"EXTRA_DATA"

padded_msg_vuln = pad(msg_vuln, AES.block_size)
cipher_ecb = AES.new(aes_key, AES.MODE_ECB)
cipher_cbc = AES.new(aes_key, AES.MODE_CBC, iv=generate_iv(16))

ct_ecb = cipher_ecb.encrypt(padded_msg_vuln)
ct_cbc = cipher_cbc.encrypt(padded_msg_vuln)

print(f"Plaintext: {msg_vuln}")
print(f"ECB Bloque 1: {ct_ecb[0:16].hex()}")
print(f"ECB Bloque 2: {ct_ecb[16:32].hex()}")
print(f"ECB Bloque 3: {ct_ecb[32:48].hex()}")

print(f"CBC Bloque 1: {ct_cbc[0:16].hex()}")
print(f"CBC Bloque 2: {ct_cbc[16:32].hex()}")
print(f"CBC Bloque 3: {ct_cbc[32:48].hex()}")

print("\n--- 2.4 Vector de Inicialización (IV) ---")
iv1 = generate_iv(16)
iv2 = generate_iv(16)
msg_iv = b"Mensaje confidencial"

cipher_cbc_1 = AES.new(aes_key, AES.MODE_CBC, iv=iv1)
cipher_cbc_2 = AES.new(aes_key, AES.MODE_CBC, iv=iv1) # same IV
cipher_cbc_3 = AES.new(aes_key, AES.MODE_CBC, iv=iv2) # different IV

ct1 = cipher_cbc_1.encrypt(pad(msg_iv, AES.block_size))
ct2 = cipher_cbc_2.encrypt(pad(msg_iv, AES.block_size))
ct3 = cipher_cbc_3.encrypt(pad(msg_iv, AES.block_size))

print(f"CT1 (IV 1)     : {ct1.hex()}")
print(f"CT2 (Mismo IV) : {ct2.hex()}")
print(f"CT3 (IV Nuevo) : {ct3.hex()}")

print("\n--- 2.5 Padding ---")
msg_5 = b"12345"
msg_8 = b"12345678"
msg_10 = b"1234567890"

pad_5 = pkcs7_pad(msg_5, 8)
pad_8 = pkcs7_pad(msg_8, 8)
pad_10 = pkcs7_pad(msg_10, 8)

print(f"5 bytes padded: {pad_5} (length {len(pad_5)})")
print(f"8 bytes padded: {pad_8} (length {len(pad_8)})")
print(f"10 bytes padded: {pad_10} (length {len(pad_10)})")

print(f"Unpadded 5: {pkcs7_unpad(pad_5, 8)}")
