import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from utils import generate_aes_key, generate_iv

def encrypt_image_ecb(input_image_path: str, output_image_path: str, key: bytes):
    """
    Cifra una imagen en modo ECB manteniendo el header intacto.
    Se asume formato BMP donde el header suele ser de 54 bytes.
    """
    with open(input_image_path, 'rb') as f:
        data = f.read()
    
    # El header de un archivo BMP estándar suele ser de 54 bytes
    header_size = 54
    header = data[:header_size]
    pixels = data[header_size:]
    
    # Padding a los píxeles usando la librería (estándar PKCS#7)
    padded_pixels = pad(pixels, AES.block_size)
    
    # Cifrar en modo ECB
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_pixels = cipher.encrypt(padded_pixels)
    
    # Guardar la nueva imagen manteniendo el header original
    with open(output_image_path, 'wb') as f:
        f.write(header + ciphertext_pixels)

def encrypt_image_cbc(input_image_path: str, output_image_path: str, key: bytes, iv: bytes):
    """
    Cifra una imagen en modo CBC manteniendo el header intacto.
    """
    with open(input_image_path, 'rb') as f:
        data = f.read()
    
    header_size = 54
    header = data[:header_size]
    pixels = data[header_size:]
    
    # Padding
    padded_pixels = pad(pixels, AES.block_size)
    
    # Cifrar en modo CBC
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext_pixels = cipher.encrypt(padded_pixels)
    
    with open(output_image_path, 'wb') as f:
        f.write(header + ciphertext_pixels)

def generate_sample_bmp(output_path: str):
    """
    Genera una imagen BMP de prueba simple con un patrón de tablero de ajedrez.
    Esto permite evidenciar fácilmente la vulnerabilidad del modo ECB,
    ya que los bloques continuos del mismo color producirán el mismo cifrado.
    """
    width = 256
    height = 256
    # Tamaño de cabeceras en BMP
    header_size = 54 
    file_size = header_size + 3 * width * height
    
    header = bytearray(header_size)
    # Magic number 'BM'
    header[0:2] = b'BM'
    # Tamaño del archivo
    header[2:6] = file_size.to_bytes(4, byteorder='little')
    # Offset hasta el inicio de los datos de imagen
    header[10:14] = header_size.to_bytes(4, byteorder='little')
    # Tamaño del header DIB
    header[14:18] = (40).to_bytes(4, byteorder='little')
    # Ancho
    header[18:22] = width.to_bytes(4, byteorder='little')
    # Alto
    header[22:26] = height.to_bytes(4, byteorder='little')
    # Planos de color
    header[26:28] = (1).to_bytes(2, byteorder='little')
    # Bits por píxel (24 bits = RGB)
    header[28:30] = (24).to_bytes(2, byteorder='little')
    # Tamaño de los datos crudos
    header[34:38] = (3 * width * height).to_bytes(4, byteorder='little')
    
    pixels = bytearray(3 * width * height)
    # Crear patrón de tablero de ajedrez gigante
    for y in range(height):
        for x in range(width):
            idx = (y * width + x) * 3
            if (x // 64) % 2 == (y // 64) % 2:
                # Blanco
                pixels[idx:idx+3] = b'\xff\xff\xff'
            else:
                # Azul
                pixels[idx:idx+3] = b'\x00\x00\xff'
                
    with open(output_path, 'wb') as f:
        f.write(header)
        f.write(pixels)

if __name__ == "__main__":
    # Asegurarnos de usar paths correctos basados en donde se ejecuta (raíz del proy.)
    images_dir = '../images'
    if not os.path.exists(images_dir):
        images_dir = 'images'
        os.makedirs(images_dir, exist_ok=True)
    
    sample_img = os.path.join(images_dir, 'original.bmp')
    ecb_img = os.path.join(images_dir, 'aes_ecb.bmp')
    cbc_img = os.path.join(images_dir, 'aes_cbc.bmp')
    
    if not os.path.exists(sample_img):
        generate_sample_bmp(sample_img)
        print(f"Imagen de prueba generada en: {sample_img}")
        
    key = generate_aes_key(256)
    iv = generate_iv(AES.block_size)
    
    encrypt_image_ecb(sample_img, ecb_img, key)
    print(f"Imagen cifrada con ECB guardada en: {ecb_img}")
    
    encrypt_image_cbc(sample_img, cbc_img, key, iv)
    print(f"Imagen cifrada con CBC guardada en: {cbc_img}")
