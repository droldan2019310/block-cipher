from Crypto.Cipher import AES
from src.utils import pkcs7_unpad

class PaddingOracle:
    def __init__(self, key: bytes):
        """
        Inicializa el oráculo con una clave secreta.
        """
        self.key = key
        
    def is_padding_valid(self, ciphertext: bytes, iv: bytes) -> bool:
        """
        Intenta descifrar el criptograma y verifica si el padding es válido.
        Retorna True si el padding es correcto, False si ocurre un error de padding.
        Esta vulnerabilidad de diseño (revelar validez) es lo que explota el ataque.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        
        try:
            # Nuestro pkcs7_unpad lanza ValueError si el padding es inválido
            pkcs7_unpad(plaintext_padded, AES.block_size)
            return True
        except ValueError:
            return False

def padding_oracle_attack(oracle: PaddingOracle, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Realiza un ataque de Padding Oracle para descifrar el criptograma íntegramente
    sin conocer la clave secreta interactuando repetidamente con el oráculo.
    """
    block_size = AES.block_size
    # Descomponer el criptograma en bloques
    blocks = [iv] + [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    decrypted_message = bytearray()
    
    # Atacar cada bloque (empezando desde el primero real, ya que el index 0 es el IV)
    for block_idx in range(1, len(blocks)):
        prev_block = blocks[block_idx - 1]
        target_block = blocks[block_idx]
        
        # Array para guardar el texto intermedio del bloque actual
        intermediate_state = bytearray(block_size)
        # Array para guardar los bytes descifrados del bloque actual
        decrypted_block = bytearray(block_size)
        
        # Vamos byte por byte, desde el final (byte 15) hasta el principio (byte 0)
        for byte_idx in reversed(range(block_size)):
            pad_val = block_size - byte_idx # El padding esperado: 1, 2, 3...
            
            # Construir bloque anterior modificado para el ataque
            # Todos los bytes generados aleatoriamente o 0 por defecto...
            modified_prev_block = bytearray(block_size)
            
            # ...excepto los bytes que ya hemos descifrado, que configuramos
            # para que el texto intermedio resulte en el pad_val deseado
            for k in range(byte_idx + 1, block_size):
                modified_prev_block[k] = intermediate_state[k] ^ pad_val
                
            found_byte = False
            for guess in range(256):
                modified_prev_block[byte_idx] = guess
                
                # Para evitar una coincidencia accidental con el padding correcto original
                # en el último byte (el byte 15, primer intento), a veces hay que modificar un byte anterior
                # para forzar un error si el padding era "\x02\x02" pero adivinamos "\x01" accidentalmente.
                # Como es una demostración simplificada estándar, lo dejaremos iterar asumiendo la casuística regular.
                
                # Enviar al oráculo:
                if oracle.is_padding_valid(bytes(target_block), bytes(modified_prev_block)):
                    # Validacion de falsos positivos en último byte (Padding 0x01 vs 0x02..0x0F original real)
                    # Si estamos en el ultimo byte, cambiamos levemente el antepenúltimo byte. 
                    # Si el oráculo falla, significaba que habíamos golpeado un padding mayor al intentado!
                    if byte_idx == block_size - 1:
                        modified_prev_block[byte_idx - 1] ^= 0x01
                        if not oracle.is_padding_valid(bytes(target_block), bytes(modified_prev_block)):
                            # Fue un falso positivo por coincidencia de block real pre-existente
                            modified_prev_block[byte_idx - 1] ^= 0x01 # revertir
                            continue
                            
                    # Hemos hallado la conjetura correcta que resulta en un byte final igual a `pad_val`
                    intermediate_byte = guess ^ pad_val
                    intermediate_state[byte_idx] = intermediate_byte
                    
                    # C = P ^ Intermediate => P = Intermediate ^ prev_block real (IV si es el 1er bloque)
                    real_plaintext_byte = intermediate_byte ^ prev_block[byte_idx]
                    decrypted_block[byte_idx] = real_plaintext_byte
                    found_byte = True
                    break
                    
            if not found_byte:
                raise Exception("Ataque falló: el oráculo no validó ningún byte.")
                
        decrypted_message.extend(decrypted_block)
        
    return bytes(decrypted_message)
