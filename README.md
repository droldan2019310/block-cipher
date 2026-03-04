# Laboratorio de Cifrados de Bloque

Este repositorio contiene las implementaciones de los cifrados de bloque DES, 3DES y AES, junto con ejemplos prácticos de sus modos de operación (ECB, CBC) y análisis de sus vulnerabilidades.

## Estructura del proyecto

```text
lab-block-ciphers/
├── src/
│   ├── des_cipher.py          # Implementación de DES en ECB
│   ├── tripledes_cipher.py    # Implementación de 3DES en CBC
│   ├── aes_cipher.py          # Implementación de AES para imágenes (ECB y CBC)
│   └── utils.py               # Funciones compartidas (generación de claves, IV, padding manual)
├── tests/
│   └── test_ciphers.py        # Pruebas unitarias para DES y 3DES
├── images/
│   ├── original.bmp           # Imagen original autogenerada
│   ├── aes_ecb.bmp            # Imagen cifrada con AES-ECB
│   └── aes_cbc.bmp            # Imagen cifrada con AES-CBC
├── requirements.txt           # Dependencias del proyecto
└── README.md                  # Este documento
```

## Instrucciones de Instalación y Uso

**Requisitos previos:** Python 3.8+

1. Clona el repositorio e instala las dependencias usando un entorno virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # En Windows usa: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. Ejecutar la demostración de AES con imágenes:
   ```bash
   export PYTHONPATH="$(pwd)/src:$PYTHONPATH" # (opcional de ser necesario)
   python src/aes_cipher.py
   ```
   Esto generará automáticamente en la carpeta `images/` un archivo `original.bmp` con un patrón simple, y creará sus versiones cifradas `aes_ecb.bmp` y `aes_cbc.bmp`.

3. Ejecutar las pruebas unitarias (testing):
   ```bash
   python -m unittest discover tests
   ```

Ejemplos de cómo usar las primitivas desde Python:

```python
from src.utils import generate_des_key
from src.des_cipher import encrypt_des_ecb, decrypt_des_ecb

key = generate_des_key()
# Padding automático y cifrado
ciphertext = encrypt_des_ecb(b"Mensaje", key) 
# Descifrado y validación del padding
plaintext = decrypt_des_ecb(ciphertext, key)
```

## Respuestas a Preguntas de Análisis

### Análisis visual de las vulnerabilidades del modo ECB
Al ejecutar `src/aes_cipher.py`, se toma una imagen con un patrón (fondo de cuadrícula de color) y se cifra usando el modo ECB. Dado que ECB cifra bloques idénticos de texto plano exactamente con el mismo bloque de texto cifrado, los patrones uniformes en la imagen original (como un fondo blanco continuo) mantienen su estructura original en el criptograma final. Como puede verse al abrir `images/aes_ecb.bmp`, **el contenido visual o la silueta original se puede distinguir fácilmente**, incluso estando la información cifrada. 

Por el contrario, el modo CBC utiliza un vector de inicialización (IV) y encadena los bloques. Por ende, el mismo bloque de información (`0xFFFFFF`) cifrado se transforma en texto cifrado diferente cada vez, derivando en que la imagen `images/aes_cbc.bmp` luzca como un ruido pseudoaleatorio, sin ningún patrón reconocible y protegiendo de verdad el contenido original.

### Importancia del Padding, Vectores de Inicialización (IV) y Tamaños de Clave
* **Padding:** Los algoritmos de cifrado en bloque necesitan que los mensajes sean múltiples exactos del tamaño de bloque (ej. 8 bytes para DES/3DES y 16 bytes para AES). El uso adecuado del padding garantiza que cualquier tamaño de mensaje pueda ajustarse a esta restricción (evitando errores) y además provee mecanismos durante el descifrado (como PKCS#7) para asegurar y validar de manera estricta que la información no está corrompida, garantizando integridad referencial.
* **Vector de Inicialización (IV):** Evita el problema visto en el modo ECB con la repetición de patrones. Un IV debe ser único (aleatorio o un pseudo-nonce) para cada mensaje distinto cifrado bajo la misma clave para introducir variabilidad o "ruido" inicial y hacer que textos idénticos resulten en criptogramas completamente distintos. **Nota:** *En una implementación del mundo real, el IV no es secreto, pero es necesario para la desencripción. Típicamente el IV (que no necesita ir cifrado y tiene un tamaño de 8 o 16 bytes) se concatena al inicio del mensaje cifrado (`IV + criptograma`). El cliente receptor lo extrae leyendo la primera cuota de bytes dependiente al tamaño de bloque y descifra la porción restante del texto cifrado.*
* **Tamaños de Clave:** Las claves dirigen el funcionamiento interno de las rondas de sustitución y permutación. Claves cortas (ej. 56 bits de DES efectivo) son vulnerables a ataques de fuerza bruta usando tecnología computacional contemporánea. Claves más largas como AES-256 incrementan el tiempo de búsqueda necesario a miles de años (haciendo estos ataques impracticables) y mejorando exponencialmente la resistencia ante ataques conocidos y análisis criptográfico actual e incluso futuro (cuántico).

### Demostración práctica de por qué usar DES/3DES y modos como ECB están deprecados
* **DES (Data Encryption Standard):** Es inseguro debido a su pequeña clave efectiva de 56 bits. Con poder computacional suficiente, se puede aplicar la fuerza bruta fácilmente.
* **3DES (Triple DES):** Aunque introducido para mitigar flaquezas temporales de DES mediante usar 3 llaves aplicadas consecutivamente, es muy ineficiente e intrínsecamente lento.
  * **2 claves (16 bytes) vs 3 claves (24 bytes):** Con 2 llaves (K1, K2, K1) se cifraba primero con K1, descifraba con K2 y se volvía a cifrar con K1, logrando una efectividad cercana a ~112 bits. Sin embargo, ataques modernos demostraron que el esquema de 2 clases presenta severas vulnerabilidades. Se recomendó el esquema de 3 llaves (K1, K2, K3), que ofrece mitigación, pero manteniendo la sobrecarga de 3 operaciones consecutivas, y por lo tanto 3DES como estándar actualmente también es obsoleto en favor de **AES**.
* **ECB (Electronic Codebook):** Su falla principal al descuidar la variabilidad (mismo input siempre produce mismo output bajo una misma llave) resalta en análisis de frecuencia, deduciéndose partes de la información original según el caso de uso (como se demuestra gráficamente en este repositorio con las imágenes de ECB vs CBC). Todos estos algoritmos y modos no deberían ser implementados en un ambiente de desarrollo o producción el día de hoy.

## Proceso de Testing (Documentación)
He agregado un archivo en `tests/test_ciphers.py` usando `unittest`. Las pruebas validan los requisitos básicos y técnicos:
1. `test_des_ecb_encryption_decryption`: Prueba del padding PKCS#7 manual en DES-ECB. Si a un `ciphertext` le falta padding o este es invlálido, el descifrado lanza un error. Si un string o input bytes tiene un tamaño "incomodo" lo convierte y lo ajusta con padding antes de empaquetar, resultando en tamaño con un múltiplo de bloque válido, para luego ser descifrado comprobando que se iguala al `plaintext` original sin alteración.
2. `test_3des_cbc_encryption_decryption`: Prueba los esquemas de tamaño de llaves de 2 llaves (16 bytes) y 3 llaves (24 bytes). Además, comprueba que generar un criptograma con el mismo texto y clave, pero con un IV diferente (en el emisor) cambia completamente el layout final del `ciphertext` garantizando seguridad contra replay attacks y variaciones en colisiones, retornando en un mensaje `plaintext` recuperable sólo con el par unívoco IV + CLAVE.
