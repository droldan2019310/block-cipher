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

## Respuestas a Preguntas de Análisis (Parte 2: Análisis de Seguridad)

### 2.1 Análisis de Tamaños de Clave (4 puntos)
* **Pregunta:** ¿Qué tamaño de clave está usando para DES, 3DES y AES? Para cada uno indique tamaño en bits y bytes.
* **Respuesta:**
  * **DES**: 8 bytes (64 bits, de los cuales 56 bits son efectivos y 8 son para bit de paridad).
  * **3DES**: 24 bytes (192 bits, equivalentes a 3 claves de 8 bytes en nuestro caso de uso con esquema de triple llave K1, K2, K3).
  * **AES**: 32 bytes (256 bits).

* **Pregunta:** Explique por qué DES se considera inseguro hoy en día y calcule cuánto tiempo tomaría un ataque de fuerza bruta con hardware moderno.
* **Respuesta:**
  * DES es inseguro debido a su pequeña longitud de clave efectiva que se limita únicamente a 56 bits. El espacio de búsqueda total es de $2^{56}$ combinaciones (72,057,594,037,927,936 posibles claves).
  * Con hardware convencional moderno (simulando un ataque distribuido que prueba 1 billón = $10^{12}$ combinaciones por segundo, lo cual es bajo actualmente): un ataque de fuerza bruta tardaría **72057.59 segundos**, equivalente a unas limitadas **20 horas** en ser perpetrado exitosamente.

* **Requisito (Código de generación y longitud):**
  ```python
  from src.utils import generate_des_key, generate_3des_key, generate_aes_key

  # Claves autogeneradas
  des_key = generate_des_key()
  print(f"DES: {len(des_key)} bytes ({len(des_key)*8} bits efectivos 56 + paridad)")

  des3_key = generate_3des_key(3) # Opción de 24 bytes (3 llaves aplicadas consecutivamente)
  print(f"3DES: {len(des3_key)} bytes ({len(des3_key)*8} bits efectivos 168 + paridad)")

  aes_key = generate_aes_key(256) # AES 256
  print(f"AES: {len(aes_key)} bytes ({len(aes_key)*8} bits)")
  ```

### 2.2 Comparación de Modos de Operación (5 puntos)
* **Pregunta:** Compare ECB vs CBC
  * *¿Qué modo de operación implementó en cada algoritmo?*
    * En **DES**, se implementó el modo **ECB** (`encrypt_des_ecb`, `decrypt_des_ecb`) con padding PKCS#7 manual.
    * En **3DES**, se implementó el modo **CBC** (`encrypt_3des_cbc`, `decrypt_3des_cbc`) con un vector de inicialización IV de 8 bytes.
    * En **AES**, se implementaron de igual manera ambos modos, **ECB** (`encrypt_image_ecb`) y **CBC** (`encrypt_image_cbc`), para la experimentación con imágenes.
  * *¿Cuáles son las diferencias fundamentales entre ECB y CBC?*
    * **ECB (Electronic Codebook):** Cada bloque de texto plano se cifra repetida e independientemente bajo la misma clave. Bloques idénticos de texto plano producen bloques idénticos en el criptograma. Falla en ocultar variabilidad de la información original.
    * **CBC (Cipher Block Chaining):** Utiliza un Vector de Inicialización (IV). Cada bloque de texto plano se combina con la operación XOR (OR Exclusivo) con el bloque cifrado *anterior* a él en la cadena antes de ser cifrado, asegurando que bloques idénticos de texto plano resulten en diferentes bloques visuales y computacionales para esconder la semántica original determinísticamente si se cuenta con el IV base.
  * *¿Se puede notar la diferencia directamente en una imagen?*
    * Sí, en el cifrado de la imagen mediante **ECB**, los píxeles idénticos de distintos subcampos mantienen los mismos valores, filtrando las geometrías y el formato al aplicar la visibilidad del patrón de píxeles del cifrado, mientras que nada se distingue en la encriptación paralela bajo derivaciones de bloque recursivas dependientes del nonce en modo CBC.

* **Requisito (Imágenes y patrones):**
  * Podemos notar los bordes y patrones de la cuadrícula repetida en ECB porque al estar conformada cada celda local por bytes idénticos entre sí, generan exactamente las mismas transformaciones encriptadas en píxeles. En CBC aparece simplemente un ruido completamente aleatorio en el layout de donde nada puede distinguirse.
  
  <p align="center">
    <img src="images/original.bmp" height="200" />
    <img src="images/aes_ecb.bmp" height="200" />
    <img src="images/aes_cbc.bmp" height="200" />
  </p>
  <p align="center">
    <i>(Izquierda: Original BMP, Centro: Cifrado modo puro ECB, Derecha: Cifrado pseudoaleatorio modo CBC)</i>
  </p>

* **Requisito (Código para generar las imágenes en src/aes_cipher.py):**
  ```python
  key = generate_aes_key(256)
  iv = generate_iv(AES.block_size) # 16 bytes
  
  # Cifrar imagen en modo ECB (Preservará estructura del tablero de ajedrez)
  encrypt_image_ecb('images/original.bmp', 'images/aes_ecb.bmp', key)
  
  # Cifrar imagen en modo CBC (Ruido uniforme pseudo-aleatorizado)
  encrypt_image_cbc('images/original.bmp', 'images/aes_cbc.bmp', key, iv)
  ```

### 2.3 Vulnerabilidad de ECB (6 puntos)
* **Pregunta:** ¿Por qué no debemos usar ECB en datos sensibles?
  Porque filtra información acerca del contenido general e idéntico original debido a las repeticiones directas. Un input genera de manera idéntica su equivalente output si se procesa usando exactamente el mismo estado global (llave).

* **Requisitos (Ejemplo de repetición ATAQUE):**
  Para probar este comportamiento, usamos el mensaje estructurado de 42 bytes `ATAQUE_ATAQUE___ATAQUE_ATAQUE___EXTRA_DATA` el cual está compuesto estratégicamente por dos bloques de bytes exactamente iguales (de 16 bytes o 1 bloque de AES cada uno) concatenados seguido de información extra.

  *Código de experimentación:*
  ```python
  from Crypto.Cipher import AES
  from Crypto.Util.Padding import pad

  msg_vuln = b"ATAQUE_ATAQUE___ATAQUE_ATAQUE___EXTRA_DATA"
  padded_msg = pad(msg_vuln, 16) 

  cipher_ecb = AES.new(aes_key, AES.MODE_ECB)
  cipher_cbc = AES.new(aes_key, AES.MODE_CBC, iv=generate_iv(16))

  ct_ecb = cipher_ecb.encrypt(padded_msg)
  ct_cbc = cipher_cbc.encrypt(padded_msg)
  ```

  **Salida en Hexadecimal:**
  ```text
  --- Resultados ECB ---
  Bloque 1 (ATAQUE_ATAQUE___): 1b44b37a6e5e11171de863e1a7fe08d1  # <- ¡IGUAL!
  Bloque 2 (ATAQUE_ATAQUE___): 1b44b37a6e5e11171de863e1a7fe08d1  # <- ¡IGUAL!
  Bloque 3 (EXTRA_DATA)      : 8d18a63cb53337463a7a7915f5bcad06

  --- Resultados CBC ---
  Bloque 1: 8eeb1e9f183b99dd000d597416bf0f8f  # <- Aleatorio/Diferentes
  Bloque 2: f13b4f2d284db042436956f03e60b2ac  # <- Combinados con xor encadenado
  Bloque 3: 0d4fee74485eb7fdcdc671100a8ab0a3
  ```
  * *¿Qué información podría filtrar esto en un escenario real?*
  Si se cifran datos sensibles y altamente estructurados (como registros JSON, campos base de un perfil médico de "NEGATIVO"/"POSITIVO", formularios bancarios o contraseñas), un intruso pasivo de la red (Man-in-the-Middle) que no conozca la llave, de todas maneras podría deducir qué datos son iguales mediante un *análisis de frecuencia computacional de los bloques cifrados que intercepta*, filtrando y comprometiendo de esta manera patrones determinísticos de usuarios en el negocio real de la data.

### 2.4 Vector de Inicialización (IV) (4 puntos)
* **Pregunta:** ¿Qué es el IV y por qué es necesario en CBC pero no en ECB?
  El IV es un elemento aleatorio (generado una sola vez que funge como nonce) emparejado e utilizado en el paso de cifrado XOR del nivel del primer bloque del texto introductorio en el modo **CBC** para brindarle una pre-variabilidad, corrompiendo en cadena a todos los subsiguientes bloques de texto sin estar codificado de manera fija desde el inicio usando la llave en bruto. No es implementable en **ECB** ya que este modo cifra cada uno de los bloques aislados limitados a la base estática de su propia llave simétrica sin transferir propiedades.

* **Requisitos (Experimento de cifrado de transacciones recurrentes con limitante de IVs en modo CBC):**
  *Código de experimentación:*
  ```python
  from Crypto.Cipher import AES
  from Crypto.Util.Padding import pad
  from src.utils import generate_iv
  
  msg_iv = b"Mensaje confidencial"

  iv1 = generate_iv(16)
  iv2 = generate_iv(16)

  cipher_cbc_1 = AES.new(aes_key, AES.MODE_CBC, iv=iv1)
  cipher_cbc_2 = AES.new(aes_key, AES.MODE_CBC, iv=iv1) # <-- Usaremos el Mismo IV
  cipher_cbc_3 = AES.new(aes_key, AES.MODE_CBC, iv=iv2) # <-- IV Diferente Nuevo generado

  ct1 = cipher_cbc_1.encrypt(pad(msg_iv, 16))
  ct2 = cipher_cbc_2.encrypt(pad(msg_iv, 16))
  ct3 = cipher_cbc_3.encrypt(pad(msg_iv, 16))
  ```

  **Resultados de Criptogramas (Hexadecimal):**
  ```text
  CT1 (Usando IV Original)     : 67a961a5350971b86c4f6c02ff2eafeb7435e5d8e0a1ff8612c28df9780aaf2d
  CT2 (Mismo IV Inseguro)      : 67a961a5350971b86c4f6c02ff2eafeb7435e5d8e0a1ff8612c28df9780aaf2d  # Igual a CT1
  CT3 (Reuso Seguro IV Nuevo)  : 000dfbdb372385e811417978249186e4a4c4c7f2669afb3a70dd8cd84313a691  # Bloque único irrepetible
  ```

  * *Explique qué pasaría si un atacante intercepta mensajes cifrados con el mismo IV repetidamente:*
  Al emitir un mensaje determinístico bajo la misma llave y siempre el mismo IV en el tiempo (ej. enviar un comando "EJECUTAR_TRANSFERENCIA_PAGO_JUAN"), el "Cipher Text" resultante de la transa será predeciblemente estático de nuevo. El atacante podría interceptar su contenido en red, y guardarlo (sin importar al ser incapaz de adivinar qué transita). Si es reenviado más tarde como un **Replay Attack** el atacador malicioso inyectará este paquete enrutándolo al servidor original produciendo transacciones ilegales y engañando a las protecciones que hubiese tenido el backend.

### 2.5 Padding (3 puntos)
* **Pregunta:** ¿Qué es el padding y por qué es necesario?
  Los algoritmos definidos en bloque operan usando fragmentos fijos forzados (usualmente 16 bytes o típicamente 8 bytes según el estándar limitante). Si un ingeniero desea subir data de tipo longitud no compatible de carácter asimétrico (ejem: 5 bytes), el padding se agrega al final del archivo antes de inyectarse como *relleno* estructural simulado que se estandarize dentro de la función criptográfica sin romper la memoria física.

* **Requisitos (Resultados implementando nuestra propia técnica de padding `pkcs7_pad(data, 8)` para un block_size de DES de 8):**

  ```text
  # Mensaje de 5 bytes 
  Padded: b'12345\x03\x03\x03' (Longitud final en bloque = 8 bytes)
  Se agregaron 3 bytes con un valor estricto de padding '0x03' cada uno, para ajustarlo de 5 a la exigencia de 8 bytes de bloque simétrico.

  # Mensaje de 8 bytes (Exactamente concordante a un bloque entero de 8 DES)
  Padded: b'12345678\x08\x08\x08\x08\x08\x08\x08\x08' (Longitud final concatenando = 16 bytes)
  Dado que este plaintext ya consta de una alineación perfecta de 8 bytes de largo, en los protocolos probados y estandarizados PKCS#7 se DEBE crear un bloque vacío y rellenar iterativamente en todos sus espacios con el largo respectivo (8 bytes adicionales del valor `\x08` como indicador). De no rellenarse por default, al desencriptarse el sistema consumiría una letra vital (`'8'`) como si fuera el largo del padding en sí durante el descarte fallando horriblemente, se mitiga rellenando ceguera con el valor propio de un bloque en bits.

  # Mensaje de 10 bytes 
  Padded: b'1234567890\x06\x06\x06\x06\x06\x06' (Total 16 bytes)
  Ocupó 1 bloque entero cabalmente empaquetado y el siguiente bloque residual se desbordó tomando dos slots valiosos. Por defecto se agregaron como sobrante los 6 elementos limitantes correspondientes restantes para equilibrar el conjunto en dos porciones fijadas, caracterizando un relleno '0x06' hacia la meta de 8.
  ```

  * *Demuestre que nuestra función manual de ingeniería `pkcs7_unpad` recupera el mensaje original cortándolo:*
  ```python
  from src.utils import pkcs7_unpad
  pad_5 = b'12345\\x03\\x03\\x03'
  recuperado = pkcs7_unpad(pad_5, block_size=8)
  print(recuperado) # Resultado Final Impreso de Desencripción: b'12345'
  ```
  La función evaluada extrajo del index final de lista el último parámetro (`'\\x03'`), el cual le indicó lógicamente la longitud base restante del array a limpiar, una validación posterior descartó las ocurrencias de iteración cortando un total `len("0x03")` del string dejándolo purgado en el valor real `"12345"`.

### 2.6 Recomendaciones de Uso (3 puntos)
* **Pregunta:** ¿En qué situaciones se recomienda cada modo de operación? ¿Cómo elegir un modo seguro en cada lenguaje de programación contemporánea?

| Modo | Casos de uso recomendados | Desventajas evidentes |
| :--- | :--- | :--- |
| **ECB** | Ninguno por lo general. A veces localmente para cifrar bloques puramente aleatorios unificados. | Esencialmente inseguro frente un análisis moderno de datos; revela sin control estructuras colindantes repetidas en base a estadísticas. |
| **CBC** | Protocolos de pasajes de carga y paquetes, correos a retención por encriptación, almacenamiento a disco directo cuando se exige confidencialidad base. | Paralelizar un bloque cifrado o descifrado es imposible por su diseño de dependencia recurrente. Obligación de un padding. Vulnerabilidades a ataques de manipulación u *Oracle Padding*. |
| **CTR** | Streaming de volúmenes de datos masivos en tiempo veloz a bajo costo computacional, buffers reducidos. | Su modalidad Stream Cipher implica un riesgo altísimo colateral de vulnerar la privacidad sin recuperación donde reutilizar inofensivamente el *nonce base inicial*/contador rompa toda viabilidad de uso. |
| **GCM** | Estándar de la industria para conexiones actuales (HTTPS, VPN, Archivos). Ambientes web pesados, comunicaciones corporativas, y protección donde se defina **AEAD**. | Puede demandar una computación fuerte a nivel software o hardware, por su encriptado en campos finitos sin una limitación previa de memoria para proveer de redundancias de seguridad por colisión. |

* *Mención fundamental a los modos AEAD robustos (Authenticated Encryption with Associated Data) como lo es el **GCM**:*
A diferencia del modo heredado CBC tradicional que se confina a la clandestinidad de que un intruso pasivo no obtenga la decodificación encriptada (*secreto confidencial*), un algoritmo basado en modo **AEAD GCM (Galois/Counter Mode)** adjuntarán además un *autenticidad general* junto con una *prueba inmutable de integridad*, emitiendo validadores algoritmicos de tipo Tag Autenticativo criptográfico. Con este MAC incorporado y verificado en la cadena el interceptor no solo desconoce el envío de la red, si no en caso de tratar de interceptarlo, manipular bytes cifrados y alterar su contenido maliciosamente inyectándolos fallará estrepitosamente al corroborar la validez de las firmas locales o remotas en las rutinas de desecho automáticas, bloqueando los accesos impuros.

* **Requisitos de uso práctico (Código demostrativo para invocar utilidades seguras usando un estándar AEAD GCM AES con al menos dos vertientes en lenguajes populares):**

  * **Uso estándar de librerías seguras recomendado en (Python usando `PyCryptodome` en GCM):**
    ```python
    from Crypto.Cipher import AES
    import secrets

    llave = secrets.token_bytes(32) # Standard AES-256
    cipher_seguro = AES.new(llave, AES.MODE_GCM) # GCM Interno autogenera al vuelo un nonce aleatorio iterativo
    
    # Proveer la información con retorno redundante
    texto_cifrado, tag_seguridad_diferido = cipher_seguro.encrypt_and_digest(b"Informacion UltraSecreta bancaria proveniente de Python App.")
    
    # En la recepción, es obligatorio pasar la clave, el texto_cifrado, cipher.nonce inicial y por supuesto el hash MAC de tag de integridad del payload blindado.
    ```
  
  * **Uso estándar base con (JavaScript integrando Node.js Crypto Package nativamente usando GCM):**
    ```javascript
    const crypto = require('crypto');

    const claveMestra = crypto.randomBytes(32); // Asignando formato a 256 bits fuertes.
    const ivTolerado = crypto.randomBytes(12);  // NIST impone para operaciones criptográficas seguras de un GCM una medida específica preferiblemente a un límite de 96 bits.

    // Config de protocolo seguro garantizado AES-256-GCM.
    const cipherGCM = crypto.createCipheriv('aes-256-gcm', claveMestra, ivTolerado);
    
    let encriptado = cipherGCM.update('Protegiendo conexiones API desde JS de punta a punta', 'utf8', 'hex');
    encriptado += cipherGCM.final('hex');
    const authTagProtegido = cipherGCM.getAuthTag().toString('hex'); // Estampa intrínseca de protección de colisión/integridad que viaja junto el cipher payload hacia la base de datos o front-end.
    ```

## Respuestas a Preguntas de Análisis (Parte 3: Validación y Pruebas)

### 3.1 Implementación de Modo CTR (5 puntos extra)
* **Comparación de rendimiento (10MB):**
  Al realizar el cifrado de un archivo de datos en memoria de 10 Megabytes con nuestra implementación, se observaron los siguientes tiempos:
  *   **AES en CBC**: `~0.048 segundos`
  *   **AES en CTR**: `~0.034 segundos`
  *   *Conclusión práctica*: El modo CTR fue consistentemente más rápido (reduce el tiempo de procesamiento casi en un 30% localmente).

* **Análisis de paralelización:**
  *   **¿Por qué CTR puede paralelizarse?** El cifrado en modo CTR funciona generando independientemente un flujo de llaves pseudoaleatorio (*keystream*) al encriptar valores secuenciales incrementales conformados por (Nonce + Contador). Como no existe dependencia del bloque previo (`Texto_Cifrado[i] = Texto_Plano[i] XOR Encrypt(Clave, Nonce+i)`), es cien por ciento posible asignar a *N* núcleos del procesador distintos rangos del contador para cifrar/descifrar fragmentos gigabytes del archivo simultáneamente sin esperar bloqueos.
  *   **¿Por qué CBC no puede paralelizarse al cifrar?** CBC encadena el cifrado de manera secuencial estricta. Para cifrar el Bloque *N*, la fórmula demanda forzosamente tener completado y resuelto el Bloque Cifrado *N-1* (`Texto_Cifrado[i] = Encrypt(Clave, Texto_Plano[i] XOR Texto_Cifrado[i-1]`) debido al operador XOR entrelazado. Esta codependencia imposibilita crear hilos paralelos de ejecución que adelanten trabajo (aunque nótese que en el descifrado CBC sí es paralelizable parcialmente al contar desde el inicio con todo el criptograma).

### 3.2 Ataque de Padding Oracle (5 puntos extra)
* **Demostración simplificada del ataque byte a byte (POODLE / Lucky 13 base):**
  En el script de experimentación `src/demo_padding_oracle.py` se construyó un Oráculo interceptor que es explotable enviando arreglos de criptogramas alterados bit a bit por la red. Al iterar hasta 256 conjeturas por el último byte pre-calculado modificado con XOR, el servidor emite una directriz binaria (Fallo de Padding / Acierto de Padding), descartando cualquier necesidad de conocer la llave criptográfica inicial y entregando con lujo de detalle en texto plano el contenido (`La clave de admin es...`).

* **Vulnerabilidades reales históricas:**
  *   **POODLE (Padding Oracle On Downgraded Legacy Encryption) [CVE-2014-3566]:** Descubierto en 2014, afectó severamente al protocolo antiguo SSL 3.0, el cual toleraba rellenos irregulares asumiéndolos válidos si solo su último byte coincidía. Los atacantes inyectaban JavaScript para forzar conexiones desprotegidas de la víctima, y aplicaban este ataque inyectando bloques de cookies como último elemento CBC logrando robar sesiones de cuentas bancarias interceptadas en routers en tiempo récord (unos 256 intentos promedio por byte).
  *   **Lucky 13 [CVE-2013-0169]:** En 2013, este ataque destrozó protocolos estandarizados (TLS y DTLS que usaban CBC con HMAC). Aunque no devolvía errores obvios que confirmaran el padding para no alertar al hacker, fue extremadamente sofisticado al inferir la respuesta analizando ínfimamente micro-diferencias del *tiempo de cálculo del servidor*. Si el padding fallaba, el servidor abortaba más rápido sin calcular el código de autenticidad HMAC (Side-Channel Timing Attack), creando de facto un Oráculo de respuesta análoga.

* **Mitigaciones existentes en implementaciones modernas:**
  1.  **Migrar a Authenticated Encryption with Associated Data (AEAD):** Abandonar CBC por completo a favor de **AES-GCM**, ChaCha20-Poly1305 o AES-CCM. Estos algoritmos cifran el contenido y validan matemáticamente su invariabilidad con un Auth Tag adjunto. Cualquier manipulación (intento de padding oracle) sobre el criptograma invalida la firma criptográfica instantáneamente, abortando el proceso antes de intentar siquiera un descifrado, apagando cualquier retroalimentación o Side-Channel.
  2.  **Esquema Encrypt-then-MAC:** Si por limitaciones empresariales es obligatorio el uso de CBC, el estándar imperativo dicta primero Cifrar y luego añadir el MAC. Al validar la autenticidad antes de descifrar la integridad del vector, los intentos de falsificación son bloqueados de puerta limitando los oráculos, mitigando la debilidad Mac-then-Encrypt (típico en TLS base y SSL).

## Proceso de Testing y Ejecución Automática de la Demostración

El repositorio cuenta ahora con `tests/test_ciphers.py` usando `unittest` que aborda una cobertura amplia incluyendo todos los scripts experimentales construidos a lo largo de los laboratorios (incluyendo los correspondientes a la Parte 3 CTR y Padding Oracles).

```bash
# Para ejecutar CTR Demo:
python src/demo_ctr.py

# Para ejecutar el ataque automático de Padding Oracle:
python src/demo_padding_oracle.py
```

Al final del día, las pruebas validan los requisitos básicos y técnicos para garantizar que las implementaciones base no han sido rotas por nuevas actualizaciones:
1. `test_des_ecb_encryption_decryption`
2. `test_3des_cbc_encryption_decryption`
3. `test_aes_ctr_encryption_decryption` (Validación asimétrica sin padding de modo de flujo rápido)
4. `test_padding_oracle_attack` (Simula un pipeline automatizado de robo del IV, intercepción y alteración asíncrona validando matemáticamente la consistencia final de los caracteres descubiertos por la vía de Oráculo CBC desprotegido)
