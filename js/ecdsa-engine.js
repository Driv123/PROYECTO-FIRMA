/**
 * ═══════════════════════════════════════════════════════
 *  ECDSA ENGINE  —  Web Crypto API  (P-256 + SHA-256)
 * ═══════════════════════════════════════════════════════
 *
 * Implementa los 3 scripts Python en el navegador usando
 * la Web Crypto API nativa (sin dependencias externas).
 *
 * Equivalencias:
 *   1_generar_llaves.py  →  ECDSAEngine.generarLlaves()
 *   2_firmar.py          →  ECDSAEngine.firmar()
 *   3_verificar.py       →  ECDSAEngine.verificar()
 */

const ECDSAEngine = (() => {

  const ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
  const HASH = { name: 'ECDSA', hash: { name: 'SHA-256' } };

  // ── Utilidades de codificación ────────────────────────────────────────────

  function bufToBase64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function base64ToBuf(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  async function bufToHex(buf) {
    const arr = new Uint8Array(buf);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function sha256Hex(data) {
    const buf = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return bufToHex(hash);
  }

  // ── 1. GENERAR LLAVES ────────────────────────────────────────────────────
  /**
   * Genera un par de llaves ECDSA P-256.
   * Retorna { llavePrivadaB64, llavePublicaB64, llavePrivadaCryptoKey, llavePublicaCryptoKey }
   *
   * Equivale a:  python 1_generar_llaves.py
   */
  async function generarLlaves() {
    const par = await crypto.subtle.generateKey(
      ALGO,
      true,   // extractable = podemos exportar
      ['sign', 'verify']
    );

    // Exportar en formato estándar (PKCS8 = privada, SPKI = pública)
    const privRaw = await crypto.subtle.exportKey('pkcs8', par.privateKey);
    const pubRaw  = await crypto.subtle.exportKey('spki',  par.publicKey);

    return {
      llavePrivadaB64: bufToBase64(privRaw),
      llavePublicaB64: bufToBase64(pubRaw),
      llavePrivadaKey: par.privateKey,
      llavePublicaKey: par.publicKey,
    };
  }

  // ── 2. FIRMAR ─────────────────────────────────────────────────────────────
  /**
   * Firma datos (string o ArrayBuffer) con una CryptoKey privada.
   *
   * Retorna un objeto firma:
   * {
   *   firmaB64        : string  — firma DER en Base64
   *   sha256Contenido : string  — hash SHA-256 hex del contenido
   *   algoritmo       : string
   *   fechaFirma      : string  — ISO 8601
   *   tamañoBytes     : number
   * }
   *
   * Equivale a:  python 2_firmar.py
   */
  async function firmar(datos, llavePrivadaKey, metaOrigen = 'web') {
    const bytes = typeof datos === 'string'
      ? new TextEncoder().encode(datos)
      : new Uint8Array(datos);

    const firmaBuf = await crypto.subtle.sign(HASH, llavePrivadaKey, bytes);
    const firmaB64 = bufToBase64(firmaBuf);
    const sha256   = await sha256Hex(bytes);

    return {
      firmaB64,
      sha256Contenido: sha256,
      algoritmo:  'ECDSA-SHA256-P256',
      fechaFirma: new Date().toISOString(),
      tamañoBytes: bytes.length,
      origen: metaOrigen,
    };
  }

  // ── 3. VERIFICAR ──────────────────────────────────────────────────────────
  /**
   * Verifica una firma ECDSA.
   *
   * Retorna:
   * {
   *   valida           : boolean
   *   hashesCoinciden  : boolean
   *   sha256Actual     : string
   *   sha256Registrado : string
   *   mensaje          : string
   * }
   *
   * Equivale a:  python 3_verificar.py
   */
  async function verificar(datos, firmaB64, llavePublicaKey, sha256Registrado = null) {
    const bytes    = typeof datos === 'string'
      ? new TextEncoder().encode(datos)
      : new Uint8Array(datos);
    const firmaBuf = base64ToBuf(firmaB64);

    let valida = false;
    let mensaje = '';

    try {
      valida = await crypto.subtle.verify(HASH, llavePublicaKey, firmaBuf, bytes);
      mensaje = valida
        ? 'La verificación matemática ECDSA es correcta.'
        : 'La firma no corresponde a los datos o la llave pública.';
    } catch (e) {
      mensaje = 'Error al verificar: ' + e.message;
    }

    const sha256Actual = await sha256Hex(bytes);
    const hashesCoinciden = sha256Registrado
      ? sha256Actual === sha256Registrado
      : true; // si no hay hash registrado, no se valida

    return { valida, hashesCoinciden, sha256Actual, sha256Registrado, mensaje };
  }

  // ── Importar llave pública desde Base64 (SPKI) ───────────────────────────
  async function importarLlavePublica(b64) {
    const buf = base64ToBuf(b64);
    return crypto.subtle.importKey('spki', buf, ALGO, true, ['verify']);
  }

  // ── Importar llave privada desde Base64 (PKCS8) ──────────────────────────
  async function importarLlavePrivada(b64) {
    const buf = base64ToBuf(b64);
    return crypto.subtle.importKey('pkcs8', buf, ALGO, true, ['sign']);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  ECIES  —  Cifrado con curvas elípticas  (ECDH P-256 + AES-GCM)
  // ═══════════════════════════════════════════════════════════════════════
  //  ECDSA solo firma/verifica; no cifra. Para CONFIDENCIALIDAD usamos ECIES,
  //  el esquema estándar de cifrado con curvas elípticas:
  //
  //    1. Quien cifra genera un par EFÍMERO ECDH P-256.
  //    2. Hace ECDH(privada efímera, pública del destinatario) -> secreto.
  //    3. Deriva una clave AES-256 del secreto con HKDF-SHA256.
  //    4. Cifra el texto con AES-GCM.
  //    5. Publica { iv, ct, epk }  (epk = llave pública efímera).
  //
  //  Para descifrar: ECDH(privada del destinatario, epk) -> mismo secreto
  //  -> misma clave AES -> descifra.
  //
  //  Esto es EFICIENTE: la parte de curva elíptica solo deriva una clave
  //  pequeña; el grueso del cifrado lo hace AES-GCM (rápido). Es exactamente
  //  el balance que pediste: ECC para el intercambio, AES para los datos.

  const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

  // Genera un par de llaves ECDH P-256 (para cifrado, distinto del de firma)
  async function generarLlavesECDH() {
    const par = await crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveKey', 'deriveBits']);
    return {
      privB64: bufToBase64(await crypto.subtle.exportKey('pkcs8', par.privateKey)),
      pubB64:  bufToBase64(await crypto.subtle.exportKey('spki',  par.publicKey)),
    };
  }

  async function importarECDHPriv(b64) {
    return crypto.subtle.importKey('pkcs8', base64ToBuf(b64), ECDH_ALGO, true, ['deriveKey', 'deriveBits']);
  }
  async function importarECDHPub(b64) {
    return crypto.subtle.importKey('spki', base64ToBuf(b64), ECDH_ALGO, true, []);
  }

  // Deriva una clave AES-GCM 256 a partir de un secreto ECDH usando HKDF
  async function derivarClaveAES(privKey, pubKey) {
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256);
    // HKDF para obtener material de clave robusto
    const hkdfKey = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('VerifySign-ECIES') },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Cifra un texto para el dueño de `pubDestinatarioB64` (ECIES).
   * Retorna { iv, ct, epk } todo en Base64. Solo quien tenga la privada
   * correspondiente podrá descifrar.
   */
  async function cifrarECIES(texto, pubDestinatarioB64) {
    const pubDest = await importarECDHPub(pubDestinatarioB64);
    // Par efímero
    const efimero = await crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveKey', 'deriveBits']);
    const aesKey  = await derivarClaveAES(efimero.privateKey, pubDest);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(texto));
    const epk = await crypto.subtle.exportKey('spki', efimero.publicKey);
    return { iv: bufToBase64(iv), ct: bufToBase64(ct), epk: bufToBase64(epk) };
  }

  /**
   * Descifra { iv, ct, epk } usando la llave privada ECDH del destinatario.
   * Lanza error si la privada no corresponde (AES-GCM autentica).
   */
  async function descifrarECIES(blob, privDestinatarioB64) {
    const privDest = await importarECDHPriv(privDestinatarioB64);
    const epk      = await importarECDHPub(blob.epk);
    const aesKey   = await derivarClaveAES(privDest, epk);
    const iv  = new Uint8Array(base64ToBuf(blob.iv));
    const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, base64ToBuf(blob.ct));
    return new TextDecoder().decode(buf);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  PROTECCIÓN DE LLAVES PRIVADAS CON CONTRASEÑA  (PBKDF2 + AES-GCM)
  // ═══════════════════════════════════════════════════════════════════════
  //  La llave privada de FIRMA de cada usuario se cifra con una clave
  //  derivada de su contraseña (PBKDF2-SHA256, 100k iteraciones) y se guarda
  //  cifrada en la base de datos. Así el usuario puede iniciar sesión desde
  //  cualquier dispositivo, y ni siquiera quien tenga la BD completa puede
  //  leer la llave privada sin la contraseña.
  //
  //  IMPORTANTE: el salt para esta derivación es DISTINTO del salt usado para
  //  el hash de login, de modo que el hash almacenado no sirve para descifrar.

  const PBKDF2_ITERS = 100000;

  function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

  // Deriva una clave AES-GCM desde la contraseña (PBKDF2)
  async function derivarClaveDeContrasena(password, saltBytes) {
    const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Cifra la llave privada (PKCS8 Base64) con la contraseña del usuario.
   * Retorna { salt, iv, ct } en Base64, listo para guardar en la BD.
   */
  async function cifrarLlavePrivada(privB64, password) {
    const salt = randomBytes(16);
    const iv   = randomBytes(12);
    const aes  = await derivarClaveDeContrasena(password, salt);
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode(privB64));
    return { salt: bufToBase64(salt), iv: bufToBase64(iv), ct: bufToBase64(ct) };
  }

  /**
   * Descifra la llave privada usando la contraseña. Lanza error si la
   * contraseña es incorrecta (AES-GCM autentica).
   */
  async function descifrarLlavePrivada(blob, password) {
    const salt = new Uint8Array(base64ToBuf(blob.salt));
    const iv   = new Uint8Array(base64ToBuf(blob.iv));
    const aes  = await derivarClaveDeContrasena(password, salt);
    const buf  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, base64ToBuf(blob.ct));
    return new TextDecoder().decode(buf);
  }

  /**
   * Hash de la contraseña para LOGIN (SHA-256 con salt propio).
   * Salt distinto al de cifrado de la llave privada -> el hash almacenado
   * no sirve para descifrar la llave.
   * Retorna { salt, hash } en Base64/hex.
   */
  async function hashLogin(password, saltB64) {
    const salt = saltB64 ? saltB64 : bufToBase64(randomBytes(16));
    const data = salt + ':' + password;
    const hash = await sha256Hex(data);
    return { salt, hash };
  }

  // ── Leer archivo como ArrayBuffer ────────────────────────────────────────
  function leerArchivo(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  // ── Descargar texto como archivo ─────────────────────────────────────────
  function descargarTexto(contenido, nombre) {
    const blob = new Blob([contenido], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: nombre });
    a.click();
    URL.revokeObjectURL(url);
  }

  return {
    generarLlaves,
    firmar,
    verificar,
    importarLlavePublica,
    importarLlavePrivada,
    leerArchivo,
    descargarTexto,
    bufToBase64,
    base64ToBuf,
    sha256Hex,
    // Cifrado ECIES (ECDH P-256 + AES-GCM)
    generarLlavesECDH,
    cifrarECIES,
    descifrarECIES,
    // Protección de llaves privadas con contraseña
    cifrarLlavePrivada,
    descifrarLlavePrivada,
    hashLogin,
  };
})();

// ── Estado global de la app ───────────────────────────────────────────────
const AppState = {
  // Sesión de llaves generadas
  llaves: null,          // { llavePrivadaB64, llavePublicaB64, llavePrivadaKey, llavePublicaKey }

  // Pedido en curso
  pedido: null,          // { descripcion, cliente, vendedor, archivoNombre, archivoBytes }

  // Firmas del flujo
  firmaCliente:  null,   // objeto firma retornado por ECDSAEngine.firmar()
  firmaVendedor: null,

  // Llaves cargadas externamente (para verificación)
  llavePublicaClienteKey:  null,
  llavePublicaVendedorKey: null,
};
