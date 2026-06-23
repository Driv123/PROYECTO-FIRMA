const ECDSAEngine = (() => {

  const ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
  const HASH = { name: 'ECDSA', hash: { name: 'SHA-256' } };


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

  // ── 1. GENERAR LLAVES 
  /**
   * Genera un par de llaves ECDSA P-256.
   */
  async function generarLlaves() {
    const par = await crypto.subtle.generateKey(
      ALGO,
      true,  
      ['sign', 'verify']
    );

    const privRaw = await crypto.subtle.exportKey('pkcs8', par.privateKey);
    const pubRaw  = await crypto.subtle.exportKey('spki',  par.publicKey);

    return {
      llavePrivadaB64: bufToBase64(privRaw),
      llavePublicaB64: bufToBase64(pubRaw),
      llavePrivadaKey: par.privateKey,
      llavePublicaKey: par.publicKey,
    };
  }

  // ── 2. FIRMAR 
  /**
   * Firma datos.
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

  // ── 3. VERIFICAR 
  /**
   * Verifica una firma ECDSA.
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
        ? 'La verificación ECDSA es correcta.'
        : 'La firma no corresponde a los datos o la llave pública.';
    } catch (e) {
      mensaje = 'Error al verificar: ' + e.message;
    }

    const sha256Actual = await sha256Hex(bytes);
    const hashesCoinciden = sha256Registrado
      ? sha256Actual === sha256Registrado
      : true;

    return { valida, hashesCoinciden, sha256Actual, sha256Registrado, mensaje };
  }

  //  Importar llave pública 
  async function importarLlavePublica(b64) {
    const buf = base64ToBuf(b64);
    return crypto.subtle.importKey('spki', buf, ALGO, true, ['verify']);
  }

  //  Importar llave privada 
  async function importarLlavePrivada(b64) {
    const buf = base64ToBuf(b64);
    return crypto.subtle.importKey('pkcs8', buf, ALGO, true, ['sign']);
  }

  //  ECIES  —  Cifrado con curvas elípticas

  const ECDH_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

  // Genera un par de llaves ECDH P-256
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

  async function derivarClaveAES(privKey, pubKey) {
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256);
    const hkdfKey = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('VerifySign-ECIES') },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  //Cifra
  async function cifrarECIES(texto, pubDestinatarioB64) {
    const pubDest = await importarECDHPub(pubDestinatarioB64);
    const efimero = await crypto.subtle.generateKey(ECDH_ALGO, true, ['deriveKey', 'deriveBits']);
    const aesKey  = await derivarClaveAES(efimero.privateKey, pubDest);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(texto));
    const epk = await crypto.subtle.exportKey('spki', efimero.publicKey);
    return { iv: bufToBase64(iv), ct: bufToBase64(ct), epk: bufToBase64(epk) };
  }

  //Descifra
  async function descifrarECIES(blob, privDestinatarioB64) {
    const privDest = await importarECDHPriv(privDestinatarioB64);
    const epk      = await importarECDHPub(blob.epk);
    const aesKey   = await derivarClaveAES(privDest, epk);
    const iv  = new Uint8Array(base64ToBuf(blob.iv));
    const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, base64ToBuf(blob.ct));
    return new TextDecoder().decode(buf);
  }

  //  PROTECCIÓN DE LLAVES PRIVADAS CON CONTRASEÑA  (PBKDF2 + AES-GCM)

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

  async function cifrarLlavePrivada(privB64, password) {
    const salt = randomBytes(16);
    const iv   = randomBytes(12);
    const aes  = await derivarClaveDeContrasena(password, salt);
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode(privB64));
    return { salt: bufToBase64(salt), iv: bufToBase64(iv), ct: bufToBase64(ct) };
  }

  async function descifrarLlavePrivada(blob, password) {
    const salt = new Uint8Array(base64ToBuf(blob.salt));
    const iv   = new Uint8Array(base64ToBuf(blob.iv));
    const aes  = await derivarClaveDeContrasena(password, salt);
    const buf  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, base64ToBuf(blob.ct));
    return new TextDecoder().decode(buf);
  }

  async function hashLogin(password, saltB64) {
    const salt = saltB64 ? saltB64 : bufToBase64(randomBytes(16));
    const data = salt + ':' + password;
    const hash = await sha256Hex(data);
    return { salt, hash };
  }

  //  Leer archivo
  function leerArchivo(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  //  Descargar texto como archivo
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
