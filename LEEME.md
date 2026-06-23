# VerifySign — versión en la nube (Supabase)

Sistema de firma digital ECDSA con base de datos en la nube, cifrado de
datos sensibles con ECIES y un simulador de sniffer para demostrar
confidencialidad e integridad.

## 1. Configurar Supabase

### a) Crear las tablas
1. Entra a tu proyecto en https://supabase.com
2. Menú lateral → **SQL Editor** → **New query**
3. Pega TODO el contenido de `supabase-schema.sql` y pulsa **Run**.
   Debe responder "Tablas creadas correctamente ✓".

### b) Poner tu anon key
1. En Supabase: **Project Settings** → **API**
2. En "Project API keys" copia la clave **anon · public** (la cadena larga).
3. Abre `js/supabase-config.js` y pega esa clave reemplazando
   `PEGA_AQUI_TU_ANON_PUBLIC_KEY`. La URL ya está puesta.

> La anon key es pública por diseño (va en el front). NO uses la
> service_role key aquí.

## 2. Ejecutar el sitio

Tiene que servirse por HTTP (no abrir el archivo directamente), porque
Web Crypto requiere un "secure context". La forma más simple:

```bash
cd firma-web
python3 -m http.server 8000
```

Luego abre http://localhost:8000

## 3. Cómo está hecha la criptografía

| Propósito                | Algoritmo                                    |
|--------------------------|----------------------------------------------|
| Firmar pedidos           | ECDSA P-256 + SHA-256                        |
| Verificar firmas         | ECDSA P-256                                  |
| Cifrar tarjeta y RFC     | ECIES = ECDH P-256 + HKDF-SHA256 + AES-GCM   |
| Proteger llaves privadas | PBKDF2-SHA256 (100k) + AES-GCM con la contraseña |
| Login                    | SHA-256(salt + contraseña), salt propio      |

**¿Por qué ECIES y no "solo curvas elípticas"?** Las curvas elípticas no
cifran datos directamente de forma práctica. ECIES es el estándar: usa
ECDH (curvas elípticas) para acordar una clave, y AES-GCM (rápido) para
cifrar los datos. Es el balance eficiente pedido: curva elíptica para el
intercambio de clave, AES para el grueso del cifrado.

### Quién puede descifrar qué
- La tarjeta y el RFC del cliente se cifran **hacia la llave pública ECDH
  del almacén**. Solo el almacén (con su llave privada ECDH) puede
  descifrarlos; ni el sniffer ni el vendedor pueden.
- Por eso **debe registrarse primero un usuario con rol Almacén** antes de
  registrar clientes (aporta la llave pública con la que se cifra).

### Llaves privadas (modelo realista)
- Cada usuario genera su llave privada de firma en el navegador. Se
  **cifra con su contraseña** (PBKDF2 + AES-GCM) y se guarda cifrada en la
  BD, así puede iniciar sesión desde cualquier dispositivo.
- Al hacer login, la contraseña descifra la llave (solo en memoria). La
  contraseña nunca viaja ni se guarda en claro.
- El salt del hash de **login** es distinto del salt del cifrado de la
  **llave**, así que tener el hash de la BD NO permite descifrar la llave.
  Ni quien tenga la BD completa puede usar las llaves sin la contraseña.

### Qué se cifra y qué no
- **Se cifran:** tarjeta y RFC (hacia el almacén); y las llaves privadas
  (con la contraseña de cada usuario).
- **En claro:** dirección (por requerimiento), nombre, productos, importe,
  llaves públicas.

## 4. Demos de seguridad

- **Simulador de sniffer** (`sniffer.html`): intercepta un pedido, muestra
  los datos cifrados (visibles pero ilegibles), intenta descifrarlos sin la
  llave (falla), y permite editar el documento crudo e inyectarlo a la BD.
  Con Realtime, el vendedor/almacén ven la alteración al instante.
- **Descifrador** (`descifrar.html` y `descifrar.py`): demuestra que el
  almacén SÍ puede descifrar la tarjeta y el RFC con su llave privada ECDH.

### Script Python de descifrado
```bash
pip install cryptography
python descifrar.py
```
Te pide la **llave privada ECDH del almacén** (inicia sesión como almacén y
en la consola del navegador ejecuta
`JSON.parse(localStorage.getItem('vs_session')).ecdhPrivadaB64`) y el blob
cifrado (en Supabase, columnas `tarjeta_cifrada` / `rfc_cifrado`).

## 5. Flujo

1. **Almacén** se registra primero (genera su par ECDH de descifrado).
2. **Cliente** se registra (tarjeta y RFC se cifran hacia el almacén) y
   firma un pedido de refrescos.
3. **Vendedor** verifica la firma del cliente (comparándola contra todos
   los clientes) y la avala con su contra-firma.
4. **Almacén** verifica ambas firmas y entrega; además puede descifrar los
   datos sensibles del cliente.

Si el sniffer altera un pedido, la verificación falla en cualquier punto y
el documento se marca como alterado.

## Nota sobre seguridad de la demo
Para que el sniffer pueda inyectar (lo que se quiere demostrar), las
políticas RLS de Supabase están abiertas y se usa la anon key sin Supabase
Auth. En un sistema real se usaría Supabase Auth + políticas estrictas por
usuario, y la llave privada del almacén viviría en un HSM o servicio de
claves.
