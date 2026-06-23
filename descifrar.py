#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════
 Descifrador ECIES standalone  —  VerifySign
═══════════════════════════════════════════════════════════════════════
"""
import base64, json, sys

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Falta la librería 'cryptography'. Instálala con:\n  pip install cryptography")
    sys.exit(1)


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def descifrar_ecies(blob: dict, priv_b64: str) -> str:
    """Descifra {iv, ct, epk} con la llave privada ECDH del sistema (PKCS8 Base64)."""
    # 1) Cargar la llave privada del sistema (formato PKCS8/DER en Base64)
    priv = serialization.load_der_private_key(b64d(priv_b64), password=None)

    # 2) Cargar la llave pública efímera (SPKI/DER en Base64)
    epk = serialization.load_der_public_key(b64d(blob["epk"]))

    # 3) ECDH -> secreto compartido
    shared = priv.exchange(ec.ECDH(), epk)

    # 4) HKDF-SHA256 -> clave AES-256 (mismos parámetros que el front)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",                       # salt vacío, igual que en el navegador
        info=b"VerifySign-ECIES",
    ).derive(shared)

    # 5) AES-GCM descifra
    iv = b64d(blob["iv"])
    ct = b64d(blob["ct"])
    pt = AESGCM(aes_key).decrypt(iv, ct, None)
    return pt.decode("utf-8")


def main():
    print("═" * 60)
    print(" Descifrador ECIES — VerifySign")
    print("═" * 60)
    priv_b64 = input("\nPega la llave privada ECDH del almacén (Base64):\n> ").strip()
    print("\nPega el blob cifrado como JSON (una línea), p. ej.")
    print('  {"iv":"...","ct":"...","epk":"..."}')
    blob_raw = input("> ").strip()

    try:
        blob = json.loads(blob_raw)
    except json.JSONDecodeError as e:
        print(f"\n✗ El blob no es JSON válido: {e}")
        return

    try:
        texto = descifrar_ecies(blob, priv_b64)
        print("\n" + "═" * 60)
        print(f" ✓ TEXTO DESCIFRADO:  {texto}")
        print("═" * 60)
    except Exception as e:
        print(f"\n✗ No se pudo descifrar: {e}")
        print("  (Verifica que la llave privada ECDH corresponda al "
              "almacén hacia cuya pública se cifró este blob.)")


if __name__ == "__main__":
    main()
