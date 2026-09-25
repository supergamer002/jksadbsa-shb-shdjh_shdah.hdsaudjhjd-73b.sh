import os
import sys
import io
import tarfile
import gzip
import secrets
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURAZIONE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

ENCRYPTED_FILE = BASE_DIR / "project.enc"

HEADER = b"AES256GCM1"
NONCE_SIZE = 12

INCLUDE = [
    "generate_qa.py",
    "segmenti",
    "dataset_generation/out",
]


# ============================================================
# CHIAVE
# ============================================================

def get_key():

    key_hex = os.environ.get("PROJECT_AES_KEY")

    if not key_hex:
        raise RuntimeError(
            "PROJECT_AES_KEY non impostata."
        )

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise RuntimeError(
            "PROJECT_AES_KEY non è una chiave esadecimale valida."
        )

    if len(key) != 32:
        raise RuntimeError(
            "PROJECT_AES_KEY deve essere AES-256 "
            "(32 byte / 64 caratteri esadecimali)."
        )

    return key


# ============================================================
# DECRYPT
# ============================================================

def decrypt_project():

    if not ENCRYPTED_FILE.exists():
        raise RuntimeError(
            f"{ENCRYPTED_FILE} non trovato."
        )

    key = get_key()

    print("========================================")
    print("DECRITTAZIONE PROJECT")
    print("========================================")

    encrypted = ENCRYPTED_FILE.read_bytes()

    if not encrypted.startswith(HEADER):
        raise RuntimeError(
            "Formato project.enc non riconosciuto."
        )

    offset = len(HEADER)

    nonce = encrypted[
        offset:
        offset + NONCE_SIZE
    ]

    ciphertext = encrypted[
        offset + NONCE_SIZE:
    ]

    aes = AESGCM(key)

    try:
        compressed = aes.decrypt(
            nonce,
            ciphertext,
            None
        )
    except Exception as e:
        raise RuntimeError(
            "Decrittazione AES-GCM fallita. "
            "Chiave errata oppure project.enc modificato."
        ) from e

    print("✓ AES-GCM authentication OK")

    try:
        tar_data = gzip.decompress(
            compressed
        )
    except Exception as e:
        raise RuntimeError(
            "Decompressione gzip fallita."
        ) from e

    print(
        f"✓ Archivio decompresso: "
        f"{len(tar_data) / 1024 / 1024:.2f} MB"
    )

    with tarfile.open(
        fileobj=io.BytesIO(tar_data),
        mode="r:"
    ) as tar:

        tar.extractall(
            BASE_DIR,
            filter="data"
        )

    print("✓ File decriptati nella repository")


# ============================================================
# ENCRYPT
# ============================================================

def encrypt_project():

    key = get_key()

    print("========================================")
    print("CIFRATURA PROJECT")
    print("========================================")

    # --------------------------------------------------------
    # Controllo dei file
    # --------------------------------------------------------

    print("\nControllo file da cifrare...")

    for item in INCLUDE:

        path = BASE_DIR / item

        if not path.exists():
            raise RuntimeError(
                f"File richiesto non trovato: {item}"
            )

        print(f"  + {item}")

    # --------------------------------------------------------
    # TAR in memoria
    # --------------------------------------------------------

    print("\nCreo archivio TAR...")

    tar_buffer = io.BytesIO()

    with tarfile.open(
        fileobj=tar_buffer,
        mode="w"
    ) as tar:

        for item in INCLUDE:

            path = BASE_DIR / item

            tar.add(
                path,
                arcname=item
            )

    tar_data = tar_buffer.getvalue()

    print(
        f"Dimensione TAR: "
        f"{len(tar_data) / 1024 / 1024:.2f} MB"
    )

    # --------------------------------------------------------
    # GZIP
    # --------------------------------------------------------

    print("Compressione gzip...")

    compressed = gzip.compress(
        tar_data,
        compresslevel=9
    )

    print(
        f"Dimensione compressa: "
        f"{len(compressed) / 1024 / 1024:.2f} MB"
    )

    # --------------------------------------------------------
    # AES-GCM
    # --------------------------------------------------------

    print("Cifratura AES-256-GCM...")

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        compressed,
        None
    )

    final_data = (
        HEADER
        + nonce
        + ciphertext
    )

    temporary_output = BASE_DIR / "project.enc.tmp"

    temporary_output.write_bytes(
        final_data
    )

    temporary_output.replace(
        ENCRYPTED_FILE
    )

    print(
        f"✓ project.enc aggiornato: "
        f"{ENCRYPTED_FILE.stat().st_size / 1024 / 1024:.2f} MB"
    )

    # --------------------------------------------------------
    # RIMOZIONE PLAINTEXT
    # --------------------------------------------------------

    print("\nElimino file in chiaro...")

    for item in INCLUDE:

        path = BASE_DIR / item

        if path.is_dir():
            shutil.rmtree(path)

        elif path.exists():
            path.unlink()

        print(f"  ✓ rimosso {item}")

    print("\n✓ Repository nuovamente cifrata")


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Uso:\n"
            "  python bootstrap.py decrypt\n"
            "  python bootstrap.py encrypt"
        )

        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "decrypt":

        decrypt_project()

    elif command == "encrypt":

        encrypt_project()

    else:

        raise RuntimeError(
            f"Comando sconosciuto: {command}"
        )


if __name__ == "__main__":
    main()
