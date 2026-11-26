"""
OmniFetch MEGA.nz Cryptographic Engine
Exact implementation of MEGA.nz encryption, decryption, and integrity primitives:
- Base64 URL decoding with variable padding.
- File key unpacking (AES-128 key, 8-byte IV, 8-byte Meta-MAC).
- Folder node key decryption via AES-128-ECB.
- Attribute (at) decryption via AES-128-CBC with zero IV.
- Multi-chunk payload decryption via AES-128-CTR with 16-byte aligned counter offsets.
- Chunked CBC-MAC calculation & verification against meta_mac.
"""

import base64
import struct
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util import Counter

def base64_url_decode(data: str) -> bytes:
    """Decodes URL-safe base64 string with optional missing padding."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    data = data.replace("-", "+").replace("_", "/")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.b64decode(data)

def base64_url_encode(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 string without trailing padding."""
    return base64.b64encode(data).decode("utf-8").replace("+", "-").replace("/", "_").rstrip("=")

def bytes_to_a32(b: bytes) -> list[int]:
    """Converts bytes to an array of 32-bit big-endian unsigned integers."""
    pad = len(b) % 4
    if pad:
        b += b"\x00" * (4 - pad)
    return list(struct.unpack(f">{len(b) // 4}I", b))

def a32_to_bytes(a: list[int]) -> bytes:
    """Converts an array of 32-bit big-endian unsigned integers to bytes."""
    return struct.pack(f">{len(a)}I", *a)

def unpack_file_key(raw_key_bytes: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Unpacks a 32-byte decoded MEGA file key into:
    - 16-byte AES-128 key: k[:16] XOR k[16:]
    - 8-byte IV: k[16:24]
    - 8-byte Meta-MAC: k[24:32]
    """
    if len(raw_key_bytes) != 32:
        raise ValueError(f"Expected 32-byte file key, got {len(raw_key_bytes)} bytes")

    aes_key = bytes(raw_key_bytes[i] ^ raw_key_bytes[i + 16] for i in range(16))
    iv_bytes = raw_key_bytes[16:24]
    meta_mac_bytes = raw_key_bytes[24:32]
    return aes_key, iv_bytes, meta_mac_bytes

def pack_file_key(aes_key: bytes, iv_bytes: bytes, meta_mac_bytes: bytes) -> bytes:
    """Packs AES key, IV, and Meta-MAC into a 32-byte raw MEGA file key."""
    if len(aes_key) != 16 or len(iv_bytes) != 8 or len(meta_mac_bytes) != 8:
        raise ValueError("Invalid component lengths for pack_file_key")
    part2 = iv_bytes + meta_mac_bytes
    part1 = bytes(aes_key[i] ^ part2[i] for i in range(16))
    return part1 + part2

def decrypt_attr(enc_attr_bytes: bytes, aes_key: bytes) -> dict:
    """
    Decrypts MEGA file attributes (at) with AES-128-CBC using zero IV.
    Plaintext format: MEGA{"n":"filename.ext",...}
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b"\x00" * 16)
    plain = cipher.decrypt(enc_attr_bytes)
    if not plain.startswith(b"MEGA"):
        raise ValueError("Invalid attribute header (missing 'MEGA' prefix)")
    json_bytes = plain[4:].rstrip(b"\x00")
    return json.loads(json_bytes.decode("utf-8", errors="ignore"))

def encrypt_attr(attr_dict: dict, aes_key: bytes) -> bytes:
    """Encrypts MEGA file attributes dict with AES-128-CBC using zero IV."""
    data = b"MEGA" + json.dumps(attr_dict, separators=(",", ":")).encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    if pad_len != 16:
        data += b"\x00" * pad_len
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b"\x00" * 16)
    return cipher.encrypt(data)

def decrypt_node_key(enc_key_bytes: bytes, folder_key_bytes: bytes) -> bytes:
    """
    Decrypts a child node key inside a shared folder using AES-128-ECB.
    If file: returns 32 bytes (raw file key).
    If folder: returns 16 bytes (raw folder key).
    Implemented via AES-128-CBC with zero IV per 16-byte block (avoids unsigned _raw_ecb.pyd on Windows).
    """
    res = bytearray()
    for i in range(0, len(enc_key_bytes), 16):
        block = enc_key_bytes[i:i + 16]
        c = AES.new(folder_key_bytes, AES.MODE_CBC, iv=b"\x00" * 16)
        res.extend(c.decrypt(block))
    return bytes(res)

def encrypt_node_key(key_bytes: bytes, folder_key_bytes: bytes) -> bytes:
    """Encrypts a child node key (16 or 32 bytes) via block-independent CBC zero-IV (ECB equivalent)."""
    res = bytearray()
    for i in range(0, len(key_bytes), 16):
        block = key_bytes[i:i + 16]
        c = AES.new(folder_key_bytes, AES.MODE_CBC, iv=b"\x00" * 16)
        res.extend(c.encrypt(block))
    return bytes(res)

def get_ctr_cipher(aes_key: bytes, iv_bytes: bytes, byte_offset: int = 0):
    """
    Builds an AES-128-CTR cipher offset by byte_offset.
    Requires byte_offset to be 16-byte block aligned.
    """
    if byte_offset % 16 != 0:
        raise ValueError(f"Byte offset must be 16-byte block aligned, got {byte_offset}")
    block_offset = byte_offset // 16
    ctr = Counter.new(64, prefix=iv_bytes, initial_value=block_offset)
    return AES.new(aes_key, AES.MODE_CTR, counter=ctr)

def decrypt_chunk(encrypted_chunk: bytes, aes_key: bytes, iv_bytes: bytes, byte_offset: int = 0) -> bytes:
    """Decrypts a chunk of ciphertext starting at a 16-byte aligned byte_offset."""
    cipher = get_ctr_cipher(aes_key, iv_bytes, byte_offset)
    return cipher.decrypt(encrypted_chunk)

def encrypt_chunk(plain_chunk: bytes, aes_key: bytes, iv_bytes: bytes, byte_offset: int = 0) -> bytes:
    """Encrypts a chunk of plaintext starting at a 16-byte aligned byte_offset."""
    cipher = get_ctr_cipher(aes_key, iv_bytes, byte_offset)
    return cipher.encrypt(plain_chunk)

def get_mega_chunks(file_size: int) -> list[tuple[int, int]]:
    """
    Generates MEGA's variable chunk sequence:
    128 KB, 256 KB, 384 KB, 512 KB, 640 KB, 768 KB, 896 KB, then 1024 KB chunks.
    Returns list of (start_offset, chunk_size).
    """
    chunks = []
    p = 0
    i = 1
    while i <= 8 and p < file_size - i * 0x20000:
        sz = i * 0x20000  # 128 KB * i
        chunks.append((p, sz))
        p += sz
        i += 1
    while p < file_size:
        sz = min(0x100000, file_size - p)  # 1024 KB max
        chunks.append((p, sz))
        p += sz
    return chunks

def compute_file_mac(data_or_file, file_size: int, aes_key: bytes, iv_bytes: bytes) -> bytes:
    """
    Computes MEGA's chunked CBC-MAC for a complete decrypted file payload.
    Uses native AES-128-CBC with iv = iv_bytes + iv_bytes per chunk,
    accumulating the tail block into file_mac.
    Returns 8-byte condensed MAC.
    """
    chunks = get_mega_chunks(file_size)
    chunk_iv = iv_bytes + iv_bytes

    file_mac_bytes = b"\x00" * 16

    is_bytes = isinstance(data_or_file, (bytes, bytearray))
    f = None
    if not is_bytes:
        if isinstance(data_or_file, (str, Path)):
            f = open(data_or_file, "rb")
        else:
            f = data_or_file

    try:
        for start, size in chunks:
            if is_bytes:
                chunk = data_or_file[start:start + size]
            else:
                f.seek(start)
                chunk = f.read(size)

            if len(chunk) % 16 != 0:
                chunk += b"\x00" * (16 - (len(chunk) % 16))

            # Full chunk CBC encryption; last 16-byte block is chunk_mac
            cipher_bytes = AES.new(aes_key, AES.MODE_CBC, iv=chunk_iv).encrypt(chunk)
            chunk_mac_bytes = cipher_bytes[-16:]

            # Accumulate chunk_mac into file_mac: E_K(file_mac ^ chunk_mac)
            file_mac_bytes = AES.new(aes_key, AES.MODE_CBC, iv=file_mac_bytes).encrypt(chunk_mac_bytes)
    finally:
        if not is_bytes and isinstance(data_or_file, (str, Path)) and f:
            f.close()

    file_mac = bytes_to_a32(file_mac_bytes)
    condensed_mac_a32 = [file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]]
    return a32_to_bytes(condensed_mac_a32)

def verify_file_mac(data_or_file, file_size: int, aes_key: bytes, iv_bytes: bytes, meta_mac_bytes: bytes) -> bool:
    """Verifies that the computed chunked CBC-MAC matches the expected meta_mac."""
    computed = compute_file_mac(data_or_file, file_size, aes_key, iv_bytes)
    return computed == meta_mac_bytes
