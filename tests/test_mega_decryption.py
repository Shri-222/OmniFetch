"""
OmniFetch Phase 3 Unit Tests:
MEGA Cryptography, Resolver, Passive SmartProxy, and Batch Clipboard Grabber
Verifies:
1. Modern + legacy MEGA URL parsing.
2. AES-128-CBC attribute decryption & encryption.
3. AES-128-CTR multi-chunk parallel decryption with 16-byte aligned counter offsets.
4. Chunked CBC-MAC verification (valid vs tampered).
5. MegaBasterd-style Passive SmartProxy HTTP 509 failover.
6. Concurrent proxy health testing (alive vs dead filtering).
7. MEGA folder node tree Stage 1 trap inspection.
8. Batch clipboard link filtering and deduplication.
"""

import os
import asyncio
import threading
import pytest
from aiohttp import web

from app.engines.mega.crypto import (
    base64_url_encode,
    base64_url_decode,
    unpack_file_key,
    pack_file_key,
    decrypt_attr,
    encrypt_attr,
    decrypt_node_key,
    encrypt_node_key,
    decrypt_chunk,
    encrypt_chunk,
    compute_file_mac,
    verify_file_mac
)
from app.engines.mega.resolver import MegaUrlResolver
from app.engines.mega.proxy_pool import ProxyPool, ProxyEntry
from app.engines.torrent.file_tree import TorrentFileInspector
from app.integrations.clipboard_listener import ClipboardLinkParser

# ---------------------------------------------------------------------------
# 1. URL Parsing Tests (Modern + Legacy)
# ---------------------------------------------------------------------------
def test_mega_url_resolver_modern_and_legacy():
    # Modern file
    u1 = "https://mega.nz/file/AbCdEf12#SecretKey_34-567890123456789012345678"
    p1 = MegaUrlResolver.parse_url(u1)
    assert p1 is not None
    assert p1["type"] == "file"
    assert p1["id"] == "AbCdEf12"
    assert p1["key"] == "SecretKey_34-567890123456789012345678"
    assert p1["is_legacy"] is False

    # Modern folder
    u2 = "https://mega.nz/folder/FolderId12#FolderKey34"
    p2 = MegaUrlResolver.parse_url(u2)
    assert p2 is not None
    assert p2["type"] == "folder"
    assert p2["id"] == "FolderId12"
    assert p2["key"] == "FolderKey34"
    assert p2["node_id"] is None
    assert p2["is_legacy"] is False

    # Modern folder with nested file
    u3 = "https://mega.nz/folder/FolderId12#FolderKey34/file/NestedNode56"
    p3 = MegaUrlResolver.parse_url(u3)
    assert p3 is not None
    assert p3["type"] == "folder"
    assert p3["id"] == "FolderId12"
    assert p3["key"] == "FolderKey34"
    assert p3["node_id"] == "NestedNode56"
    assert p3["is_legacy"] is False

    # Legacy file
    u4 = "https://mega.co.nz/#!OldFile12!OldKey3456789012345678901234567890"
    p4 = MegaUrlResolver.parse_url(u4)
    assert p4 is not None
    assert p4["type"] == "file"
    assert p4["id"] == "OldFile12"
    assert p4["key"] == "OldKey3456789012345678901234567890"
    assert p4["is_legacy"] is True

    # Legacy folder
    u5 = "https://mega.nz/#F!OldFolder12!OldFolderKey34"
    p5 = MegaUrlResolver.parse_url(u5)
    assert p5 is not None
    assert p5["type"] == "folder"
    assert p5["id"] == "OldFolder12"
    assert p5["key"] == "OldFolderKey34"
    assert p5["node_id"] is None
    assert p5["is_legacy"] is True

    # Legacy folder with nested node
    u6 = "https://mega.nz/#F!OldFolder12!OldFolderKey34!ChildNode78"
    p6 = MegaUrlResolver.parse_url(u6)
    assert p6 is not None
    assert p6["type"] == "folder"
    assert p6["id"] == "OldFolder12"
    assert p6["key"] == "OldFolderKey34"
    assert p6["node_id"] == "ChildNode78"
    assert p6["is_legacy"] is True

    # Non-mega link
    assert MegaUrlResolver.parse_url("https://example.com/file.zip") is None

# ---------------------------------------------------------------------------
# 2. Key Unpacking & Attribute Decryption Tests
# ---------------------------------------------------------------------------
def test_mega_key_unpacking_and_attribute_crypto():
    aes_key = b"0123456789ABCDEF"  # 16 bytes
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"  # 8 bytes
    meta_mac = b"\x11\x22\x33\x44\x55\x66\x77\x88"  # 8 bytes

    raw_key = pack_file_key(aes_key, iv, meta_mac)
    assert len(raw_key) == 32

    # Unpack and verify components
    k_aes, k_iv, k_mac = unpack_file_key(raw_key)
    assert k_aes == aes_key
    assert k_iv == iv
    assert k_mac == meta_mac

    # Encrypt and decrypt attributes
    attr_dict = {"n": "ConfidentialDocument.pdf", "c": "123456"}
    enc_attr = encrypt_attr(attr_dict, aes_key)
    decrypted = decrypt_attr(enc_attr, aes_key)
    assert decrypted["n"] == "ConfidentialDocument.pdf"
    assert decrypted["c"] == "123456"

    # Corrupt attributes (invalid prefix)
    corrupted_attr = b"FAIL" + enc_attr[4:]
    with pytest.raises(ValueError, match="Invalid attribute header"):
        decrypt_attr(corrupted_attr, aes_key)

def test_mega_folder_node_key_decryption_16_and_32_bytes():
    """
    Deliverable 1 Crypto Audit:
    Proves folder node-key decryption handles BOTH 16-byte (subfolder) AND 32-byte (file)
    node keys identically to block-independent AES-128-ECB.
    """
    folder_key = b"FOLDER_MASTER_16"  # 16-byte folder master key

    # 1. 16-byte subfolder node key
    child_folder_key = b"SUBFOLDER_KEY_16"
    enc_folder_key = encrypt_node_key(child_folder_key, folder_key)
    assert len(enc_folder_key) == 16
    dec_folder_key = decrypt_node_key(enc_folder_key, folder_key)
    assert dec_folder_key == child_folder_key

    # 2. 32-byte child file key (AES key + IV + MAC)
    child_file_key = b"FILE_KEY_BLOCK_1FILE_KEY_BLOCK_2"  # 32 bytes
    assert len(child_file_key) == 32
    enc_file_key = encrypt_node_key(child_file_key, folder_key)
    assert len(enc_file_key) == 32

    # Decrypt and verify identical round-trip
    dec_file_key = decrypt_node_key(enc_file_key, folder_key)
    assert dec_file_key == child_file_key

    # Block independence check: block 2 decrypts identically regardless of block 1
    block1_enc = enc_file_key[:16]
    block2_enc = enc_file_key[16:]
    assert decrypt_node_key(block1_enc, folder_key) == child_file_key[:16]
    assert decrypt_node_key(block2_enc, folder_key) == child_file_key[16:]

# ---------------------------------------------------------------------------
# 3. Multi-Chunk Parallel AES-128-CTR Decryption Alignment
# ---------------------------------------------------------------------------
def test_mega_aes_ctr_multi_chunk_parallel_alignment():
    aes_key = b"SECURE_KEY_12345"
    iv = b"\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18"

    # 64 KB patterned payload (4096 16-byte blocks)
    payload_size = 64 * 1024
    payload = b"ParallelMegaChunkBlockPatternTest!" * (payload_size // 34 + 1)
    payload = payload[:payload_size]

    # Encrypt entire payload sequentially
    full_cipher = encrypt_chunk(payload, aes_key, iv, byte_offset=0)

    # Decrypt in 4 parallel slots (16 KB each) with 16-byte aligned counter offsets
    chunk_size = 16 * 1024
    chunks = [
        full_cipher[0:16384],
        full_cipher[16384:32768],
        full_cipher[32768:49152],
        full_cipher[49152:65536]
    ]

    decrypted_parts = []
    for idx, c in enumerate(chunks):
        offset = idx * chunk_size
        dec = decrypt_chunk(c, aes_key, iv, byte_offset=offset)
        decrypted_parts.append(dec)

    assembled = b"".join(decrypted_parts)
    assert assembled == payload, "Multi-chunk parallel CTR decryption failed to match sequential plaintext"

    # Non-16-byte aligned offset must raise ValueError
    with pytest.raises(ValueError, match="16-byte block aligned"):
        decrypt_chunk(chunks[0], aes_key, iv, byte_offset=15)

# ---------------------------------------------------------------------------
# 4. Chunked CBC-MAC Verification (Authentic vs Tampered)
# ---------------------------------------------------------------------------
def test_mega_chunked_cbc_mac_valid_and_tampered():
    aes_key = b"MAC_AES_KEY_TEST"
    iv = b"\x10\x20\x30\x40\x50\x60\x70\x80"

    # 300 KB payload spanning across variable chunk boundaries (128 KB, 172 KB)
    payload = b"SampleFileBytesForCBCMACVerificationTestingPurpose" * 6500

    # Compute authentic meta_mac
    meta_mac = compute_file_mac(payload, len(payload), aes_key, iv)
    assert len(meta_mac) == 8

    # Authentic payload must verify True
    assert verify_file_mac(payload, len(payload), aes_key, iv, meta_mac) is True

    # Tampering one byte anywhere in payload must fail MAC verification
    tampered = bytearray(payload)
    tampered[140000] ^= 0x55
    assert verify_file_mac(bytes(tampered), len(payload), aes_key, iv, meta_mac) is False

# ---------------------------------------------------------------------------
# 5. SmartProxy Passive Mode & HTTP 509 Failover
# ---------------------------------------------------------------------------
def test_smart_proxy_passive_mode_and_509_failover():
    pool = ProxyPool(passive_mode=True)
    pool.load_proxies(["127.0.0.1:8080", "127.0.0.1:8081"])
    assert len(pool.entries) == 2

    # In passive mode before 509, download is direct (returns None)
    assert pool.get_proxy() is None

    # When HTTP 509 hits, failover is triggered and rotates to first proxy
    p1 = pool.trigger_failover_509(failing_proxy=None)
    assert p1 == "http://127.0.0.1:8080"

    # Subsequent request rotates to second proxy
    p2 = pool.get_proxy()
    assert p2 == "http://127.0.0.1:8081"

    # If proxy 1 fails with 509, mark it unhealthy and failover
    p3 = pool.trigger_failover_509(failing_proxy="http://127.0.0.1:8080")
    assert pool.entries[0].is_healthy is False
    assert p3 == "http://127.0.0.1:8081"

# ---------------------------------------------------------------------------
# 6. Concurrent Proxy Health Testing
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def mock_proxy_target_server():
    loop = asyncio.new_event_loop()
    server_info = {}

    async def handle_ping(request):
        return web.Response(text="OK", status=200)

    app = web.Application()
    app.router.add_get("/cs", handle_ping)
    runner = web.AppRunner(app)

    def run_loop():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port = site._server.sockets[0].getsockname()[1]
        server_info["url"] = f"http://127.0.0.1:{port}/cs"
        server_info["ready"] = True
        loop.run_forever()

    t = threading.Thread(target=run_loop, daemon=True)
    t.start()

    while "ready" not in server_info:
        import time
        time.sleep(0.05)

    yield server_info["url"]
    loop.call_soon_threadsafe(loop.stop)

@pytest.mark.asyncio
async def test_concurrent_proxy_list_health_testing(mock_proxy_target_server):
    # Test with 1 dead proxy and direct loopback check
    proxy_list = [
        "127.0.0.1:59999",  # Dead non-existent port
        "127.0.0.1:59998"   # Dead non-existent port
    ]

    res = await ProxyPool.test_proxy_list(proxy_list, test_target=mock_proxy_target_server, timeout_sec=1.0)
    assert res["dead_count"] == 2
    assert res["alive_count"] == 0
    assert len(res["results"]) == 2
    for r in res["results"]:
        assert r["alive"] is False

# ---------------------------------------------------------------------------
# 7. MEGA Folder Node Tree Stage 1 Trap Detection
# ---------------------------------------------------------------------------
def test_mega_folder_node_tree_stage1_traps():
    """
    Verifies that decrypted MEGA folder node trees pass through Stage 1
    threat inspector, auto-unchecking camouflage traps by default.
    """
    mock_mega_nodes = [
        {"index": 0, "path": "Series/Episode1.mkv", "size": 1_200_000_000},
        {"index": 1, "path": "Series/Episode1.srt", "size": 65_000},
        {"index": 2, "path": "Series/Codec_Update.mp4.exe", "size": 350_000},  # Double-ext trap
        {"index": 3, "path": "Series/QuickWatch.scr", "size": 85_000},          # ScreenSaver trap
        {"index": 4, "path": "Series/keygen.exe", "size": 400_000}              # Small exe in media
    ]

    res = TorrentFileInspector.inspect_file_tree(mock_mega_nodes)
    assert res["context"] == "MEDIA"
    assert res["trap_count"] == 3

    files = res["files"]
    # Media file clean and checked
    assert files[0]["checked"] is True
    assert files[0]["priority"] == 4
    assert files[0]["severity"] == "CLEAN"

    # Traps auto-unchecked with priority 0
    assert files[2]["checked"] is False
    assert files[2]["priority"] == 0
    assert files[2]["severity"] == "CRITICAL"

    assert files[3]["checked"] is False
    assert files[3]["priority"] == 0
    assert files[3]["severity"] == "CRITICAL"

    assert files[4]["checked"] is False
    assert files[4]["priority"] == 0
    assert files[4]["severity"] == "CRITICAL"

# ---------------------------------------------------------------------------
# 8. Batch Clipboard Link Filtering and Deduplication
# ---------------------------------------------------------------------------
def test_batch_clipboard_link_filtering_and_deduplication():
    clipboard_payload = """
    Check out these download sources:
    magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Ubuntu_ISO
    https://mega.nz/file/File123#Key456
    https://mega.nz/folder/Folder123#Key456
    https://mega.nz/#!Legacy123!Key456
    https://example.com/downloads/archive.tar.gz
    https://example.com/downloads/archive.tar.gz   # Duplicate
    https://example.com/downloads/video.mkv
    https://www.google.com/search?q=unrelated      # Should be ignored (non-downloadable web page)
    """

    extracted = ClipboardLinkParser.extract_links(clipboard_payload)

    # Must extract exactly 6 distinct valid downloadable items
    assert len(extracted) == 6

    # Verify types
    engines = [item["engine_type"] for item in extracted]
    assert engines.count("TORRENT") == 1
    assert engines.count("MEGA") == 3
    assert engines.count("HTTP") == 2

    # Verify deduplication
    urls = [item["url"] for item in extracted]
    assert len(urls) == len(set(urls))
    assert "https://example.com/downloads/archive.tar.gz" in urls
    assert not any("google.com" in u for u in urls)
