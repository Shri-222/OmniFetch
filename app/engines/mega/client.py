"""
OmniFetch MEGA.nz API Client
Communicates with MEGA Client-Server API (https://g.api.mega.co.nz/cs):
- Queries file metadata & temporary download URLs.
- Queries shared folder node hierarchy, decrypts child node keys and attributes.
- Reconstructs relative directory structures for selective file downloads.
"""

import aiohttp
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .resolver import MegaUrlResolver
from .crypto import (
    base64_url_decode,
    unpack_file_key,
    decrypt_node_key,
    decrypt_attr
)
from ...core.ssl_context import get_ssl_context

MEGA_API_BASE = "https://g.api.mega.co.nz/cs"

class MegaClient:
    def __init__(self, proxy_pool=None):
        self.proxy_pool = proxy_pool

    async def _post_api(self, payload: list, params: Optional[dict] = None, proxy: Optional[str] = None) -> list:
        url = MEGA_API_BASE
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"

        headers = {"Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=20, connect=10)
        connector = aiohttp.TCPConnector(ssl=get_ssl_context())

        # Use passed proxy, or proxy from pool, or direct (None)
        effective_proxy = proxy or (self.proxy_pool.get_proxy() if self.proxy_pool else None)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.post(url, json=payload, headers=headers, proxy=effective_proxy) as resp:
                if resp.status == 509:
                    raise PermissionError("HTTP 509 Bandwidth Limit Exceeded")
                if resp.status != 200:
                    raise ConnectionError(f"MEGA API returned HTTP {resp.status}")
                data = await resp.json()
                if isinstance(data, list) and len(data) > 0 and isinstance(data[0], int) and data[0] < 0:
                    err_code = data[0]
                    raise ValueError(f"MEGA API Error code {err_code}")
                return data

    async def get_file_info(self, file_id: str, file_key_b64: str, proxy: Optional[str] = None) -> Dict:
        """
        Retrieves file metadata, decrypted filename, size, and temporary storage download URL.
        """
        raw_key = base64_url_decode(file_key_b64)
        if len(raw_key) != 32:
            raise ValueError(f"Invalid file key length: {len(raw_key)} bytes (expected 32)")

        aes_key, iv, meta_mac = unpack_file_key(raw_key)

        req = [{"a": "g", "g": 1, "p": file_id}]
        res = await self._post_api(req, proxy=proxy)
        file_data = res[0]

        enc_attr = base64_url_decode(file_data["at"])
        attr = decrypt_attr(enc_attr, aes_key)
        filename = attr.get("n", f"{file_id}.bin")

        return {
            "file_id": file_id,
            "filename": filename,
            "size": file_data["s"],
            "download_url": file_data["g"],
            "aes_key": aes_key,
            "iv": iv,
            "meta_mac": meta_mac,
            "raw_key": raw_key
        }

    async def get_folder_nodes(self, folder_id: str, folder_key_b64: str, proxy: Optional[str] = None) -> List[Dict]:
        """
        Retrieves full node hierarchy for a shared folder, decrypts all child node keys
        and attributes, and builds relative paths for each file.
        """
        folder_key = base64_url_decode(folder_key_b64)
        if len(folder_key) != 16:
            raise ValueError(f"Invalid folder key length: {len(folder_key)} bytes (expected 16)")

        req = [{"a": "f", "c": 1, "r": 1}]
        res = await self._post_api(req, params={"n": folder_id}, proxy=proxy)
        nodes_raw = res[0].get("f", [])

        # Pass 1: Decrypt node keys and attributes
        nodes_by_id = {}
        for n in nodes_raw:
            handle = n["h"]
            parent = n.get("p", "")
            ntype = n.get("t", 0)  # 0=file, 1=folder, 2=root

            k_str = n.get("k", "")
            if "/" in k_str:
                k_str = k_str.split("/")[-1]
            if ":" in k_str:
                k_str = k_str.split(":")[-1]

            decrypted_key = None
            aes_key = None
            iv = None
            meta_mac = None

            if k_str:
                try:
                    enc_key = base64_url_decode(k_str)
                    decrypted_key = decrypt_node_key(enc_key, folder_key)
                    if ntype == 0 and len(decrypted_key) == 32:
                        aes_key, iv, meta_mac = unpack_file_key(decrypted_key)
                    elif ntype in (1, 2) and len(decrypted_key) >= 16:
                        aes_key = decrypted_key[:16]
                except Exception:
                    pass

            name = f"node_{handle}"
            if aes_key and "a" in n:
                try:
                    enc_attr = base64_url_decode(n["a"])
                    attr = decrypt_attr(enc_attr, aes_key)
                    name = attr.get("n", name)
                except Exception:
                    pass

            nodes_by_id[handle] = {
                "id": handle,
                "parent": parent,
                "type": ntype,
                "name": name,
                "size": n.get("s", 0),
                "aes_key": aes_key,
                "iv": iv,
                "meta_mac": meta_mac,
                "raw_key": decrypted_key
            }

        # Pass 2: Reconstruct hierarchical paths
        def resolve_path(h: str) -> str:
            path_parts = []
            curr = h
            while curr in nodes_by_id:
                node = nodes_by_id[curr]
                if node["type"] in (0, 1):  # Include file or subfolder
                    path_parts.append(node["name"])
                curr = node["parent"]
            path_parts.reverse()
            return "/".join(path_parts) if path_parts else nodes_by_id[h]["name"]

        file_list = []
        for idx, (h, item) in enumerate(nodes_by_id.items()):
            if item["type"] == 0:  # Only files are downloadable payload targets
                rel_path = resolve_path(h)
                file_list.append({
                    "index": len(file_list),
                    "id": item["id"],
                    "path": rel_path,
                    "name": item["name"],
                    "size": item["size"],
                    "type": "file",
                    "aes_key": item["aes_key"],
                    "iv": item["iv"],
                    "meta_mac": item["meta_mac"],
                    "raw_key": item["raw_key"]
                })

        return file_list

    async def get_folder_file_download_url(self, folder_id: str, node_id: str, proxy: Optional[str] = None) -> Dict:
        """Retrieves temporary direct download URL for a file node inside a shared folder."""
        req = [{"a": "g", "g": 1, "n": node_id}]
        res = await self._post_api(req, params={"n": folder_id}, proxy=proxy)
        file_data = res[0]
        return {
            "download_url": file_data["g"],
            "size": file_data["s"]
        }
