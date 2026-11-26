"""
OmniFetch MEGA.nz URL Resolver
Parses modern and legacy MEGA.nz file and folder links into standardized descriptors.
"""

import re

class MegaUrlResolver:
    @staticmethod
    def is_mega_url(url: str) -> bool:
        if not url or not isinstance(url, str):
            return False
        return MegaUrlResolver.parse_url(url) is not None

    @staticmethod
    def parse_url(url: str) -> dict | None:
        """
        Parses modern and legacy MEGA.nz file and folder URLs:
        - Modern file: https://mega.nz/file/<id>#<key>
        - Modern folder: https://mega.nz/folder/<id>#<key>
        - Modern folder nested file: https://mega.nz/folder/<id>#<key>/file/<node_id>
        - Legacy file: https://mega.nz/#!<id>!<key>
        - Legacy folder: https://mega.nz/#F!<id>!<key>
        - Legacy folder nested file: https://mega.nz/#F!<id>!<key>!<node_id>
        """
        if not url or not isinstance(url, str):
            return None

        clean_url = url.strip()

        # 1. Modern folder nested file: /folder/<folder_id>#<key>/file/<node_id>
        m = re.search(
            r'mega\.(?:nz|co\.nz)/folder/([a-zA-Z0-9_-]+)#([a-zA-Z0-9_-]+)/file/([a-zA-Z0-9_-]+)',
            clean_url,
            re.IGNORECASE
        )
        if m:
            return {
                "type": "folder",
                "id": m.group(1),
                "key": m.group(2),
                "node_id": m.group(3),
                "is_legacy": False,
                "raw_url": clean_url
            }

        # 2. Modern folder: /folder/<folder_id>#<key>
        m = re.search(
            r'mega\.(?:nz|co\.nz)/folder/([a-zA-Z0-9_-]+)#([a-zA-Z0-9_-]+)',
            clean_url,
            re.IGNORECASE
        )
        if m:
            return {
                "type": "folder",
                "id": m.group(1),
                "key": m.group(2),
                "node_id": None,
                "is_legacy": False,
                "raw_url": clean_url
            }

        # 3. Modern file: /file/<file_id>#<key>
        m = re.search(
            r'mega\.(?:nz|co\.nz)/file/([a-zA-Z0-9_-]+)#([a-zA-Z0-9_-]+)',
            clean_url,
            re.IGNORECASE
        )
        if m:
            return {
                "type": "file",
                "id": m.group(1),
                "key": m.group(2),
                "node_id": None,
                "is_legacy": False,
                "raw_url": clean_url
            }

        # 4. Legacy folder with nested node: /#F!<folder_id>!<key>!<node_id>
        m = re.search(
            r'mega\.(?:nz|co\.nz)/#F!([a-zA-Z0-9_-]+)!([a-zA-Z0-9_-]+)!([a-zA-Z0-9_-]+)',
            clean_url,
            re.IGNORECASE
        )
        if m:
            return {
                "type": "folder",
                "id": m.group(1),
                "key": m.group(2),
                "node_id": m.group(3),
                "is_legacy": True,
                "raw_url": clean_url
            }

        # 5. Legacy folder: /#F!<folder_id>!<key>
        m = re.search(
            r'mega\.(?:nz|co\.nz)/#F!([a-zA-Z0-9_-]+)!([a-zA-Z0-9_-]+)',
            clean_url,
            re.IGNORECASE
        )
        if m:
            return {
                "type": "folder",
                "id": m.group(1),
                "key": m.group(2),
                "node_id": None,
                "is_legacy": True,
                "raw_url": clean_url
            }

        # 6. Legacy file: /#!<file_id>!<key>
        m = re.search(
            r'mega\.(?:nz|co\.nz)/#!([a-zA-Z0-9_-]+)!([a-zA-Z0-9_-]+)',
            clean_url,
            re.IGNORECASE
        )
        if m:
            return {
                "type": "file",
                "id": m.group(1),
                "key": m.group(2),
                "node_id": None,
                "is_legacy": True,
                "raw_url": clean_url
            }

        return None
