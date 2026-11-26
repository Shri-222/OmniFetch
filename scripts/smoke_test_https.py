"""
Live HTTPS Smoke Test:
Verifies SSL context initialization and successful HTTPS probing with certifi CA bundle.
"""
import sys
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.ssl_context import get_ca_bundle_path, get_ssl_context
from app.engines.http.downloader import HttpDownloader
from app.core.db import Database
from app.core.staging import StagingManager

def test_live_https():
    ca_path = get_ca_bundle_path()
    print(f"Active CA Bundle: {ca_path}")
    assert Path(ca_path).exists(), f"CA bundle not found at {ca_path}"

    ctx = get_ssl_context()
    print(f"SSL Context initialized: {ctx.protocol.name}")

    db = Database(":memory:")
    sm = StagingManager(".staging")
    dl = HttpDownloader(db, sm)

    async def run_probe():
        # Test probing an HTTPS URL
        url = "https://httpbin.org/get"
        try:
            res = await dl.probe(url)
            print(f"Probe succeeded: status={res.get('status')}, filename={res.get('filename')}")
            return True
        except Exception as e:
            print(f"HTTPS Probe failed: {e}")
            return False

    success = asyncio.run(run_probe())
    db.close()
    print(f"HTTPS Smoke Test: {'PASS' if success else 'FAIL'}")
    return success

if __name__ == "__main__":
    ok = test_live_https()
    sys.exit(0 if ok else 1)
