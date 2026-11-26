"""
OmniFetch SSL / TLS Context Factory
Ensures valid CA bundle is provided via certifi so HTTPS requests never fail TLS validation in frozen binaries.
"""

import os
import ssl
import sys
from pathlib import Path
from .logger import get_logger

logger = get_logger("ssl")

def get_ca_bundle_path() -> str:
    """Returns absolute path to valid cacert.pem, resolving PyInstaller sys._MEIPASS when frozen."""
    try:
        import certifi
        cafile = certifi.where()
        if os.path.exists(cafile):
            return cafile
    except Exception:
        pass

    # Check sys._MEIPASS for PyInstaller
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass_cert = Path(sys._MEIPASS) / "certifi" / "cacert.pem"
        if meipass_cert.exists():
            return str(meipass_cert)

    # Fallback to standard OpenSSL default
    return ssl.get_default_verify_paths().cafile or ""

def get_ssl_context() -> ssl.SSLContext:
    """Builds an SSLContext configured with certifi's CA certificates."""
    cafile = get_ca_bundle_path()
    if cafile and os.path.exists(cafile):
        try:
            return ssl.create_default_context(cafile=cafile)
        except Exception as e:
            logger.warning(f"Failed to create default SSL context with {cafile}: {e}")
    return ssl.create_default_context()

def setup_ssl_environment():
    """Sets SSL_CERT_FILE environment variable for libraries checking env vars."""
    cafile = get_ca_bundle_path()
    if cafile and os.path.exists(cafile):
        os.environ["SSL_CERT_FILE"] = cafile
        logger.debug(f"Configured SSL_CERT_FILE: {cafile}")
