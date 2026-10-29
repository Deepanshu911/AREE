"""
server/device_manager.py — Cryptographic device registration, authentication, and state management.
"""
import hashlib
import hmac
import logging
import secrets
from typing import Any, Dict, Optional, Tuple
from store.db import IncidentDB

logger = logging.getLogger(__name__)

class DeviceManager:
    """Manages secure registration, credential hashing, and multi-device authentication."""

    SALT = "AREE_MULTI_DEVICE_SECURITY_SALT_2026"

    def __init__(self, db: Optional[IncidentDB] = None):
        self.db = db or IncidentDB()

    @classmethod
    def hash_token(cls, raw_token: str) -> str:
        """Computes salted SHA-256 digest of authentication token."""
        payload = f"{cls.SALT}:{raw_token}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def enroll_device(self, device_name: str, os_type: str,
                      custom_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        """
        Enrolls a new device.
        Returns: (device_id, raw_secret_token)
        NOTE: raw_secret_token is returned ONLY during enrollment and never stored in plaintext.
        """
        device_id = custom_id or f"dev-{secrets.token_hex(4)}"
        raw_token = f"aree_tok_{secrets.token_urlsafe(24)}"
        token_hash = self.hash_token(raw_token)

        self.db.register_device(
            device_id=device_id,
            device_name=device_name or f"Device-{device_id[-4:]}",
            os_type=os_type or "Unknown OS",
            token_hash=token_hash,
            metadata=metadata or {}
        )
        logger.info("Enrolled new device: %s (%s)", device_id, device_name)
        return device_id, raw_token

    def authenticate(self, device_id: str, raw_token: str) -> bool:
        """Validates incoming Bearer token using constant-time comparison."""
        device = self.db.get_device(device_id)
        if not device:
            return False

        stored_hash = device.get("auth_token_hash", "")
        incoming_hash = self.hash_token(raw_token)
        return hmac.compare_digest(stored_hash, incoming_hash)

    def record_heartbeat(self, device_id: str) -> bool:
        return self.db.update_device_heartbeat(device_id, status="connected")

    def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_device(device_id)

    def list_all_devices(self) -> list:
        return self.db.list_devices()
