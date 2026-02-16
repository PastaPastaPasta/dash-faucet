"""Promo code service for the core faucet."""
import json
import logging
import os
import time
from collections import defaultdict
from pathlib import Path
from threading import Lock

from app.config import settings
from app.middleware.rate_limit import normalize_ip

logger = logging.getLogger(__name__)


class PromoService:
    """Manages promo codes and per-IP usage tracking with 1-hour cooldown."""

    def __init__(self, path: str):
        self._codes: dict[str, float] = {}
        self._usage: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = Lock()
        self._load(path)

    def _load(self, path: str) -> None:
        # Load from JSON file first
        p = Path(path)
        if p.exists():
            try:
                with open(p) as f:
                    data = json.load(f)
                for code, info in data.items():
                    self._codes[code.upper()] = info["amount"]
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning(
                    "Failed to load promo codes from %s: %s", p, e
                )
        else:
            logger.warning("Promo codes file not found: %s", p)

        # Merge in env var codes (overrides file entries on conflict)
        env_codes = os.environ.get("PROMO_CODES")
        if env_codes:
            try:
                data = json.loads(env_codes)
                for code, info in data.items():
                    self._codes[code.upper()] = info["amount"]
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning(
                    "Invalid PROMO_CODES env var (falling back to file only): %s",
                    e,
                )

    def claim(self, code: str, ip: str) -> float | None:
        """Atomically validate and record promo code usage.

        Returns the promo amount if the code is valid and not used by this IP
        within the last hour. Returns None otherwise.

        This combines validation and recording under a single lock to prevent
        TOCTOU race conditions with concurrent redemptions.
        """
        code = code.upper()
        ip = normalize_ip(ip)

        if code not in self._codes:
            return None

        now = time.time()
        with self._lock:
            self._cleanup(code, now)
            if ip in self._usage[code]:
                return None
            # Record usage atomically with validation
            self._usage[code][ip] = now
            return self._codes[code]

    def release(self, code: str, ip: str) -> None:
        """Undo a claim (e.g. when the transaction fails after claiming).

        Removes the usage record so the IP can try again.
        """
        code = code.upper()
        ip = normalize_ip(ip)
        with self._lock:
            self._usage[code].pop(ip, None)

    def _cleanup(self, code: str, now: float) -> None:
        cutoff = now - 3600
        self._usage[code] = {
            ip: ts for ip, ts in self._usage[code].items() if ts > cutoff
        }


promo_service = PromoService(settings.promo_codes_file)
