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
            with open(p) as f:
                data = json.load(f)
            for code, info in data.items():
                self._codes[code.upper()] = info["amount"]

        # Merge in env var codes (overrides file entries on conflict)
        env_codes = os.environ.get("PROMO_CODES")
        if env_codes:
            try:
                data = json.loads(env_codes)
                for code, info in data.items():
                    self._codes[code.upper()] = info["amount"]
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(
                    "Invalid PROMO_CODES env var (falling back to file only): "
                    "%s — value was: %s", e, env_codes
                )

    def validate(self, code: str, ip: str) -> float | None:
        """Return the promo amount if the code is valid and not used by this IP
        within the last hour. Returns None if the code is unknown."""
        code = code.upper()
        ip = normalize_ip(ip)

        if code not in self._codes:
            return None

        now = time.time()
        with self._lock:
            self._cleanup(code, now)
            if ip in self._usage[code]:
                return None
            return self._codes[code]

    def record_usage(self, code: str, ip: str) -> None:
        code = code.upper()
        ip = normalize_ip(ip)
        with self._lock:
            self._usage[code][ip] = time.time()

    def _cleanup(self, code: str, now: float) -> None:
        cutoff = now - 3600
        self._usage[code] = {
            ip: ts for ip, ts in self._usage[code].items() if ts > cutoff
        }


promo_service = PromoService(settings.promo_codes_file)
