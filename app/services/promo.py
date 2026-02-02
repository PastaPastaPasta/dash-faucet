"""Promo code service for the core faucet."""
import json
import time
from collections import defaultdict
from pathlib import Path
from threading import Lock

from app.config import settings
from app.middleware.rate_limit import normalize_ip


class PromoService:
    """Manages promo codes and per-IP usage tracking with 1-hour cooldown."""

    def __init__(self, path: str):
        self._codes: dict[str, float] = {}
        self._usage: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = Lock()
        self._load(path)

    def _load(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        with open(p) as f:
            data = json.load(f)
        for code, info in data.items():
            self._codes[code.upper()] = info["amount"]

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
