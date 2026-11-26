"""
OmniFetch SmartProxy Pool & Health Checker
Provides MegaBasterd-style proxy failover for MEGA.nz downloads:
- Passive Mode by default: Downloads directly at full speed with zero proxies.
- Automatic failover on HTTP 509 (Bandwidth Limit Exceeded) to healthy rotating proxies.
- Concurrent 'Test Proxy List' health tester measuring live latency and filtering dead proxies.
- Cooldown tracking for proxies returning 509 or timing out mid-download.
"""

import time
import asyncio
import aiohttp
from typing import List, Dict, Optional

class ProxyEntry:
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.url = self._normalize(self.raw)
        self.is_healthy = True
        self.latency_ms: Optional[float] = None
        self.last_failed_time = 0.0
        self.cooldown = 600.0  # 10 minutes default cooldown

    def _normalize(self, raw: str) -> str:
        if not raw.startswith("http://") and not raw.startswith("https://"):
            return f"http://{raw}"
        return raw

    def mark_failed(self, cooldown: float = 600.0):
        self.is_healthy = False
        self.last_failed_time = time.time()
        self.cooldown = cooldown

    def check_cooldown(self) -> bool:
        if not self.is_healthy:
            if time.time() - self.last_failed_time > self.cooldown:
                self.is_healthy = True
        return self.is_healthy

class ProxyPool:
    def __init__(self, passive_mode: bool = True):
        self.passive_mode = passive_mode
        self.entries: List[ProxyEntry] = []
        self._current_index = 0
        self._lock = asyncio.Lock()
        self._fallback_active = False

    def load_proxies(self, proxy_items: List[str] | str):
        """Loads and normalizes proxies from list or newline/comma-separated text."""
        if isinstance(proxy_items, str):
            lines = [line.strip() for line in proxy_items.replace(",", "\n").splitlines() if line.strip()]
        else:
            lines = [p.strip() for p in proxy_items if p and p.strip()]

        self.entries = [ProxyEntry(p) for p in lines]
        self._current_index = 0

    def get_proxy(self, force_proxy: bool = False) -> Optional[str]:
        """
        Returns next healthy proxy URL, or None if in passive direct mode and no failover active.
        """
        # If in passive mode and failover is not triggered, download directly (None)
        if self.passive_mode and not self._fallback_active and not force_proxy:
            return None

        # Check cooldowns
        for entry in self.entries:
            entry.check_cooldown()

        healthy = [e for e in self.entries if e.is_healthy]
        if not healthy:
            return None

        idx = self._current_index % len(healthy)
        self._current_index += 1
        return healthy[idx].url

    def trigger_failover_509(self, failing_proxy: Optional[str] = None, cooldown: float = 600.0) -> Optional[str]:
        """
        Called when HTTP 509 hits.
        Marks failing proxy unhealthy and activates proxy pool rotation.
        """
        self._fallback_active = True
        if failing_proxy:
            for entry in self.entries:
                if entry.url == failing_proxy or entry.raw == failing_proxy:
                    entry.mark_failed(cooldown=cooldown)
                    break

        return self.get_proxy(force_proxy=True)

    def mark_proxy_dead(self, proxy_url: str):
        for entry in self.entries:
            if entry.url == proxy_url or entry.raw == proxy_url:
                entry.mark_failed(cooldown=3600.0)
                break

    @staticmethod
    async def test_single_proxy(proxy_url: str, test_target: str = "https://g.api.mega.co.nz/cs", timeout_sec: float = 5.0) -> Dict:
        """Probes a single proxy measuring connection and response latency."""
        norm_url = proxy_url if proxy_url.startswith("http") else f"http://{proxy_url}"
        t0 = time.time()
        timeout = aiohttp.ClientTimeout(total=timeout_sec, connect=min(3.0, timeout_sec))
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(test_target, proxy=norm_url, ssl=False) as resp:
                    latency = round((time.time() - t0) * 1000, 1)
                    if resp.status < 500:
                        return {"proxy": norm_url, "alive": True, "latency_ms": latency, "status": resp.status, "error": None}
                    else:
                        return {"proxy": norm_url, "alive": False, "latency_ms": latency, "status": resp.status, "error": f"HTTP {resp.status}"}
        except Exception as e:
            latency = round((time.time() - t0) * 1000, 1)
            return {"proxy": norm_url, "alive": False, "latency_ms": latency, "status": 0, "error": str(e)}

    @classmethod
    async def test_proxy_list(
        cls,
        proxy_strings: List[str],
        test_target: str = "https://g.api.mega.co.nz/cs",
        timeout_sec: float = 5.0
    ) -> Dict:
        """
        Concurrently probes all configured proxies with timeout.
        Filters out dead proxies, sorts alive proxies by latency ascending.
        """
        if not proxy_strings:
            return {"alive_count": 0, "dead_count": 0, "alive_proxies": [], "results": []}

        tasks = [cls.test_single_proxy(p, test_target, timeout_sec) for p in proxy_strings if p.strip()]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        alive = [r for r in results if r["alive"]]
        dead = [r for r in results if not r["alive"]]

        # Sort alive proxies by latency ms ascending
        alive.sort(key=lambda x: x["latency_ms"])

        return {
            "alive_count": len(alive),
            "dead_count": len(dead),
            "alive_proxies": [r["proxy"] for r in alive],
            "results": alive + dead
        }
