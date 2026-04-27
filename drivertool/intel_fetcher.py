"""
IntelFetcher
============
Fetches and normalizes vulnerable driver intelligence from multiple
external sources into a unified local cache at
``~/.cache/drivertool/intel_db.json``.

Sources
-------
* LOLDrivers GitHub repository (ZIP + YAML metadata)
* LOLDrivers API / JSON endpoint
* Microsoft Vulnerable Driver Block List (aka.ms)
* MalwareBazaar API (tag:driver metadata + optional sample download)
* Hybrid Analysis API (sandbox reports for known drivers)
* HEVD GitHub (HackSys Extreme Vulnerable Driver for test coverage)

Each source is fetched independently, normalized into a common
``DriverIntelEntry`` schema, and merged incrementally into the local DB.
"""

from __future__ import annotations

import io
import json
import logging
import os
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────

LOLDRIVERS_GITHUB_ZIP = (
    "https://github.com/magicsword-io/LOLDrivers/archive/refs/heads/main.zip"
)
LOLDRIVERS_API_ENDPOINTS = (
    "https://www.loldrivers.io/api/drivers.json",
    "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/api/drivers.json",
)

MS_BLOCKLIST_URL = "https://aka.ms/VulnerableDriverBlockList"

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

HYBRID_ANALYSIS_API = "https://www.hybrid-analysis.com/api/v2/search/terms"

HEVD_GITHUB_ZIP = (
    "https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/"
    "archive/refs/heads/master.zip"
)

STALE_DAYS = 7


# ── Data model ──────────────────────────────────────────────────────────

@dataclass
class DriverIntelEntry:
    """Normalized driver intelligence entry."""

    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    name: str = ""
    filename: str = ""
    source: str = ""
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[str] = None
    file_size: Optional[int] = None
    local_path: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def key(self) -> str:
        return self.sha256.lower()


# ── Fetcher ─────────────────────────────────────────────────────────────

class IntelFetcher:
    """Unified external driver-intelligence fetcher."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or (Path.home() / ".cache" / "drivertool")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir = self.cache_dir / "intel_binaries"
        self.bin_dir.mkdir(exist_ok=True)

        self.db_path = self.cache_dir / "intel_db.json"
        self.meta_path = self.cache_dir / "intel_meta.json"

        self.db: Dict[str, DriverIntelEntry] = {}
        self.meta: Dict[str, float] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        if self.db_path.exists():
            try:
                with self.db_path.open("r", encoding="utf-8") as f:
                    raw = json.load(f)
                for item in raw:
                    entry = DriverIntelEntry(**item)
                    self.db[entry.key()] = entry
            except Exception:
                logger.debug("Intel DB load failed", exc_info=True)
                self.db = {}

        if self.meta_path.exists():
            try:
                with self.meta_path.open("r", encoding="utf-8") as f:
                    self.meta = json.load(f)
            except Exception:
                logger.debug("Intel meta load failed", exc_info=True)
                self.meta = {}

    def save(self) -> None:
        try:
            with self.db_path.open("w", encoding="utf-8") as f:
                json.dump([asdict(e) for e in self.db.values()], f, indent=2)
        except Exception:
            logger.debug("Intel DB save failed", exc_info=True)

        try:
            with self.meta_path.open("w", encoding="utf-8") as f:
                json.dump(self.meta, f, indent=2)
        except Exception:
            logger.debug("Intel meta save failed", exc_info=True)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def fetch_all(self, force: bool = False) -> Dict[str, Tuple[int, int]]:
        """Fetch every source and return stats:
        {source_name: (entries_added, binaries_downloaded)}.
        """
        results: Dict[str, Tuple[int, int]] = {}
        sources = [
            ("loldrivers_github", self._fetch_loldrivers_github),
            ("loldrivers_api", self._fetch_loldrivers_api),
            ("ms_blocklist", self._fetch_ms_blocklist),
            ("malwarebazaar", self._fetch_malwarebazaar),
            ("hybrid_analysis", self._fetch_hybrid_analysis),
            ("hevd", self._fetch_hevd),
        ]

        for name, fetcher in sources:
            if not force and self._is_fresh(name):
                logger.debug("Skipping %s (cache fresh)", name)
                results[name] = (0, 0)
                continue
            try:
                entries, binaries = fetcher()
                self._merge(entries)
                self.meta[f"{name}_last_fetch"] = time.time()
                results[name] = (len(entries), binaries)
            except Exception:
                logger.debug("Source %s failed", name, exc_info=True)
                results[name] = (0, 0)

        self.save()
        return results

    def get_hashes(self) -> Dict[str, str]:
        """Return {sha256_lowercase: name} for quick lookups."""
        return {
            e.sha256.lower(): (e.name or e.filename or "unknown")
            for e in self.db.values()
            if e.sha256
        }

    def get_entries(self) -> List[DriverIntelEntry]:
        return list(self.db.values())

    def count_binaries(self) -> int:
        return sum(
            1
            for e in self.db.values()
            if e.local_path and Path(e.local_path).exists()
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _is_fresh(self, name: str) -> bool:
        last = self.meta.get(f"{name}_last_fetch")
        if not last:
            return False
        return (time.time() - last) / 86400.0 < STALE_DAYS

    def _merge(self, entries: List[DriverIntelEntry]) -> None:
        for entry in entries:
            key = entry.key()
            if key in self.db:
                existing = self.db[key]
                existing.tags = list({*existing.tags, *entry.tags})
                existing.references = list({*existing.references, *entry.references})
                # Track every source that knows about this sample
                srcs = {s.strip() for s in existing.source.split(",") if s.strip()}
                srcs.add(entry.source)
                existing.source = ",".join(sorted(srcs))
                # Prefer non-empty fields from new data
                if entry.name and not existing.name:
                    existing.name = entry.name
                if entry.filename and not existing.filename:
                    existing.filename = entry.filename
                if entry.description and not existing.description:
                    existing.description = entry.description
                if entry.local_path and not existing.local_path:
                    existing.local_path = entry.local_path
                if entry.first_seen and not existing.first_seen:
                    existing.first_seen = entry.first_seen
            else:
                self.db[key] = entry

    def _download_zip(self, url: str, timeout: float = 60.0) -> bytes:
        with urlopen(url, timeout=timeout) as resp:
            return resp.read()

    def _write_binary(self, filename: str, data: bytes) -> Optional[str]:
        try:
            path = self.bin_dir / filename
            path.write_bytes(data)
            return str(path)
        except Exception:
            logger.debug("Failed to write binary %s", filename, exc_info=True)
            return None

    # ------------------------------------------------------------------ #
    # Source 1: LOLDrivers GitHub ZIP
    # ------------------------------------------------------------------ #

    def _fetch_loldrivers_github(self) -> Tuple[List[DriverIntelEntry], int]:
        zip_bytes = self._download_zip(LOLDRIVERS_GITHUB_ZIP)
        entries: List[DriverIntelEntry] = []
        binaries = 0

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for info in z.infolist():
                if info.filename.startswith("__MACOSX"):
                    continue
                parts = info.filename.split("/")
                if len(parts) < 3:
                    continue

                # YAML metadata
                if parts[1] == "yaml" and info.filename.endswith(".yaml"):
                    data = z.read(info.filename)
                    entries.extend(_parse_loldrivers_yaml(data))

                # Binary drivers
                elif parts[1] == "drivers" and info.filename.endswith(".sys"):
                    filename = parts[-1]
                    data = z.read(info.filename)
                    local = self._write_binary(filename, data)
                    if local:
                        binaries += 1
                        # Link binary to any existing entry with matching filename
                        for e in entries:
                            if e.filename == filename:
                                e.local_path = local

        return entries, binaries

    # ------------------------------------------------------------------ #
    # Source 2: LOLDrivers API
    # ------------------------------------------------------------------ #

    def _fetch_loldrivers_api(self) -> Tuple[List[DriverIntelEntry], int]:
        entries: List[DriverIntelEntry] = []
        for url in LOLDRIVERS_API_ENDPOINTS:
            try:
                with urlopen(url, timeout=20.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                # Expect either a list or a dict with "drivers" key
                drivers = data if isinstance(data, list) else data.get("drivers", [])
                for item in drivers:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("Name") or item.get("name", "unknown")
                    samples = item.get("KnownVulnerableSamples") or []
                    if isinstance(samples, dict):
                        samples = [samples]
                    for sample in samples:
                        if not isinstance(sample, dict):
                            continue
                        sha = sample.get("SHA256") or sample.get("sha256")
                        if sha:
                            entries.append(DriverIntelEntry(
                                sha256=sha.lower(),
                                name=name,
                                source="loldrivers_api",
                                tags=["loldrivers"],
                                references=[url],
                            ))
                # If we got here, one endpoint succeeded — stop trying
                break
            except Exception:
                logger.debug("LOLDrivers API endpoint failed: %s", url, exc_info=True)
        return entries, 0

    # ------------------------------------------------------------------ #
    # Source 3: Microsoft Vulnerable Driver Block List
    # ------------------------------------------------------------------ #

    def _fetch_ms_blocklist(self) -> Tuple[List[DriverIntelEntry], int]:
        # Re-use policy_cache logic so we don't duplicate the CIP parser
        from drivertool import policy_cache as _pc
        entries: List[DriverIntelEntry] = []
        try:
            bl_sha1, bl_sha256, _age = _pc.load_driver_blocklist(
                auto_fetch=True, max_age_days=0)
            for h in bl_sha256:
                entries.append(DriverIntelEntry(
                    sha256=h.lower(),
                    sha1=None,
                    name="Microsoft blocked driver",
                    source="ms_blocklist",
                    tags=["blocked-by-microsoft", "vulnerable"],
                    description="Listed in Microsoft recommended driver block rules",
                    references=[MS_BLOCKLIST_URL],
                ))
            for h in bl_sha1:
                entries.append(DriverIntelEntry(
                    sha256="",
                    sha1=h.lower(),
                    name="Microsoft blocked driver",
                    source="ms_blocklist",
                    tags=["blocked-by-microsoft", "vulnerable"],
                    description="Listed in Microsoft recommended driver block rules",
                    references=[MS_BLOCKLIST_URL],
                ))
        except Exception:
            logger.debug("MS blocklist fetch failed", exc_info=True)
        return entries, 0

    # ------------------------------------------------------------------ #
    # Source 4: MalwareBazaar API
    # ------------------------------------------------------------------ #

    def _fetch_malwarebazaar(self) -> Tuple[List[DriverIntelEntry], int]:
        entries: List[DriverIntelEntry] = []
        binaries = 0
        try:
            req = Request(
                MALWAREBAZAAR_API,
                data=json.dumps({
                    "query": "get_taginfo",
                    "tag": "driver",
                    "limit": 1000,
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=30.0) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            if result.get("query_status") != "ok":
                logger.debug("MalwareBazaar returned: %s", result.get("query_status"))
                return entries, binaries

            for item in result.get("data", []):
                sha256 = (item.get("sha256_hash") or "").lower()
                if not sha256:
                    continue
                entry = DriverIntelEntry(
                    sha256=sha256,
                    sha1=(item.get("sha1_hash") or "").lower() or None,
                    md5=(item.get("md5_hash") or "").lower() or None,
                    filename=item.get("file_name", ""),
                    name=item.get("file_name", "MalwareBazaar driver sample"),
                    source="malwarebazaar",
                    tags=item.get("tags", []) + ["malwarebazaar"],
                    description=f"Signature: {item.get('signature', 'unknown')}",
                    first_seen=item.get("first_seen"),
                    file_size=item.get("file_size"),
                    references=[f"https://bazaar.abuse.ch/sample/{sha256}/"],
                )
                entries.append(entry)

                # Optional: download the sample ZIP (password: infected)
                # This is gated behind an env var to avoid accidental bulk
                # malware downloads.
                if os.environ.get("DRIVERTOOL_FETCH_MALWARE_SAMPLES"):
                    try:
                        dl_req = Request(
                            MALWAREBAZAAR_API,
                            data=json.dumps({
                                "query": "get_file",
                                "sha256_hash": sha256,
                            }).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with urlopen(dl_req, timeout=60.0) as dl_resp:
                            zip_data = dl_resp.read()
                        # MalwareBazaar returns a ZIP with the sample inside
                        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                            for info in z.infolist():
                                if info.filename.endswith(".sys"):
                                    fname = f"mb_{sha256[:16]}_{info.filename}"
                                    local = self._write_binary(
                                        fname, z.read(info.filename))
                                    if local:
                                        entry.local_path = local
                                        binaries += 1
                                        break
                    except Exception:
                        logger.debug("Sample download failed for %s", sha256,
                                     exc_info=True)

        except Exception:
            logger.debug("MalwareBazaar fetch failed", exc_info=True)
        return entries, binaries

    # ------------------------------------------------------------------ #
    # Source 5: Hybrid Analysis API
    # ------------------------------------------------------------------ #

    def _fetch_hybrid_analysis(self) -> Tuple[List[DriverIntelEntry], int]:
        entries: List[DriverIntelEntry] = []
        api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
        if not api_key:
            logger.debug(
                "Hybrid Analysis skipped — set HYBRID_ANALYSIS_API_KEY env var")
            return entries, 0

        try:
            req = Request(
                HYBRID_ANALYSIS_API,
                data=json.dumps({
                    "filename": "*.sys",
                    "sort": "relevance",
                    "limit": 100,
                }).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "api-key": api_key,
                    "User-Agent": "Falcon",
                },
                method="POST",
            )
            with urlopen(req, timeout=30.0) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            for item in result.get("result", []):
                sha256 = (item.get("sha256") or "").lower()
                if not sha256:
                    continue
                tags = item.get("tags", []) + ["hybrid-analysis"]
                entry = DriverIntelEntry(
                    sha256=sha256,
                    name=item.get("submit_name", "Hybrid Analysis driver"),
                    filename=item.get("submit_name", ""),
                    source="hybrid_analysis",
                    tags=tags,
                    description=(
                        f"Verdict: {item.get('verdict', 'unknown')}; "
                        f"Threat Score: {item.get('threat_score', 'N/A')}"
                    ),
                    first_seen=item.get("analysis_start_time"),
                    references=[
                        f"https://www.hybrid-analysis.com/sample/{sha256}"
                    ],
                )
                entries.append(entry)
        except Exception:
            logger.debug("Hybrid Analysis fetch failed", exc_info=True)
        return entries, 0

    # ------------------------------------------------------------------ #
    # Source 6: HEVD (HackSys Extreme Vulnerable Driver)
    # ------------------------------------------------------------------ #

    def _fetch_hevd(self) -> Tuple[List[DriverIntelEntry], int]:
        entries: List[DriverIntelEntry] = []
        binaries = 0
        try:
            zip_bytes = self._download_zip(HEVD_GITHUB_ZIP, timeout=60.0)
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                for info in z.infolist():
                    if info.filename.startswith("__MACOSX"):
                        continue
                    # Look for compiled .sys binaries inside the repo
                    if info.filename.endswith(".sys"):
                        parts = info.filename.split("/")
                        filename = parts[-1]
                        data = z.read(info.filename)
                        local = self._write_binary(f"hevd_{filename}", data)
                        if local:
                            binaries += 1
                            entries.append(DriverIntelEntry(
                                sha256="",  # we don't have the hash yet
                                name="HEVD (HackSys Extreme Vulnerable Driver)",
                                filename=filename,
                                source="hevd",
                                tags=["hevd", "vulnerable", "test-sample"],
                                description=(
                                    "Intentionally vulnerable driver for security "
                                    "research and testing."
                                ),
                                local_path=local,
                                references=[
                                    "https://github.com/hacksysteam/"
                                    "HackSysExtremeVulnerableDriver"
                                ],
                            ))
        except Exception:
            logger.debug("HEVD fetch failed", exc_info=True)
        return entries, binaries


# ── Module-level helpers ────────────────────────────────────────────────

def _parse_loldrivers_yaml(data: bytes) -> List[DriverIntelEntry]:
    """Extract entries from a single LOLDrivers YAML file."""
    try:
        import yaml
        doc = yaml.safe_load(data)
    except Exception:
        logger.debug("YAML parse failed", exc_info=True)
        return []
    if not isinstance(doc, dict):
        return []

    name = doc.get("Name", "unknown")
    entries: List[DriverIntelEntry] = []
    samples = doc.get("KnownVulnerableSamples") or []
    if isinstance(samples, dict):
        samples = [samples]
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        sha = sample.get("SHA256") or sample.get("sha256")
        if sha:
            entries.append(DriverIntelEntry(
                sha256=sha.lower(),
                name=name,
                filename=sample.get("Filename", sample.get("filename", "")),
                source="loldrivers_github",
                tags=["loldrivers"],
                references=[
                    "https://github.com/magicsword-io/LOLDrivers",
                    "https://www.loldrivers.io/",
                ],
            ))
    return entries
