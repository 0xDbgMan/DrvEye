"""Live Microsoft trust/revocation list fetching & caching.

Pulls the exact files the Windows kernel consults for driver trust
decisions so our verdicts match real CI behaviour:

  - authroot.stl         — trusted root CAs (SHA-1 thumbprint list)
  - disallowedcert.stl   — explicitly blocked certs (SHA-1 thumbprint list)

Both are published by Microsoft as signed CTL (Certificate Trust List)
files wrapped in PKCS#7 SignedData. We only need the list of SHA-1
subject identifiers inside trustedSubjects — which is a straight DER walk.

Cache lives at ~/.cache/drivertool/ and is refreshed on --live-check.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)
from urllib.request import urlopen

from drivertool.authenticode import (
    _children, _tlv, TAG_OCTETSTRING, TAG_SEQUENCE, parse_signed_data,
)


STL_URLS = {
    "authroot.stl":
        "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/"
        "en/authroot.stl",
    "disallowedcert.stl":
        "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/"
        "en/disallowedcert.stl",
}

# Microsoft's recommended driver block rules — published as a ZIP of WDAC
# policy files. aka.ms redirects to a CDN; urlopen follows 302s.
DRIVER_BLOCKLIST_URL = "https://aka.ms/VulnerableDriverBlockList"
DRIVER_BLOCKLIST_CACHE = "VulnerableDriverBlockList.zip"
DRIVER_BLOCKLIST_HASHES = "driver_blocklist_hashes.txt"


def cache_dir() -> Path:
    home = Path(os.environ.get("XDG_CACHE_HOME") or
                Path.home() / ".cache")
    d = home / "drivertool"
    d.mkdir(parents=True, exist_ok=True)
    return d


def fetch_stl(name: str, timeout: float = 20.0) -> bytes:
    """Download a single STL file from Microsoft's CTL endpoint."""
    url = STL_URLS[name]
    with urlopen(url, timeout=timeout) as resp:
        return resp.read()


def update_cache() -> Dict[str, int]:
    """Fetch all STL files and write to cache. Returns {name: byte_size}."""
    out: Dict[str, int] = {}
    d = cache_dir()
    for name in STL_URLS:
        data = fetch_stl(name)
        (d / name).write_bytes(data)
        out[name] = len(data)
    return out


def load_cached(name: str) -> Tuple[bytes, float]:
    """Read a cached STL file. Returns (data, mtime_epoch).
    Raises FileNotFoundError if absent."""
    p = cache_dir() / name
    return p.read_bytes(), p.stat().st_mtime


def extract_ctl_thumbprints(stl_der: bytes,
                             lengths: Tuple[int, ...] = (20, 32)
                             ) -> Dict[int, Set[str]]:
    """Parse subject thumbprints out of an STL's CTL content.

    STL is a PKCS#7 SignedData; the encapContentInfo.content is a CTL
    SEQUENCE. trustedSubjects begins each entry with an OCTET STRING
    carrying the subject's hash thumbprint. authroot.stl uses 20-byte
    SHA-1. disallowedcert.stl mixes sizes (16-byte CERT_SIGNATURE_HASH,
    32-byte SHA-256, etc). We collect every OCTET STRING whose length
    matches one in `lengths` and bucket by length.

    Returns {byte_length: {hex_thumbprint, ...}}.
    """
    out: Dict[int, Set[str]] = {n: set() for n in lengths}
    sd = parse_signed_data(stl_der)
    if not sd:
        return out
    ctl = sd.get("encap_content_for_hash") or b""
    if not ctl:
        return out

    def _walk(blob: bytes, start: int, end: int, depth: int = 0):
        if depth > 8:
            return
        i = start
        while i < end:
            try:
                tag, hl, cl, tl = _tlv(blob, i)
            except Exception:
                logger.debug("CTL entry parse failed", exc_info=True)
                return
            if tag == TAG_OCTETSTRING and cl in out:
                out[cl].add(blob[i + hl : i + hl + cl].hex())
            elif tag & 0x20:
                _walk(blob, i + hl, i + hl + cl, depth + 1)
            i += tl

    _walk(ctl, 0, len(ctl))
    return out


def load_trusted_thumbprints(auto_fetch: bool = False,
                             max_age_days: int = 30
                             ) -> Tuple[Set[str], Dict[int, Set[str]],
                                        Dict[str, float]]:
    """Load trusted-root + disallowed-cert thumbprints from the cache.

    Returns (trusted_sha1, disallowed_by_length, metadata). Metadata has
    keys 'authroot.stl_age_days', 'disallowedcert.stl_age_days'.
    authroot.stl only uses 20-byte SHA-1. disallowedcert.stl mixes sizes
    so it's returned as {length: {hex, ...}} for later matching against
    the appropriate cert fingerprint.
    """
    now = time.time()
    meta: Dict[str, float] = {}
    trusted: Set[str] = set()
    disallowed: Dict[int, Set[str]] = {20: set(), 32: set()}

    for name in ("authroot.stl", "disallowedcert.stl"):
        try:
            data, mtime = load_cached(name)
            age_days = (now - mtime) / 86400.0
            if auto_fetch and age_days > max_age_days:
                raise FileNotFoundError
        except FileNotFoundError:
            if not auto_fetch:
                meta[f"{name}_age_days"] = float("inf")
                continue
            try:
                data = fetch_stl(name)
                (cache_dir() / name).write_bytes(data)
                age_days = 0.0
            except Exception:
                logger.debug("Cache age check failed for %s", name, exc_info=True)
                meta[f"{name}_age_days"] = float("inf")
                continue
        meta[f"{name}_age_days"] = age_days
        buckets = extract_ctl_thumbprints(data, lengths=(20, 32))
        if name == "authroot.stl":
            trusted |= buckets.get(20, set())
        else:
            for ln, thumbs in buckets.items():
                disallowed.setdefault(ln, set()).update(thumbs)

    return trusted, disallowed, meta


def fetch_driver_blocklist(timeout: float = 30.0) -> bytes:
    """Download the WDAC-policy ZIP containing Microsoft's vulnerable
    driver block rules. Returns the raw ZIP bytes (caller caches)."""
    with urlopen(DRIVER_BLOCKLIST_URL, timeout=timeout) as resp:
        return resp.read()


def extract_blocklist_hashes_from_zip(zip_bytes: bytes
                                       ) -> Tuple[Set[str], Set[str]]:
    """Extract SHA-1 (20B) and SHA-256 (32B) hashes of blocked drivers from
    every .p7b inside the MS WDAC blocklist ZIP.

    The .p7b files wrap a binary WDAC CIP policy. The CIP contains
    FileRules whose Hash values are encoded as fixed-length byte blobs
    immediately after a small rule header. We extract every 20/32-byte
    aligned sequence found inside plausible rule positions. This is
    heuristic but effective — the CIP binary is dense and length-32
    OCTET STRING-shaped values are almost exclusively file hashes.
    """
    import io
    import zipfile

    sha1: Set[str] = set()
    sha256: Set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for name in z.namelist():
                if not name.lower().endswith(".p7b"):
                    continue
                data = z.read(name)
                sd = parse_signed_data(data)
                cip = (sd.get("encap_content_for_hash") if sd else None) or b""
                if not cip:
                    # Some .p7b are detached — the body may not have a
                    # parseable SignedData layer. Fall back to the raw bytes.
                    cip = data

                # Each rule hash in a CIP is preceded by its length as a
                # 32-bit little-endian prefix. Scan for plausible len+blob
                # patterns: (\x14\x00\x00\x00 + 20B) → SHA-1,
                # (\x20\x00\x00\x00 + 32B) → SHA-256.
                i = 0
                end = len(cip)
                while i + 4 < end:
                    length = int.from_bytes(cip[i:i + 4], "little")
                    if length == 20 and i + 4 + 20 <= end:
                        sha1.add(cip[i + 4:i + 4 + 20].hex())
                    elif length == 32 and i + 4 + 32 <= end:
                        sha256.add(cip[i + 4:i + 4 + 32].hex())
                    i += 1
    except Exception:
        logger.debug("Driver blocklist parse failed", exc_info=True)
    return sha1, sha256


def load_driver_blocklist(auto_fetch: bool = False,
                          max_age_days: int = 30
                          ) -> Tuple[Set[str], Set[str], float]:
    """Return (sha1_set, sha256_set, age_days). Refreshes cache when
    auto_fetch=True and the cache is stale/absent."""
    now = time.time()
    d = cache_dir()
    p_zip = d / DRIVER_BLOCKLIST_CACHE
    p_txt = d / DRIVER_BLOCKLIST_HASHES

    age = float("inf")
    zip_bytes = b""
    if p_zip.exists():
        age = (now - p_zip.stat().st_mtime) / 86400.0

    if auto_fetch and (not p_zip.exists() or age > max_age_days):
        try:
            zip_bytes = fetch_driver_blocklist()
            p_zip.write_bytes(zip_bytes)
            age = 0.0
        except Exception:
            logger.debug("Blocklist download failed", exc_info=True)
            zip_bytes = b""

    if not zip_bytes and p_zip.exists():
        try:
            zip_bytes = p_zip.read_bytes()
        except Exception:
            logger.debug("Blocklist extraction failed", exc_info=True)
            return set(), set(), float("inf")

    if not zip_bytes:
        return set(), set(), float("inf")

    s1, s2 = extract_blocklist_hashes_from_zip(zip_bytes)
    # Cache the parsed hash list as plain text for fast startup.
    try:
        lines = ["sha1:" + h for h in s1] + ["sha256:" + h for h in s2]
        p_txt.write_text("\n".join(lines))
    except Exception:
        logger.debug("Blocklist load failed", exc_info=True)
    return s1, s2, age


def merge_into_kernel_trusted(live_thumbs: Set[str]) -> int:
    """Augment constants.KERNEL_TRUSTED_ROOTS with live thumbprints.

    Live entries are categorised as "ms-live-ctl" so the anchor classifier
    treats them the same as kernel-trusted. Returns the number of entries
    added (i.e. not already present)."""
    from drivertool.constants import KERNEL_TRUSTED_ROOTS
    added = 0
    for tp in live_thumbs:
        if tp not in KERNEL_TRUSTED_ROOTS:
            KERNEL_TRUSTED_ROOTS[tp] = ("ms-live-ctl", "live-trusted-root")
            added += 1
    return added

