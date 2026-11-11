#!/usr/bin/env python3
"""
TI Mirror — Feed Downloader
────────────────────────────────────────────────────────────
Downloads threat intelligence feeds and publishes them as static
files under /var/www/html/feeds/. Designed for air-gapped Splunk ES
deployments where the Search Head must not have direct internet access.

All feed-specific configuration (URLs, credentials, transforms)
is loaded from feeds.yaml. This script contains no secrets.

Usage:
    python3 update_feeds.py

License: Apache-2.0
"""

import gzip
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml


# ─── Configuration ───────────────────────────────────────────
BASE_DIR       = Path("/opt/ti-mirror")
FEEDS_DIR      = Path("/var/www/html/feeds")
CONFIG_FILE    = BASE_DIR / "feeds.yaml"
LOG_FILE       = Path("/var/log/ti-mirror.log")
METADATA_FILE  = FEEDS_DIR / "_metadata.json"

HTTP_TIMEOUT   = 180
USER_AGENT     = "TI-Mirror/2.1 (+internal)"
MAX_RETRIES    = 3
RETRY_DELAY    = 30


# ─── Logging ─────────────────────────────────────────────────
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ti-mirror")

if sys.stdout.isatty():
    console = logging.StreamHandler()
    console.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    log.addHandler(console)


# ─── Helpers ─────────────────────────────────────────────────
def load_config() -> dict:
    """Load and validate feeds.yaml."""
    if not CONFIG_FILE.exists():
        log.error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
    with CONFIG_FILE.open("r") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict) or "feeds" not in cfg:
        log.error("Invalid config: missing top-level 'feeds' key")
        sys.exit(1)
    return cfg


def ensure_dirs() -> None:
    """Create output directory if it does not exist."""
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(target: Path, content: bytes) -> None:
    """Write bytes to target atomically to prevent partial reads."""
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=target.name + ".",
        suffix=".tmp",
    )
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ─── Decompression ───────────────────────────────────────────
def maybe_decompress_gzip(content: bytes, spec: dict, name: str) -> bytes:
    """Decompress gzip content if configured."""
    decompress = spec.get("decompress", "none")
    if decompress == "none":
        return content
    if decompress == "gzip":
        if content[:2] != b"\x1f\x8b":
            log.warning(f"  {name}: 'decompress: gzip' set, content not gzip")
            return content
        try:
            original_size = len(content)
            content = gzip.decompress(content)
            log.info(f"  {name}: gzip {original_size}B → {len(content)}B")
            return content
        except Exception as e:
            log.warning(f"  {name}: gzip decompression failed: {e}")
            return content
    log.warning(f"  {name}: unknown decompress mode '{decompress}'")
    return content


# ─── Transforms ──────────────────────────────────────────────
def strip_comments(content: bytes) -> bytes:
    """Remove lines starting with '#'."""
    out_lines = []
    for line in content.splitlines(keepends=True):
        if line.lstrip().startswith(b"#"):
            continue
        out_lines.append(line)
    return b"".join(out_lines)


def strip_semicolon_comments(content: bytes) -> bytes:
    """Remove lines starting with ';'."""
    out_lines = []
    for line in content.splitlines(keepends=True):
        if line.lstrip().startswith(b";"):
            continue
        out_lines.append(line)
    return b"".join(out_lines)


def strip_inline_semicolon(content: bytes) -> bytes:
    """Remove everything after ';' on each line (inline comments)."""
    out_lines = []
    for line in content.splitlines(keepends=False):
        if not line:
            continue
        part = line.split(b";", 1)[0].strip()
        if part:
            out_lines.append(part)
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def extract_ip_from_iblocklist(content: bytes) -> bytes:
    """Extract start IP from 'description:start_ip-end_ip'."""
    ip_re = re.compile(rb"^[^:]+:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-")
    out_lines = []
    for line in content.splitlines(keepends=False):
        if not line:
            continue
        m = ip_re.search(line)
        if m:
            out_lines.append(m.group(1))
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def extract_ip_from_comma(content: bytes) -> bytes:
    """Extract first field if it looks like an IP."""
    ip_re = re.compile(rb"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    out_lines = []
    for line in content.splitlines(keepends=False):
        if not line:
            continue
        m = ip_re.search(line)
        if m:
            out_lines.append(m.group(1))
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def feodo_extract_ip(content: bytes) -> bytes:
    """Extract dst_ip from 2nd column of Feodo CSV."""
    out_lines = []
    is_header = True
    for line in content.splitlines(keepends=False):
        if not line or line.startswith(b"#"):
            continue
        if is_header:
            is_header = False
            continue
        parts = line.split(b",")
        if len(parts) >= 2:
            ip = parts[1].strip(b'"').strip()
            if ip:
                out_lines.append(ip)
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def urlhaus_extract_url(content: bytes) -> bytes:
    """Extract URL from 3rd column of URLhaus CSV."""
    import csv
    from io import StringIO
    out_lines = []
    reader = csv.reader(StringIO(content.decode("utf-8", errors="ignore")))
    for row in reader:
        if len(row) >= 3 and row[2]:
            out_lines.append(row[2].encode())
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


TRANSFORMS = {
    "strip_comments":         strip_comments,
    "strip_semicolon":        strip_semicolon_comments,
    "strip_inline_semicolon": strip_inline_semicolon,
    "extract_iblocklist":     extract_ip_from_iblocklist,
    "extract_comma":          extract_ip_from_comma,
    "feodo_extract_ip":       feodo_extract_ip,
    "urlhaus_extract_url":    urlhaus_extract_url,
}


def apply_transforms(content: bytes, spec: dict, name: str) -> bytes:
    """Apply configured transforms in order."""
    transform_names = spec.get("transform", [])
    if isinstance(transform_names, str):
        transform_names = [transform_names]

    for t_name in transform_names:
        fn = TRANSFORMS.get(t_name)
        if fn is None:
            log.warning(f"  {name}: unknown transform '{t_name}', skipping")
            continue
        before = len(content)
        content = fn(content)
        log.info(f"  {name}: transform '{t_name}' {before}B → {len(content)}B")

    return content


# ─── Download ────────────────────────────────────────────────
def download_feed(name: str, spec: dict) -> dict:
    """Download a single feed, apply transforms, and write atomically."""
    result = {
        "name":       name,
        "url":        spec["url"],
        "filename":   spec["filename"],
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status":     "unknown",
    }
    target = FEEDS_DIR / spec["filename"]

    timeout     = spec.get("timeout", HTTP_TIMEOUT)
    max_retries = spec.get("max_retries", MAX_RETRIES)
    retry_delay = spec.get("retry_delay", RETRY_DELAY)
    accept_enc  = spec.get("accept_encoding", "identity")

    last_error = None
    if sys.stdout.isatty():
        print(f"  → {name}: downloading...", end="", flush=True)

    for attempt in range(1, max_retries + 1):
        try:
            headers = {"User-Agent": USER_AGENT, "Accept-Encoding": accept_enc}
            with httpx.Client(
                timeout=timeout,
                follow_redirects=True,
                headers=headers,
            ) as client:
                resp = client.get(spec["url"])
                resp.raise_for_status()

            raw = resp.content
            if not raw:
                raise ValueError("empty response body")

            if spec.get("keep_raw", False):
                raw_target = target.with_suffix(target.suffix + ".raw")
                atomic_write_bytes(raw_target, raw)
                result["raw_size_bytes"] = len(raw)

            content = maybe_decompress_gzip(raw, spec, name)
            content = apply_transforms(content, spec, name)
            atomic_write_bytes(target, content)

            result["status"]      = "ok"
            result["size_bytes"]  = len(content)
            result["http_status"] = resp.status_code
            result["attempts"]    = attempt
            log.info(f"{name}: OK  size={len(content)}B  status={resp.status_code}")
            if sys.stdout.isatty():
                print(f" OK ({len(content)} bytes)")
            return result

        except KeyboardInterrupt:
            if sys.stdout.isatty():
                print(" CANCELLED")
            raise
        except Exception as e:
            last_error = str(e)
            log.warning(f"{name}: attempt {attempt} failed — {e}")
            if sys.stdout.isatty():
                print(f" retry {attempt}...", end="", flush=True)
            if attempt < max_retries:
                time.sleep(retry_delay)

    result["status"] = "error"
    result["error"]  = last_error
    log.error(f"{name}: FAILED after {max_retries} attempts — {last_error}")
    if sys.stdout.isatty():
        print(f" FAIL ({last_error})")
    return result


# ─── Metadata ────────────────────────────────────────────────
def write_metadata(results: list) -> None:
    """Write _metadata.json with per-feed status."""
    meta = {
        "last_run":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feed_count":  len(results),
        "ok_count":    sum(1 for r in results if r["status"] == "ok"),
        "error_count": sum(1 for r in results if r["status"] == "error"),
        "feeds":       results,
    }
    atomic_write_bytes(METADATA_FILE, json.dumps(meta, indent=2).encode("utf-8"))


# ─── Main ────────────────────────────────────────────────────
def main() -> int:
    log.info("─── TI Mirror run started ───")
    ensure_dirs()
    cfg = load_config()

    results = []
    total = len([f for f in cfg["feeds"].values() if f.get("enabled", True)])
    idx = 0

    for name, spec in cfg["feeds"].items():
        if not spec.get("enabled", True):
            log.info(f"{name}: disabled, skipping")
            continue
        idx += 1
        if sys.stdout.isatty():
            print(f"[{idx}/{total}] {name}", end="", flush=True)
        results.append(download_feed(name, spec))

    write_metadata(results)

    ok = sum(1 for r in results if r["status"] == "ok")
    tot = len(results)
    log.info(f"─── TI Mirror run finished: {ok}/{tot} OK ───")
    if sys.stdout.isatty():
        print(f"\n─── Finished: {ok}/{tot} OK ───")
    return 0 if ok == tot else 1


if __name__ == "__main__":
    sys.exit(main())