#!/usr/bin/env python3
"""
TI Mirror — Feed Downloader with Structure-Aware Suppression (v2.6)
Supports TXT, CSV, and JSON files for suppression.
"""

import gzip
import json
import logging
import os
import re
import sys
import tempfile
import time
import fnmatch
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml


# ─── Configuration ───────────────────────────────────────────
BASE_DIR       = Path("/opt/ti-mirror")
FEEDS_DIR      = Path("/var/www/html/feeds")
CONFIG_FILE    = BASE_DIR / "feeds.yaml"
SUPP_FILE      = BASE_DIR / "suppression.yaml"
LOG_FILE       = Path("/var/log/ti-mirror.log")
METADATA_FILE  = FEEDS_DIR / "_metadata.json"

HTTP_TIMEOUT   = 180
USER_AGENT     = "TI-Mirror/2.6 (+internal)"
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
    if not CONFIG_FILE.exists():
        log.error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
    with CONFIG_FILE.open("r") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict) or "feeds" not in cfg:
        log.error("Invalid config: missing top-level 'feeds' key")
        sys.exit(1)
    return cfg


def load_suppression() -> dict:
    if not SUPP_FILE.exists():
        log.warning(f"Suppression file not found: {SUPP_FILE}")
        return {}
    with SUPP_FILE.open("r") as f:
        return yaml.safe_load(f)


def ensure_dirs() -> None:
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(target: Path, content: bytes) -> None:
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


# ─── Indicator Type Detection ────────────────────────────────
def detect_indicator_type(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        return "hash"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "@" in value and "." in value.split("@")[-1]:
        return "email"
    return "domain"


# ─── Core Suppression Logic ──────────────────────────────────
def is_suppressed_value(val: str, supp: dict, cdn_ips: set) -> bool:
    """Check if a single value should be suppressed. Supports substring matching."""
    if not val:
        return False
    
    ind_type = detect_indicator_type(val)
    allowlist = supp.get("allowlist", {}) or {}
    denylist = supp.get("denylist", {}) or {}

    # 1. Check CDN IPs
    if ind_type == "ip":
        try:
            if str(ipaddress.ip_address(val)) in cdn_ips:
                return True
        except ValueError:
            pass

    # 2. Check Allowlist
    patterns = allowlist.get(ind_type, [])
    for pattern in patterns:
        if ind_type == "ip":
            try:
                if "/" in pattern:
                    if ipaddress.ip_address(val) in ipaddress.ip_network(pattern, strict=False):
                        return True
                elif val == pattern:
                    return True
            except ValueError:
                pass
        else:
            regex_pattern = fnmatch.translate(pattern)
            if re.search(regex_pattern, val):
                return True

    # 3. Check Denylist
    patterns = denylist.get(ind_type, [])
    for pattern in patterns:
        if ind_type == "ip":
            try:
                if "/" in pattern:
                    if ipaddress.ip_address(val) in ipaddress.ip_network(pattern, strict=False):
                        return True
                elif val == pattern:
                    return True
            except ValueError:
                pass
        else:
            regex_pattern = fnmatch.translate(pattern)
            if re.search(regex_pattern, val):
                return True

    return False


def apply_suppression_json(data: any, supp: dict, cdn_ips: set) -> any:
    """Recursively traverse JSON and remove suppressed string values."""
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            if isinstance(v, str) and is_suppressed_value(v, supp, cdn_ips):
                continue
            new_dict[k] = apply_suppression_json(v, supp, cdn_ips)
        return new_dict
    elif isinstance(data, list):
        new_list = []
        for item in data:
            if isinstance(item, str) and is_suppressed_value(item, supp, cdn_ips):
                continue
            new_list.append(apply_suppression_json(item, supp, cdn_ips))
        return new_list
    else:
        return data


def apply_suppression(content: bytes, spec: dict, supp: dict, cdn_ips: set, name: str) -> bytes:
    """Route suppression based on file type."""
    file_type = spec.get("file_type", "text")

    if file_type == "json":
        try:
            data = json.loads(content.decode("utf-8"))
            original_len = len(content)
            data = apply_suppression_json(data, supp, cdn_ips)
            content = json.dumps(data, indent=2).encode("utf-8")
            if original_len != len(content):
                log.info(f"  {name}: JSON suppression {original_len}B → {len(content)}B")
            return content
        except json.JSONDecodeError as e:
            log.warning(f"  {name}: failed to parse JSON for suppression: {e}")
            return content

    # Default: line-by-line (TXT, CSV)
    out_lines = []
    for line in content.splitlines(keepends=False):
        val = line.decode("utf-8", errors="ignore").strip()
        if not val:
            continue
        if not is_suppressed_value(val, supp, cdn_ips):
            out_lines.append(val.encode("utf-8"))
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


# ─── Transforms ──────────────────────────────────────────────
def strip_comments(content: bytes) -> bytes:
    out_lines = []
    for line in content.splitlines(keepends=True):
        if line.lstrip().startswith(b"#"):
            continue
        out_lines.append(line)
    return b"".join(out_lines)


def strip_semicolon_comments(content: bytes) -> bytes:
    out_lines = []
    for line in content.splitlines(keepends=True):
        if line.lstrip().startswith(b";"):
            continue
        out_lines.append(line)
    return b"".join(out_lines)


def strip_inline_semicolon(content: bytes) -> bytes:
    out_lines = []
    for line in content.splitlines(keepends=False):
        if not line:
            continue
        part = line.split(b";", 1)[0].strip()
        if part:
            out_lines.append(part)
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def extract_ip_from_iblocklist(content: bytes) -> bytes:
    ip_re = re.compile(rb"^[^:]+:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-")
    out_lines = []
    for line in content.splitlines(keepends=False):
        if not line:
            continue
        m = ip_re.search(line)
        if m:
            out_lines.append(m.group(1))
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def feodo_extract_ip(content: bytes) -> bytes:
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
    import csv
    from io import StringIO
    out_lines = []
    reader = csv.reader(StringIO(content.decode("utf-8", errors="ignore")))
    for row in reader:
        if len(row) >= 3 and row[2]:
            out_lines.append(row[2].encode())
    return b"\n".join(out_lines) + b"\n" if out_lines else b""


def extract_cdn_ips(content: bytes) -> bytes:
    try:
        data = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return b""
    ips = set()
    if "prefixes" in data:
        for p in data["prefixes"]:
            if "ip_prefix" in p: ips.add(p["ip_prefix"])
            if "ipv4Prefix" in p: ips.add(p["ipv4Prefix"])
    if "result" in data and "ipv4_cidrs" in data["result"]:
        for cidr in data["result"]["ipv4_cidrs"]: ips.add(cidr)
    return ("\n".join(ips) + "\n").encode() if ips else b""


TRANSFORMS = {
    "strip_comments":        strip_comments,
    "strip_semicolon":       strip_semicolon_comments,
    "strip_inline_semicolon": strip_inline_semicolon,
    "extract_iblocklist":    extract_ip_from_iblocklist,
    "feodo_extract_ip":      feodo_extract_ip,
    "urlhaus_extract_url":   urlhaus_extract_url,
    "extract_cdn_ips":       extract_cdn_ips,
}


def apply_transforms(content: bytes, spec: dict, name: str) -> bytes:
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
def maybe_decompress_gzip(content: bytes, spec: dict, name: str) -> bytes:
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


def download_feed(name: str, spec: dict, supp: dict, cdn_ips: set) -> dict:
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

            if name not in supp.get("cdn_feeds", []):
                content = apply_suppression(content, spec, supp, cdn_ips, name)

            atomic_write_bytes(target, content)

            result["status"]       = "ok"
            result["size_bytes"]   = len(content)
            result["http_status"]  = resp.status_code
            result["attempts"]     = attempt
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
    supp = load_suppression()

    cdn_ips = set()
    for feed_name in supp.get("cdn_feeds", []):
        feed_spec = cfg["feeds"].get(feed_name)
        if feed_spec and feed_spec.get("enabled", True):
            cdn_file = FEEDS_DIR / feed_spec["filename"]
            if cdn_file.exists():
                with cdn_file.open("r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            cdn_ips.add(line)
    
    log.info(f"Loaded {len(cdn_ips)} CDN IPs from suppression sources")

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
        results.append(download_feed(name, spec, supp, cdn_ips))

    write_metadata(results)

    ok = sum(1 for r in results if r["status"] == "ok")
    tot = len(results)
    log.info(f"─── TI Mirror run finished: {ok}/{tot} OK ───")
    if sys.stdout.isatty():
        print(f"\n─── Finished: {ok}/{tot} OK ───")
    return 0 if ok == tot else 1


if __name__ == "__main__":
    sys.exit(main())
