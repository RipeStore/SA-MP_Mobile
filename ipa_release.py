#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path


MANIFEST_URL = os.environ.get(
    "IPA_MANIFEST_URL",
    "https://alynsampmobile.pro/api/resa/ios/manifest",
)

STATE_FILE = Path(
    os.environ.get("IPA_STATE_FILE", "ipa-state.json")
)

WORK_DIR = Path(
    os.environ.get("IPA_WORK_DIR", "build/ipa")
)

DIST_DIR = WORK_DIR / "dist"
META_FILE = WORK_DIR / "release-meta.json"

DEFAULT_UA = os.environ.get(
    "IPA_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 "
    "Chrome/154.0.0.0 Safari/537.36",
)

SCHEMA_VERSION = 1

# Mach-O load command
LC_CODE_SIGNATURE = 0x1D

# Thin Mach-O:
# magic -> (endianness, header_bits)
MACH_MAGICS = {
    0xFEEDFACE: ("<", 32),
    0xFEEDFACF: ("<", 64),
    0xCEFAEDFE: (">", 32),
    0xCFFAEDFE: (">", 64),
}

# Universal/FAT Mach-O
# magic -> (endianness, fat_arch_64)
FAT_MAGICS = {
    0xCAFEBABE: (">", False),
    0xCAFEBABF: (">", True),
    0xBEBAFECA: ("<", False),
    0xBFBAFECA: ("<", True),
}


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def log(message: str) -> None:
    print(f"[*] {message}", flush=True)


def ok(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def die(message: str) -> None:
    raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def byteorder(endian: str) -> str:
    return "big" if endian == ">" else "little"


def u32(data: bytes | bytearray, offset: int, endian: str) -> int:
    return int.from_bytes(
        data[offset:offset + 4],
        byteorder(endian),
    )


def u64(data: bytes | bytearray, offset: int, endian: str) -> int:
    return int.from_bytes(
        data[offset:offset + 8],
        byteorder(endian),
    )


def put_u32(
    data: bytearray,
    offset: int,
    value: int,
    endian: str,
) -> None:
    data[offset:offset + 4] = int(value).to_bytes(
        4,
        byteorder(endian),
    )


def safe_component(
    value: str,
    fallback: str = "unknown",
) -> str:
    value = str(value or "").strip()

    value = re.sub(
        r'[\\/:*?"<>|\x00-\x1f]',
        "_",
        value,
    )

    value = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value,
    )

    value = value.strip("._")

    return value or fallback


def safe_tag_component(value: str) -> str:
    value = str(value or "").strip()

    value = re.sub(
        r"[^A-Za-z0-9._+~-]+",
        "-",
        value,
    )

    value = value.strip(".-")

    return value or "unknown"


def parse_bool_env(
    name: str,
    default: bool = False,
) -> bool:
    value = os.environ.get(name)

    if value is None:
        return default

    return value.lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_get(
    url: str,
    retries: int = 4,
    timeout: int = 60,
) -> bytes:
    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": DEFAULT_UA,
                "Accept": (
                    "application/xml,"
                    "text/xml,"
                    "application/plist,"
                    "*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.7",
                "Connection": "close",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:

                if response.status != 200:
                    raise RuntimeError(
                        f"HTTP {response.status}"
                    )

                return response.read()

        except urllib.error.HTTPError as exc:
            last_error = exc

            retryable = (
                exc.code == 429
                or 500 <= exc.code < 600
            )

            if not retryable or attempt == retries:
                raise

            retry_after = exc.headers.get(
                "Retry-After"
            )

            if retry_after and retry_after.isdigit():
                delay = int(retry_after)
            else:
                delay = min(
                    2 ** attempt,
                    15,
                )

            warn(
                f"HTTP {exc.code}; "
                f"retrying in {delay}s "
                f"({attempt}/{retries})"
            )

            time.sleep(delay)

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            RuntimeError,
        ) as exc:

            last_error = exc

            if attempt == retries:
                raise

            delay = min(
                2 ** attempt,
                15,
            )

            warn(
                f"Download error: {exc}; "
                f"retrying in {delay}s "
                f"({attempt}/{retries})"
            )

            time.sleep(delay)

    raise RuntimeError(
        f"download failed: {last_error}"
    )


def download_file(
    url: str,
    destination: Path,
    retries: int = 5,
    timeout: int = 60,
) -> None:

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": DEFAULT_UA,
                "Accept": (
                    "application/octet-stream,"
                    "*/*;q=0.8"
                ),
                "Connection": "close",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:

                if response.status != 200:
                    raise RuntimeError(
                        f"HTTP {response.status}"
                    )

                with destination.open("wb") as out:
                    while True:
                        chunk = response.read(
                            1024 * 1024
                        )

                        if not chunk:
                            break

                        out.write(chunk)

            if destination.stat().st_size == 0:
                raise RuntimeError(
                    "downloaded IPA is empty"
                )

            return

        except urllib.error.HTTPError as exc:
            last_error = exc

            retryable = (
                exc.code == 429
                or 500 <= exc.code < 600
            )

            if not retryable or attempt == retries:
                raise

            retry_after = exc.headers.get(
                "Retry-After"
            )

            if retry_after and retry_after.isdigit():
                delay = int(retry_after)
            else:
                delay = min(
                    2 ** attempt,
                    20,
                )

            warn(
                f"IPA HTTP {exc.code}; "
                f"retrying in {delay}s "
                f"({attempt}/{retries})"
            )

            time.sleep(delay)

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            RuntimeError,
        ) as exc:

            last_error = exc

            if attempt == retries:
                raise

            delay = min(
                2 ** attempt,
                20,
            )

            warn(
                f"IPA download error: {exc}; "
                f"retrying in {delay}s "
                f"({attempt}/{retries})"
            )

            time.sleep(delay)

    raise RuntimeError(
        f"IPA download failed: {last_error}"
    )


# ---------------------------------------------------------------------------
# plist / manifest
# ---------------------------------------------------------------------------

def load_plist_bytes(data: bytes) -> dict:
    try:
        obj = plistlib.loads(data)

    except Exception as exc:
        raise RuntimeError(
            f"invalid plist: {exc}"
        ) from exc

    if not isinstance(obj, dict):
        raise RuntimeError(
            "plist root is not a dictionary"
        )

    return obj


def parse_manifest(data: bytes) -> dict:
    root = load_plist_bytes(data)

    items = root.get("items")

    if not isinstance(items, list) or not items:
        raise RuntimeError(
            "manifest contains no items[]"
        )

    for item in items:
        if not isinstance(item, dict):
            continue

        metadata = item.get("metadata") or {}
        assets = item.get("assets") or []

        if not isinstance(metadata, dict):
            continue

        if not isinstance(assets, list):
            continue

        ipa_url = None

        for asset in assets:
            if not isinstance(asset, dict):
                continue

            if asset.get("kind") != "software-package":
                continue

            ipa_url = asset.get("url")
            break

        if ipa_url:
            return {
                "title": str(
                    metadata.get("title")
                    or "iOS Application"
                ),
                "bundle_identifier": str(
                    metadata.get(
                        "bundle-identifier"
                    )
                    or "unknown.bundle"
                ),
                "bundle_version": str(
                    metadata.get(
                        "bundle-version"
                    )
                    or "unknown"
                ),
                "kind": metadata.get("kind"),
                "ipa_url": str(ipa_url),
            }

    raise RuntimeError(
        "manifest has no software-package asset"
    )


def find_main_info_plist(
    zf: zipfile.ZipFile,
) -> tuple[str, dict]:

    candidates = []

    for name in zf.namelist():
        normalized = (
            name
            .replace("\\", "/")
            .lstrip("/")
        )

        parts = normalized.split("/")

        if (
            len(parts) == 3
            and parts[0] == "Payload"
            and parts[1].endswith(".app")
            and parts[2] == "Info.plist"
        ):
            candidates.append(name)

    if not candidates:
        raise RuntimeError(
            "IPA has no Payload/*.app/Info.plist"
        )

    candidates.sort()

    name = candidates[0]

    return (
        name,
        load_plist_bytes(
            zf.read(name)
        ),
    )


# ---------------------------------------------------------------------------
# Mach-O code signature stripping
#
# We deliberately do NOT shrink Mach-O slices.
#
# Instead:
#
#   1. Locate LC_CODE_SIGNATURE.
#   2. Zero the referenced signature blob.
#   3. Remove that load command from the load-command table.
#   4. Decrement ncmds and sizeofcmds.
#   5. Preserve the overall binary size and all file offsets.
#
# This is especially useful for FAT/universal binaries because no slice
# offsets/sizes need to be relocated.
#
# Apple documents that Mach-O code signatures are referenced through
# LC_CODE_SIGNATURE; universal binaries have independent architecture
# slices/signatures. The approach below removes those references and
# destroys the referenced signature bytes.
# ---------------------------------------------------------------------------

def strip_thin_macho(
    blob: bytearray,
) -> int:

    if len(blob) < 4:
        return 0

    magic_le = int.from_bytes(
        blob[0:4],
        "little",
    )

    magic_be = int.from_bytes(
        blob[0:4],
        "big",
    )

    info = (
        MACH_MAGICS.get(magic_le)
        or MACH_MAGICS.get(magic_be)
    )

    if not info:
        return 0

    endian, bits = info

    header_size = (
        32
        if bits == 64
        else 28
    )

    if len(blob) < header_size:
        raise RuntimeError(
            "truncated Mach-O header"
        )

    ncmds = u32(
        blob,
        16,
        endian,
    )

    sizeofcmds = u32(
        blob,
        20,
        endian,
    )

    load_start = header_size

    load_end = (
        load_start
        + sizeofcmds
    )

    if load_end > len(blob):
        raise RuntimeError(
            "Mach-O load commands "
            "extend beyond file"
        )

    pos = load_start
    removed = 0

    while pos < load_end:
        if pos + 8 > load_end:
            raise RuntimeError(
                "truncated Mach-O "
                "load command"
            )

        cmd = u32(
            blob,
            pos,
            endian,
        )

        cmdsize = u32(
            blob,
            pos + 4,
            endian,
        )

        if (
            cmdsize < 8
            or pos + cmdsize > load_end
        ):
            raise RuntimeError(
                "invalid Mach-O "
                "load command size"
            )

        if cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise RuntimeError(
                    "invalid "
                    "LC_CODE_SIGNATURE size"
                )

            dataoff = u32(
                blob,
                pos + 8,
                endian,
            )

            datasize = u32(
                blob,
                pos + 12,
                endian,
            )

            data_end = (
                dataoff
                + datasize
            )

            if data_end > len(blob):
                raise RuntimeError(
                    "LC_CODE_SIGNATURE "
                    "points beyond Mach-O"
                )

            if (
                datasize
                and dataoff < load_end
            ):
                raise RuntimeError(
                    "LC_CODE_SIGNATURE "
                    "overlaps Mach-O "
                    "load-command area"
                )

            # Destroy the signature data itself.
            if datasize:
                blob[
                    dataoff:data_end
                ] = (
                    b"\x00"
                    * datasize
                )

            # Remove this load command without
            # moving any file-offset-based sections.
            tail = bytes(
                blob[
                    pos + cmdsize:load_end
                ]
            )

            blob[
                pos:pos + len(tail)
            ] = tail

            new_load_end = (
                load_end - cmdsize
            )

            blob[
                new_load_end:load_end
            ] = (
                b"\x00"
                * cmdsize
            )

            load_end = new_load_end

            ncmds -= 1
            sizeofcmds -= cmdsize

            put_u32(
                blob,
                16,
                ncmds,
                endian,
            )

            put_u32(
                blob,
                20,
                sizeofcmds,
                endian,
            )

            removed += 1

            continue

        pos += cmdsize

    return removed


def strip_macho(
    blob: bytes,
) -> tuple[bytes, int]:

    data = bytearray(blob)

    if len(data) < 4:
        return blob, 0

    magic_be = int.from_bytes(
        data[0:4],
        "big",
    )

    fat_info = FAT_MAGICS.get(
        magic_be
    )

    if fat_info:
        endian, is64 = fat_info

        entry_size = (
            32
            if is64
            else 20
        )

        nfat_arch = u32(
            data,
            4,
            endian,
        )

        table_end = (
            8
            + nfat_arch * entry_size
        )

        if table_end > len(data):
            raise RuntimeError(
                "truncated FAT Mach-O "
                "architecture table"
            )

        removed = 0

        for i in range(nfat_arch):
            base = (
                8
                + i * entry_size
            )

            offset = (
                u64(
                    data,
                    base + 8,
                    endian,
                )
                if is64
                else u32(
                    data,
                    base + 8,
                    endian,
                )
            )

            size = (
                u64(
                    data,
                    base + 16,
                    endian,
                )
                if is64
                else u32(
                    data,
                    base + 12,
                    endian,
                )
            )

            end = (
                offset + size
            )

            if end > len(data):
                raise RuntimeError(
                    "FAT Mach-O slice "
                    "exceeds file bounds"
                )

            slice_data = data[
                offset:end
            ]

            removed += strip_thin_macho(
                slice_data
            )

            data[
                offset:end
            ] = slice_data

        return (
            bytes(data),
            removed,
        )

    removed = strip_thin_macho(data)

    return (
        bytes(data),
        removed,
    )


def is_codesignature_path(
    name: str,
) -> bool:

    parts = [
        part
        for part in (
            name
            .replace("\\", "/")
            .split("/")
        )
        if part
    ]

    return "_CodeSignature" in parts


def strip_ipa(
    source: Path,
    destination: Path,
) -> dict:

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    macho_files = 0
    macho_signatures = 0
    codesignature_entries = 0

    fd, tmp_name = tempfile.mkstemp(
        prefix="ipa-",
        suffix=".ipa",
        dir=str(destination.parent),
    )

    os.close(fd)

    tmp_path = Path(tmp_name)

    try:
        with (
            zipfile.ZipFile(
                source,
                "r",
            ) as zin,
            zipfile.ZipFile(
                tmp_path,
                "w",
                allowZip64=True,
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as zout
        ):
            for info in zin.infolist():
                name = info.filename

                # Remove bundle-level _CodeSignature
                # structures.
                if is_codesignature_path(name):
                    codesignature_entries += 1
                    continue

                if info.is_dir():
                    zout.writestr(
                        info,
                        b"",
                    )
                    continue

                payload = zin.read(info)

                stripped, removed = strip_macho(
                    payload
                )

                if removed:
                    macho_files += 1
                    macho_signatures += removed

                # Keep the original ZipInfo metadata,
                # including executable permission bits.
                zout.writestr(
                    info,
                    stripped,
                )

        # ZIP integrity check + residual signature scan.
        with zipfile.ZipFile(
            tmp_path,
            "r",
        ) as check:

            bad = check.testzip()

            if bad is not None:
                raise RuntimeError(
                    "repacked IPA failed ZIP "
                    f"integrity check at {bad}"
                )

            residual_signatures = 0
            residual_paths = []

            for entry in check.infolist():
                if entry.is_dir():
                    continue

                if is_codesignature_path(
                    entry.filename
                ):
                    continue

                payload = check.read(
                    entry
                )

                _, residual = strip_macho(
                    payload
                )

                if residual:
                    residual_signatures += residual
                    residual_paths.append(
                        entry.filename
                    )

            if residual_signatures:
                sample = ", ".join(
                    residual_paths[:5]
                )

                raise RuntimeError(
                    "code-signature stripping "
                    "verification failed: "
                    f"{residual_signatures} "
                    "residual Mach-O signature(s); "
                    f"sample: {sample}"
                )

        os.replace(
            tmp_path,
            destination,
        )

    finally:
        tmp_path.unlink(
            missing_ok=True
        )

    return {
        "macho_files_modified": macho_files,
        "macho_signatures_removed": macho_signatures,
        "codesignature_entries_removed": codesignature_entries,
    }


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if not STATE_FILE.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "source": {
                "manifest_url": MANIFEST_URL,
            },
            "app": {},
            "current": None,
            "pending": None,
            "history": [],
        }

    with STATE_FILE.open(
        "r",
        encoding="utf-8",
    ) as f:
        state = json.load(f)

    if not isinstance(state, dict):
        raise RuntimeError(
            "state JSON root is not an object"
        )

    if (
        state.get("schema_version")
        != SCHEMA_VERSION
    ):
        raise RuntimeError(
            "unsupported state schema: "
            f"{state.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION}"
        )

    state.setdefault(
        "source",
        {},
    )

    state.setdefault(
        "app",
        {},
    )

    state.setdefault(
        "current",
        None,
    )

    state.setdefault(
        "pending",
        None,
    )

    state.setdefault(
        "history",
        [],
    )

    return state


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = STATE_FILE.with_suffix(
        STATE_FILE.suffix + ".tmp"
    )

    with temp.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            state,
            f,
            indent=2,
            ensure_ascii=False,
        )

        f.write("\n")

    os.replace(
        temp,
        STATE_FILE,
    )


# ---------------------------------------------------------------------------
# Git / GitHub
# ---------------------------------------------------------------------------

def git_tag_exists(
    tag: str,
) -> bool:

    try:
        result = subprocess.run(
            [
                "git",
                "ls-remote",
                "--exit-code",
                "--tags",
                "origin",
                f"refs/tags/{tag}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )

        return result.returncode == 0

    except (
        OSError,
        subprocess.SubprocessError,
    ):
        return False


def release_view(
    tag: str,
) -> str | None:

    repo = os.environ.get(
        "GITHUB_REPOSITORY"
    )

    if (
        not repo
        or shutil.which("gh") is None
    ):
        return None

    result = subprocess.run(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            repo,
            "--json",
            "body",
            "--jq",
            ".body",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
    )

    if result.returncode != 0:
        return None

    return result.stdout


def choose_tag(
    version: str,
    state: dict,
) -> str:

    base = (
        f"v{safe_tag_component(version)}"
    )

    used = set()

    for record in state.get(
        "history",
        [],
    ):
        if (
            isinstance(record, dict)
            and record.get("release_tag")
        ):
            used.add(
                str(record["release_tag"])
            )

    current = state.get(
        "current"
    )

    if (
        isinstance(current, dict)
        and current.get("release_tag")
    ):
        used.add(
            str(current["release_tag"])
        )

    pending = state.get(
        "pending"
    )

    if (
        isinstance(pending, dict)
        and pending.get("release_tag")
    ):
        used.add(
            str(pending["release_tag"])
        )

    candidate = base
    revision = 1

    while (
        candidate in used
        or git_tag_exists(candidate)
    ):
        revision += 1

        candidate = (
            f"{base}-r{revision}"
        )

    return candidate


def write_github_outputs(
    values: dict[str, object],
) -> None:

    output = os.environ.get(
        "GITHUB_OUTPUT"
    )

    if not output:
        return

    with open(
        output,
        "a",
        encoding="utf-8",
    ) as f:

        for key, value in values.items():
            text = str(value)

            text = (
                text
                .replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A")
            )

            f.write(
                f"{key}={text}\n"
            )


def run_gh(
    args: list[str],
) -> subprocess.CompletedProcess[str]:

    if shutil.which("gh") is None:
        raise RuntimeError(
            "GitHub CLI (gh) is required"
        )

    env = os.environ.copy()

    if (
        "GH_TOKEN" not in env
        and "GITHUB_TOKEN" in env
    ):
        env["GH_TOKEN"] = env[
            "GITHUB_TOKEN"
        ]

    result = subprocess.run(
        ["gh", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
        timeout=600,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"gh failed: {args}"
        )

    return result


# ---------------------------------------------------------------------------
# Prepare
# ---------------------------------------------------------------------------

def prepare(
    force_release: bool = False,
) -> int:

    WORK_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    DIST_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Manifest
    # ---------------------------------------------------------

    log(
        f"Manifest URL: {MANIFEST_URL}"
    )

    log(
        "Downloading manifest..."
    )

    manifest_bytes = http_get(
        MANIFEST_URL
    )

    manifest_sha = hashlib.sha256(
        manifest_bytes
    ).hexdigest()

    manifest = parse_manifest(
        manifest_bytes
    )

    ok("Manifest parsed")

    title = manifest["title"]

    bundle_id = manifest[
        "bundle_identifier"
    ]

    bundle_version = manifest[
        "bundle_version"
    ]

    ipa_url = manifest[
        "ipa_url"
    ]

    manifest_path = (
        WORK_DIR
        / "manifest.plist"
    )

    manifest_path.write_bytes(
        manifest_bytes
    )

    # ---------------------------------------------------------
    # IPA
    # ---------------------------------------------------------

    source_ipa = (
        WORK_DIR
        / "source.ipa"
    )

    log(
        f"Downloading IPA: {ipa_url}"
    )

    download_file(
        ipa_url,
        source_ipa,
    )

    source_sha = sha256_file(
        source_ipa
    )

    ok(
        f"Source IPA SHA-256: "
        f"{source_sha}"
    )

    # ---------------------------------------------------------
    # IPA Info.plist
    # ---------------------------------------------------------

    with zipfile.ZipFile(
        source_ipa,
        "r",
    ) as zf:

        if zf.testzip() is not None:
            raise RuntimeError(
                "source IPA failed ZIP "
                "integrity check"
            )

        info_name, info_plist = (
            find_main_info_plist(zf)
        )

    ipa_bundle_id = str(
        info_plist.get(
            "CFBundleIdentifier"
        )
        or bundle_id
    )

    marketing_version = str(
        info_plist.get(
            "CFBundleShortVersionString"
        )
        or bundle_version
    )

    build_version = str(
        info_plist.get(
            "CFBundleVersion"
        )
        or bundle_version
    )

    executable = str(
        info_plist.get(
            "CFBundleExecutable"
        )
        or ""
    )

    display_name = str(
        info_plist.get(
            "CFBundleDisplayName"
        )
        or info_plist.get(
            "CFBundleName"
        )
        or title
    )

    # ---------------------------------------------------------
    # State
    # ---------------------------------------------------------

    state = load_state()

    current = (
        state.get("current")
        or {}
    )

    pending = (
        state.get("pending")
        or {}
    )

    current_source_sha = (
        current.get("source_sha256")
        if isinstance(current, dict)
        else None
    )

    current_version = (
        current.get("bundle_version")
        if isinstance(current, dict)
        else None
    )

    same_as_current = (
        not force_release
        and current_source_sha
        == source_sha
        and current_version
        == bundle_version
    )

    if (
        same_as_current
        and not pending
    ):
        ok(
            "No new IPA: current release "
            f"already contains {bundle_version}"
        )

        write_github_outputs(
            {
                "should_release": "false",
                "state_changed": "false",
                "release_tag": current.get(
                    "release_tag",
                    "",
                ),
                "version": bundle_version,
            }
        )

        return 0

    # ---------------------------------------------------------
    # Recover stale pending state
    # ---------------------------------------------------------

    pending_same_source = (
        isinstance(pending, dict)
        and pending.get(
            "source_sha256"
        ) == source_sha
        and pending.get(
            "bundle_version"
        ) == bundle_version
    )

    if pending and not pending_same_source:
        old_tag = str(
            pending.get(
                "release_tag"
            )
            or ""
        )

        old_source_sha = str(
            pending.get(
                "source_sha256"
            )
            or ""
        )

        old_body = (
            release_view(old_tag)
            if old_tag
            else None
        )

        if old_body is not None:
            marker = (
                "Source IPA SHA-256: "
                f"`{old_source_sha}`"
            )

            if marker not in old_body:
                raise RuntimeError(
                    f"pending release {old_tag} "
                    "exists on GitHub but its "
                    "source SHA-256 does not "
                    "match repository state"
                )

            recovered = dict(
                pending
            )

            recovered[
                "status"
            ] = "released"

            recovered[
                "released_at"
            ] = now_iso()

            history = (
                state.get("history")
                if isinstance(
                    state.get("history"),
                    list,
                )
                else []
            )

            history = [
                item
                for item in history
                if not (
                    isinstance(item, dict)
                    and item.get(
                        "release_tag"
                    ) == old_tag
                )
            ]

            history.append(
                recovered
            )

            state["current"] = recovered
            state["history"] = history
            state["pending"] = None

            save_state(state)

            pending = {}

            ok(
                "Recovered previously "
                f"published pending release "
                f"{old_tag}"
            )

        else:
            abandoned = dict(
                pending
            )

            abandoned[
                "status"
            ] = "abandoned"

            abandoned[
                "abandoned_at"
            ] = now_iso()

            abandoned[
                "abandon_reason"
            ] = (
                "No GitHub release existed "
                "when a newer source version "
                "was detected"
            )

            history = (
                state.get("history")
                if isinstance(
                    state.get("history"),
                    list,
                )
                else []
            )

            history.append(
                abandoned
            )

            state["history"] = history
            state["pending"] = None

            save_state(state)

            pending = {}

            warn(
                "No GitHub release found for "
                f"stale pending release {old_tag}; "
                "marking it abandoned"
            )

        current = (
            state.get("current")
            or {}
        )

    # ---------------------------------------------------------
    # Release tag
    # ---------------------------------------------------------

    if pending_same_source:
        release_tag = str(
            pending["release_tag"]
        )

        revision = int(
            pending.get(
                "release_revision",
                1,
            )
        )

    else:
        release_tag = choose_tag(
            bundle_version,
            state,
        )

        revision = 1

        match = re.search(
            r"-r(\d+)$",
            release_tag,
        )

        if match:
            revision = int(
                match.group(1)
            )

    # ---------------------------------------------------------
    # Strip
    # ---------------------------------------------------------

    safe_title = safe_component(
        display_name
        or title,
        "iOS_App",
    )

    safe_tag = safe_component(
        release_tag,
        "release",
    )

    asset_name = (
        f"{safe_title}_"
        f"{safe_tag}.ipa"
    )

    stripped_ipa = (
        DIST_DIR
        / asset_name
    )

    log(
        "Stripping Mach-O code signatures "
        "and bundle _CodeSignature entries..."
    )

    strip_stats = strip_ipa(
        source_ipa,
        stripped_ipa,
    )

    stripped_sha = sha256_file(
        stripped_ipa
    )

    ok(
        "Stripped "
        f"{strip_stats['macho_signatures_removed']} "
        "Mach-O code signature(s); "
        "removed "
        f"{strip_stats['codesignature_entries_removed']} "
        "_CodeSignature archive entries"
    )

    # ---------------------------------------------------------
    # Release assets
    # ---------------------------------------------------------

    checksum_file = (
        DIST_DIR
        / f"{asset_name}.sha256"
    )

    checksum_file.write_text(
        f"{stripped_sha}  "
        f"{asset_name}\n",
        encoding="utf-8",
    )

    release_metadata = {
        "schema_version": 1,
        "title": display_name,
        "manifest_title": title,
        "bundle_identifier": bundle_id,
        "ipa_bundle_identifier": ipa_bundle_id,
        "bundle_version": bundle_version,
        "marketing_version": marketing_version,
        "build_version": build_version,
        "executable": executable,
        "info_plist_path": info_name,
        "manifest_url": MANIFEST_URL,
        "ipa_url": ipa_url,
        "manifest_sha256": manifest_sha,
        "source_sha256": source_sha,
        "stripped_sha256": stripped_sha,
        "release_tag": release_tag,
        "release_revision": revision,
        "release_name": (
            f"{display_name} "
            f"{marketing_version} "
            f"({build_version})"
        ),
        "asset_name": asset_name,
        "asset_path": str(
            stripped_ipa
        ),
        "checksum_path": str(
            checksum_file
        ),
        "strip": strip_stats,
        "prepared_at": now_iso(),
    }

    release_notes = (
        f"## {display_name} "
        f"{marketing_version} "
        f"({build_version})\n\n"

        f"Bundle ID: "
        f"`{ipa_bundle_id}`\n\n"

        f"Manifest version: "
        f"`{bundle_version}`\n\n"

        f"Release tag: "
        f"`{release_tag}`\n\n"

        f"Source manifest: "
        f"`{MANIFEST_URL}`\n\n"

        f"Source IPA: "
        f"`{ipa_url}`\n\n"

        f"Source IPA SHA-256: "
        f"`{source_sha}`\n\n"

        f"Stripped IPA SHA-256: "
        f"`{stripped_sha}`\n\n"

        f"Mach-O signatures removed: "
        f"`{strip_stats['macho_signatures_removed']}`\n\n"

        f"`_CodeSignature` archive entries removed: "
        f"`{strip_stats['codesignature_entries_removed']}`\n"
    )

    release_metadata[
        "release_notes"
    ] = release_notes

    META_FILE.write_text(
        json.dumps(
            release_metadata,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    (
        WORK_DIR
        / "release-notes.md"
    ).write_text(
        release_notes,
        encoding="utf-8",
    )

    shutil.copy2(
        manifest_path,
        DIST_DIR / "manifest.plist",
    )

    (
        DIST_DIR
        / "release-meta.json"
    ).write_text(
        json.dumps(
            release_metadata,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # Pending state
    #
    # This is intentionally committed BEFORE release creation.
    # If GitHub release creation fails, the next workflow run
    # can reuse the same tag instead of inventing a new one.
    # ---------------------------------------------------------

    state["source"] = {
        "manifest_url": MANIFEST_URL,
        "ipa_url": ipa_url,
    }

    state["app"] = {
        "title": display_name,
        "bundle_identifier": ipa_bundle_id,
    }

    state["pending"] = {
        **release_metadata,
        "status": "pending",
    }

    save_state(state)

    ok(
        f"Prepared release {release_tag}"
    )

    write_github_outputs(
        {
            "should_release": "true",
            "state_changed": "true",
            "release_tag": release_tag,
            "version": bundle_version,
            "asset_path": str(
                stripped_ipa
            ),
        }
    )

    return 0


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------

def publish() -> int:
    state = load_state()

    pending = state.get(
        "pending"
    )

    if not isinstance(
        pending,
        dict,
    ):
        ok(
            "No pending release"
        )
        return 0

    if not META_FILE.exists():
        raise RuntimeError(
            f"missing release metadata: "
            f"{META_FILE}"
        )

    meta = json.loads(
        META_FILE.read_text(
            encoding="utf-8"
        )
    )

    release_tag = str(
        pending["release_tag"]
    )

    source_sha = str(
        pending["source_sha256"]
    )

    repo = os.environ.get(
        "GITHUB_REPOSITORY"
    )

    if not repo:
        raise RuntimeError(
            "GITHUB_REPOSITORY is not set"
        )

    # ---------------------------------------------------------
    # Existing release recovery
    # ---------------------------------------------------------

    body = release_view(
        release_tag
    )

    if body is None:
        log(
            f"Creating GitHub release "
            f"{release_tag}..."
        )

        release_target = (
            subprocess.check_output(
                [
                    "git",
                    "rev-parse",
                    "HEAD",
                ],
                text=True,
            )
            .strip()
        )

        run_gh(
            [
                "release",
                "create",
                release_tag,

                # IPA
                str(
                    meta["asset_path"]
                ),

                # SHA256
                str(
                    meta["checksum_path"]
                ),

                # Original installation manifest
                str(
                    DIST_DIR
                    / "manifest.plist"
                ),

                # Machine-readable metadata
                str(
                    DIST_DIR
                    / "release-meta.json"
                ),

                "--repo",
                repo,

                "--target",
                release_target,

                "--title",
                str(
                    meta["release_name"]
                ),

                "--notes-file",
                str(
                    WORK_DIR
                    / "release-notes.md"
                ),

                "--latest",
            ]
        )

        ok(
            f"GitHub release "
            f"{release_tag} published"
        )

    else:
        marker = (
            "Source IPA SHA-256: "
            f"`{source_sha}`"
        )

        if marker not in body:
            raise RuntimeError(
                f"GitHub release {release_tag} "
                "already exists but does not "
                "match pending source SHA-256"
            )

        ok(
            f"GitHub release {release_tag} "
            "already exists; "
            "recovering/finalizing state"
        )

    # ---------------------------------------------------------
    # Finalize state
    # ---------------------------------------------------------

    record = dict(
        pending
    )

    record[
        "status"
    ] = "released"

    record[
        "released_at"
    ] = now_iso()

    history = state.get(
        "history"
    )

    if not isinstance(
        history,
        list,
    ):
        history = []

    # Never duplicate the same tag.
    history = [
        item
        for item in history
        if not (
            isinstance(item, dict)
            and item.get(
                "release_tag"
            ) == release_tag
        )
    ]

    history.append(
        record
    )

    history.sort(
        key=lambda item: str(
            item.get(
                "released_at",
                "",
            )
        )
    )

    state["current"] = record
    state["pending"] = None
    state["history"] = history

    save_state(state)

    # ---------------------------------------------------------
    # Commit final state
    # ---------------------------------------------------------

    subprocess.run(
        [
            "git",
            "config",
            "user.name",
            "github-actions[bot]",
        ],
        check=True,
    )

    subprocess.run(
        [
            "git",
            "config",
            "user.email",
            "41898282+github-actions[bot]"
            "@users.noreply.github.com",
        ],
        check=True,
    )

    subprocess.run(
        [
            "git",
            "add",
            str(STATE_FILE),
        ],
        check=True,
    )

    diff = subprocess.run(
        [
            "git",
            "diff",
            "--cached",
            "--quiet",
        ],
        check=False,
    )

    if diff.returncode != 0:
        subprocess.run(
            [
                "git",
                "commit",
                "-m",
                (
                    "chore(ipa): "
                    f"record "
                    f"{meta['release_name']}"
                ),
            ],
            check=True,
        )

        branch = (
            os.environ.get(
                "GITHUB_REF_NAME"
            )
            or subprocess.check_output(
                [
                    "git",
                    "branch",
                    "--show-current",
                ],
                text=True,
            ).strip()
        )

        if branch:
            subprocess.run(
                [
                    "git",
                    "push",
                    "origin",
                    f"HEAD:{branch}",
                ],
                check=True,
            )

            ok(
                f"Updated {STATE_FILE} "
                "and pushed state"
            )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch, strip, release, "
            "and track an iOS IPA"
        )
    )

    sub = parser.add_subparsers(
        dest="command",
        required=False,
    )

    prepare_parser = sub.add_parser(
        "prepare"
    )

    prepare_parser.add_argument(
        "--force-release",
        action="store_true",
    )

    sub.add_parser(
        "publish"
    )

    args = parser.parse_args()

    command = (
        args.command
        or "prepare"
    )

    try:
        if command == "prepare":
            force = (
                args.force_release
                or parse_bool_env(
                    "IPA_FORCE_RELEASE",
                    False,
                )
            )

            return prepare(
                force_release=force
            )

        if command == "publish":
            return publish()

        raise RuntimeError(
            f"unknown command: {command}"
        )

    except KeyboardInterrupt:
        warn(
            "interrupted"
        )
        return 130

    except Exception as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
