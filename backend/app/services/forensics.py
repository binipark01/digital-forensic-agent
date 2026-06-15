from __future__ import annotations

import hashlib
import importlib.metadata
import shutil
from pathlib import Path
from typing import Any

from dfatool import __version__ as dfatool_version


CHUNK_SIZE = 1024 * 1024


def hash_file(path: Path) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def detect_image_format(path: Path) -> tuple[str, dict[str, Any]]:
    suffix = path.suffix.lower()
    hints: dict[str, Any] = {"extension": suffix, "recognized_by": []}

    header = b""
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
    except OSError:
        header = b""

    if header.startswith(b"EVF"):
        hints["recognized_by"].append("ewf_magic")
        return "ewf", hints

    if header.startswith(b"FILE"):
        hints["recognized_by"].append("mft_file_signature")
        return "ntfs_mft", hints

    if suffix in {".e01", ".ex01", ".s01"}:
        hints["recognized_by"].append("ewf_extension")
        return "ewf", hints

    if suffix in {".dd", ".img", ".raw", ".001"}:
        hints["recognized_by"].append("raw_extension")
        return "raw", hints

    if path.name.lower() in {"$mft", "mft"} or suffix.lower() in {".mft"}:
        hints["recognized_by"].append("mft_name")
        return "ntfs_mft", hints

    hints["recognized_by"].append("fallback_raw")
    return "raw", hints


def parser_capabilities() -> dict[str, Any]:
    packages: dict[str, str | None] = {}
    for package_name in ("dfvfs", "pytsk3", "pyewf", "pyfsntfs"):
        try:
            packages[package_name] = importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError:
            packages[package_name] = None

    commands = {
        "mmls": shutil.which("mmls"),
        "fls": shutil.which("fls"),
    }

    return {
        "dfatool": {
            "version": dfatool_version,
            "mft_parser": True,
        },
        "packages": packages,
        "commands": commands,
        "sleuthkit_cli_available": bool(commands["fls"]),
        "dfvfs_available": bool(packages["dfvfs"]),
        "supported_image_formats": ["extracted_ntfs_mft", "ewf", "raw"],
        "supported_artifacts": ["NTFS:$MFT", "$UsnJrnl:$J", "Recycle Bin", "NTFS metadata"],
    }
