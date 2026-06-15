from __future__ import annotations

from pathlib import Path

from app.services.forensics import detect_image_format, hash_file


def test_detect_image_format_from_extension_and_magic(tmp_path: Path) -> None:
    raw = tmp_path / "disk.dd"
    raw.write_bytes(b"not an ewf file")
    assert detect_image_format(raw)[0] == "raw"

    ewf = tmp_path / "case.bin"
    ewf.write_bytes(b"EVF\t\r\n\xff\x00extra")
    assert detect_image_format(ewf)[0] == "ewf"


def test_hash_file_returns_three_hashes(tmp_path: Path) -> None:
    image = tmp_path / "image.raw"
    image.write_bytes(b"forensic image bytes")

    hashes = hash_file(image)

    assert set(hashes) == {"md5", "sha1", "sha256"}
    assert len(hashes["sha256"]) == 64

