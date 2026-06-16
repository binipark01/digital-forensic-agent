from __future__ import annotations

from datetime import UTC, datetime

from dfatool import __version__ as PARSER_VERSION

PARSER_NAME = "dfatool.mft"
ATTRIBUTE_END = 0xFFFFFFFF
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

ATTRIBUTE_NAMES = {
    ATTR_STANDARD_INFORMATION: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    ATTR_FILE_NAME: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    ATTR_DATA: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0x100: "$LOGGED_UTILITY_STREAM",
}

FILE_NAME_NAMESPACES = {
    0: "POSIX",
    1: "Win32",
    2: "DOS",
    3: "Win32+DOS",
}

TIMESTAMP_ACTIONS = {
    "created": "file_created",
    "modified": "file_modified",
    "mft_modified": "file_mft_modified",
    "accessed": "file_accessed",
}

SOURCE_ARTIFACTS = {
    "$STANDARD_INFORMATION": "NTFS:$MFT:$STANDARD_INFORMATION",
    "$FILE_NAME": "NTFS:$MFT:$FILE_NAME",
    "$DATA": "NTFS:$MFT:$DATA",
}
