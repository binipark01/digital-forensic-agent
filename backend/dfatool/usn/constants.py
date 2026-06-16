from __future__ import annotations

from typing import Final

from dfatool import __version__ as PARSER_VERSION

PARSER_NAME: Final = "dfatool.usn"
SOURCE_ARTIFACT: Final = "NTFS:$UsnJrnl:$J"
TIMESTAMP_SOURCE: Final = "$UsnJrnl:$J"

USN_RECORD_V2_HEADER_SIZE: Final = 60
USN_RECORD_V3_HEADER_SIZE: Final = 76
MAX_RECORD_SIZE: Final = 1024 * 1024

FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010

REASON_FLAGS: Final = (
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x80000000, "CLOSE"),
)

CONTENT_REASON_FLAGS: Final = frozenset(
    {
        "DATA_OVERWRITE",
        "DATA_EXTEND",
        "DATA_TRUNCATION",
        "NAMED_DATA_OVERWRITE",
        "NAMED_DATA_EXTEND",
        "NAMED_DATA_TRUNCATION",
    }
)

DIRECT_ACTIONS: Final = {
    "FILE_CREATE": "file_created",
    "FILE_DELETE": "file_deleted",
    "RENAME_OLD_NAME": "file_rename_old_name",
    "RENAME_NEW_NAME": "file_rename_new_name",
    "BASIC_INFO_CHANGE": "file_metadata_modified",
    "SECURITY_CHANGE": "file_security_modified",
}
