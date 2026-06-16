from __future__ import annotations

ALLOWED_SOURCE_TYPES = frozenset(
    {
        "mounted_directory",
        "mounted_volume",
        "mounted_windows_directory",
        "mounted_windows_volume",
    }
)

MFT_PARSER_HINT = {"parser": "dfatool.mft", "parser_status": "implemented", "priority": 20}
SIDECAR_PARSER_HINT = {"parser": "sidecar", "parser_status": "implemented", "priority": 10}
UNSUPPORTED_PARSER_HINT = {
    "parser": None,
    "implemented": False,
    "warning_code": "parser_not_implemented",
    "priority": 100,
}

PARSER_HINTS = {
    "ntfs_mft": MFT_PARSER_HINT,
    "NTFS:$MFT": MFT_PARSER_HINT,
    "sidecar_timeline": SIDECAR_PARSER_HINT,
}

DEFAULT_DISCOVERY_PATTERNS = [
    ("ntfs_mft", "$MFT"),
    ("NTFS:$LogFile", "$LogFile"),
    ("NTFS:$Boot", "$Boot"),
    ("NTFS:$Bitmap", "$Bitmap"),
    ("NTFS:$UsnJrnl", "$Extend/$UsnJrnl"),
    ("recycle_bin", "$Recycle.Bin"),
    ("windows_event_log", "Windows/System32/winevt/Logs/*.evtx"),
    ("prefetch", "Windows/Prefetch/*.pf"),
    ("registry_hive", "Windows/System32/config/SYSTEM"),
    ("registry_hive", "Windows/System32/config/SOFTWARE"),
    ("registry_hive", "Windows/System32/config/SAM"),
    ("registry_hive", "Windows/System32/config/SECURITY"),
    ("registry_hive", "Users/*/NTUSER.DAT"),
    ("registry_hive", "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"),
    ("browser_history", "Users/*/AppData/Local/Google/Chrome/User Data/*/History"),
    ("browser_history", "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History"),
    ("browser_history", "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite"),
    ("windows_webcache", "Users/*/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"),
    ("lnk_file", "Users/**/*.lnk"),
    ("jump_list", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms"),
    ("jump_list", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms"),
    ("sidecar_timeline", "**/*.timeline.json"),
    ("sidecar_timeline", "**/*.timeline.csv"),
]
