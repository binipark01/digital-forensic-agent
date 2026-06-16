from __future__ import annotations

from functools import lru_cache

from dfatool.mft.models import FileNameAttribute, MftRecord


def reconstruct_paths(records: list[MftRecord]) -> None:
    records_by_entry = {record.entry: record for record in records}

    @lru_cache(maxsize=None)
    def build_path(entry: int, seen: tuple[int, ...] = ()) -> str:
        record = records_by_entry.get(entry)
        if not record:
            return f"/$OrphanFiles/{entry}"
        file_name = preferred_file_name(record)
        if not file_name:
            return f"/$MFT/{entry}"
        parent_entry = file_name.parent_reference.entry
        if file_name.name in {"", "."} or parent_entry == entry:
            return "/"
        if entry in seen:
            record.warnings.append("parent reference loop while reconstructing path")
            return f"/$PathLoop/{entry}/{file_name.name}"
        parent = build_path(parent_entry, (*seen, entry)).rstrip("/")
        return f"{parent}/{file_name.name}" if parent else f"/{file_name.name}"

    for record in records:
        record.path = build_path(record.entry)
        for file_name in record.file_names:
            file_name.full_path = _file_name_path(file_name, record, build_path)


def preferred_file_name(record: MftRecord) -> FileNameAttribute | None:
    if not record.file_names:
        return None
    order = {1: 0, 3: 1, 0: 2, 2: 3}
    return sorted(record.file_names, key=lambda item: (order.get(item.namespace, 9), item.name))[0]


def timeline_file_names(record: MftRecord) -> list[FileNameAttribute]:
    non_dos = [file_name for file_name in record.file_names if file_name.namespace != 2]
    return non_dos or record.file_names


def file_name_aliases(record: MftRecord, selected: FileNameAttribute | None) -> list[dict[str, str | int]]:
    aliases = []
    for file_name in record.file_names:
        if selected is file_name:
            continue
        aliases.append(
            {
                "name": file_name.name,
                "namespace": file_name.namespace,
                "namespace_name": file_name.namespace_name,
            }
        )
    return aliases


def path_assessment(record: MftRecord, selected_path: str | None = None) -> tuple[str, list[str]]:
    warnings: list[str] = []
    confidence = "high"
    path = selected_path or record.path
    if record.is_deleted:
        confidence = "low"
        warnings.append("deleted record path is best-effort and not an asserted current path")
    if path.startswith("/$OrphanFiles"):
        confidence = "low"
        warnings.append("parent reference was not present in parsed records")
    if path.startswith("/$PathLoop"):
        confidence = "low"
        warnings.append("parent reference loop was detected during path reconstruction")
    if path.startswith("/$MFT/"):
        confidence = "medium"
        warnings.append("record has no usable $FILE_NAME attribute")
    return confidence, warnings


def _file_name_path(
    file_name: FileNameAttribute,
    record: MftRecord,
    build_path,
) -> str:
    if file_name.name in {"", "."} or file_name.parent_reference.entry == record.entry:
        return "/"
    parent = build_path(file_name.parent_reference.entry).rstrip("/")
    return f"{parent}/{file_name.name}" if parent else f"/{file_name.name}"
