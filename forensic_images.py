import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile


class ForensicImageError(Exception):
    pass


ANALYSIS_TOOLS = ("img_stat", "img_cat", "mmls", "fsstat", "fls")
RECOVERY_TOOLS = ("tsk_recover",)


def require_tools(names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise ForensicImageError(
            "The Sleuth Kit tools are missing: " + ", ".join(missing) +
            ". Install The Sleuth Kit and add its bin directory to PATH."
        )


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_text(args):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ForensicImageError(
            f"{os.path.basename(args[0])} failed (exit {result.returncode}): "
            f"{detail[:1200] or 'no diagnostic output'}"
        )
    return result.stdout


def _logical_image_hash(image_path, image_type):
    digest = hashlib.sha256()
    command = ["img_cat", "-i", image_type, image_path]
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error_output)
        if process.stdout is None:
            raise ForensicImageError("Could not read the logical image stream.")
        byte_count = 0
        try:
            for chunk in iter(lambda: process.stdout.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
        finally:
            process.stdout.close()
        return_code = process.wait()
        error_output.seek(0)
        error_message = error_output.read().decode("utf-8", errors="replace").strip()
    if return_code:
        raise ForensicImageError(
            f"img_cat could not read the complete image (exit {return_code}): "
            f"{error_message[:1200] or 'no diagnostic output'}"
        )
    if byte_count == 0:
        raise ForensicImageError("The forensic reader returned an empty image.")
    return digest.hexdigest(), byte_count


def _parse_partitions(mmls_output):
    sector_match = re.search(r"Units are in\s+(\d+)-byte sectors", mmls_output, re.I)
    sector_size = int(sector_match.group(1)) if sector_match else 512
    row_pattern = re.compile(
        r"^\s*(\d{3}):\s+\d{3}:\d{3}\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$"
    )
    partitions = []
    for line in mmls_output.splitlines():
        match = row_pattern.match(line)
        if not match:
            continue
        slot, start, end, length, description = match.groups()
        if re.search(r"\b(unallocated|table|metadata)\b", description, re.I):
            continue
        start_sector = int(start)
        end_sector = int(end)
        partitions.append({
            "slot": slot,
            "start_sector": start_sector,
            "end_sector": end_sector,
            "length_sectors": int(length),
            "offset_bytes": start_sector * sector_size,
            "description": description.strip(),
        })
    return sector_size, partitions


def _write_file_listing(image_path, image_type, offset, listing_path):
    command = ["fls", "-r", "-p", "-i", image_type, "-o", str(offset), image_path]
    with open(listing_path, "w", encoding="utf-8", errors="replace", newline="") as output:
        result = subprocess.run(
            command,
            stdout=output,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    if result.returncode:
        try:
            os.remove(listing_path)
        except FileNotFoundError:
            pass
        raise ForensicImageError(
            f"fls failed (exit {result.returncode}): "
            f"{(result.stderr or 'no diagnostic output').strip()[:1200]}"
        )
    total = 0
    deleted = 0
    sample = []
    with open(listing_path, "r", encoding="utf-8", errors="replace") as listing:
        for line in listing:
            clean_line = line.rstrip("\r\n")
            total += 1
            if re.search(r"\s\*\s", clean_line):
                deleted += 1
            if len(sample) < 100:
                sample.append(clean_line)
    return {"file_count": total, "deleted_entry_count": deleted, "sample": sample}


def analyze_image(image_path, image_type, artifact_dir):
    require_tools(ANALYSIS_TOOLS)
    os.makedirs(artifact_dir, exist_ok=True)
    image_info = _run_text(["img_stat", "-i", image_type, image_path])
    partition_table_error = None
    try:
        partition_table = _run_text(["mmls", "-i", image_type, image_path])
    except ForensicImageError as exc:
        partition_table = "No partition table output was available."
        partition_table_error = str(exc)
    sector_size, partitions = _parse_partitions(partition_table)
    if not partitions:
        partitions = [{
            "slot": "000",
            "start_sector": 0,
            "end_sector": None,
            "length_sectors": None,
            "offset_bytes": 0,
            "description": "Whole image (no partition table entry detected)",
        }]

    results = []
    for index, partition in enumerate(partitions, start=1):
        offset = partition["start_sector"]
        result = dict(partition)
        try:
            result["filesystem_info"] = _run_text([
                "fsstat", "-i", image_type, "-o", str(offset), image_path,
            ])
        except ForensicImageError as exc:
            result["filesystem_error"] = str(exc)
            results.append(result)
            continue

        listing_name = f"partition_{index}_files.txt"
        listing_path = os.path.join(artifact_dir, listing_name)
        try:
            listing_summary = _write_file_listing(
                image_path, image_type, offset, listing_path
            )
            listing_summary["listing_file"] = listing_name
            listing_summary["listing_sha256"] = sha256_file(listing_path)
            result["file_listing"] = listing_summary
        except ForensicImageError as exc:
            result["listing_error"] = str(exc)
        results.append(result)

    logical_sha256, logical_size = _logical_image_hash(image_path, image_type)
    return {
        "image_info": image_info,
        "partition_table": partition_table,
        "partition_table_error": partition_table_error,
        "sector_size_bytes": sector_size,
        "partitions": results,
        "logical_sha256": logical_sha256,
        "logical_size_bytes": logical_size,
    }


def recover_image(image_path, image_type, analysis, artifact_dir):
    require_tools(RECOVERY_TOOLS)
    os.makedirs(artifact_dir, exist_ok=True)
    recovery_root = os.path.join(artifact_dir, "recovered")
    if os.path.isdir(recovery_root):
        shutil.rmtree(recovery_root)
    manifest_path = os.path.join(artifact_dir, "recovery-manifest.jsonl")
    if os.path.exists(manifest_path):
        os.remove(manifest_path)
    os.makedirs(recovery_root, exist_ok=True)
    recovered_count = 0
    recovered_bytes = 0
    partitions = analysis.get("partitions") or []
    usable_partitions = [
        part for part in partitions
        if part.get("filesystem_info") and not part.get("filesystem_error")
    ]
    if not usable_partitions:
        raise ForensicImageError(
            "No readable filesystem was found. Recovery was not started."
        )

    for index, partition in enumerate(usable_partitions, start=1):
        output_dir = os.path.join(recovery_root, f"partition_{index}")
        os.makedirs(output_dir, exist_ok=True)
        command = [
            "tsk_recover", "-e", "-i", image_type,
            "-o", str(partition["start_sector"]), image_path, output_dir,
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise ForensicImageError(
                f"tsk_recover failed for partition {partition['slot']} "
                f"(exit {result.returncode}): {detail[:1200] or 'no diagnostic output'}"
            )

    with open(manifest_path, "w", encoding="utf-8") as manifest:
        for current_dir, directories, filenames in os.walk(recovery_root):
            directories[:] = [
                name for name in directories
                if not os.path.islink(os.path.join(current_dir, name))
            ]
            for name in filenames:
                full_path = os.path.join(current_dir, name)
                if os.path.islink(full_path) or not os.path.isfile(full_path):
                    continue
                relative_path = os.path.relpath(full_path, recovery_root).replace(os.sep, "/")
                size = os.path.getsize(full_path)
                file_record = {
                    "path": relative_path,
                    "size_bytes": size,
                    "sha256": sha256_file(full_path),
                }
                manifest.write(json.dumps(file_record, ensure_ascii=False) + "\n")
                recovered_count += 1
                recovered_bytes += size

    return {
        "recovered_file_count": recovered_count,
        "recovered_size_bytes": recovered_bytes,
        "manifest_file": os.path.basename(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "recovery_scope": "All files reported recoverable by The Sleuth Kit (-e).",
    }
