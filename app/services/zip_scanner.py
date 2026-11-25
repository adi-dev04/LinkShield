
import zipfile
import os

MAX_FILES = 1000
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_COMPRESSION_RATIO = 1000


def analyze_zip(file_path: str) -> dict:

    findings = []

    try:
        with zipfile.ZipFile(file_path, "r") as archive:

            file_list = archive.namelist()
            file_info = archive.infolist()
            if len(file_info) > MAX_FILES:
                raise ValueError("ZIP archive contains too many files.")
            total_uncompressed_size = sum(
                item.file_size for item in file_info
                )
            if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE:
                raise ValueError("ZIP archive exceeds the 100 MB uncompressed size limit.")
            for item in file_info:
                if item.file_size > 0 and item.compress_size == 0:
                    raise ValueError("ZIP archive contains a suspicious compression ratio.")
                if item.compress_size > 0:
                    compression_ratio = item.file_size / item.compress_size
                    if compression_ratio > MAX_COMPRESSION_RATIO:
                        raise ValueError("ZIP archive exceeds the allowed compression ratio.")

            if not file_list:
                findings.append({
                    "title": "Empty ZIP Archive",
                    "description": "The ZIP archive contains no files.",
                    "severity": "low"
                })

            suspicious_extensions = [
                ".exe",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".scr",
                ".msi"
            ]

            for file_name in file_list:

                extension = os.path.splitext(file_name)[1].lower()

                if extension in suspicious_extensions:
                    findings.append({
                        "title": "Suspicious File in ZIP",
                        "description": f"The archive contains a potentially risky file: {file_name}",
                        "severity": "medium"
                    })

            return {
                "file_type": "ZIP",
                "file_count": len(file_list),
                "findings": findings,
                "status": "analyzed"
            }

    except zipfile.BadZipFile as error:
        raise ValueError("Invalid or corrupted ZIP archive.") from error

    except Exception as error:
        raise ValueError("Unable to analyze this ZIP file.") from error
