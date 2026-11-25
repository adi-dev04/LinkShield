import zipfile
import os

MAX_FILES = 2000
MAX_UNCOMPRESSED_SIZE = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000


def analyze_apk(file_path: str) -> dict:

    findings = []

    try:

        if not zipfile.is_zipfile(file_path):
            raise ValueError("Invalid APK file.")

        with zipfile.ZipFile(file_path, "r") as apk:

            file_list = apk.infolist()

            if len(file_list) > MAX_FILES:
                raise ValueError("APK contains too many files.")

            total_size = sum(item.file_size for item in file_list)

            if total_size > MAX_UNCOMPRESSED_SIZE:
                raise ValueError("APK uncompressed size exceeds the allowed limit.")

            for item in file_list:

                if item.compress_size > 0:

                    ratio = item.file_size / item.compress_size

                    if ratio > MAX_COMPRESSION_RATIO:
                        findings.append(
                            {
                                "title": "Suspicious compression ratio",
                                "description": "An APK entry has an unusually high compression ratio.",
                                "severity": "high",
                            }
                        )

            file_names = apk.namelist()

            has_manifest = "AndroidManifest.xml" in file_names

            has_dex = any(name.endswith(".dex") for name in file_names)

            if not has_manifest:
                findings.append(
                    {
                        "title": "Android manifest missing",
                        "description": "The APK does not contain AndroidManifest.xml.",
                        "severity": "high",
                    }
                )

            if not has_dex:
                findings.append(
                    {
                        "title": "DEX file missing",
                        "description": "No Android Dalvik executable file was found.",
                        "severity": "medium",
                    }
                )

            return {
                "file_type": "APK",
                "file_size": os.path.getsize(file_path),
                "file_count": len(file_list),
                "has_manifest": has_manifest,
                "has_dex": has_dex,
                "findings": findings,
                "status": "analyzed",
            }

    except ValueError:
        raise

    except Exception as error:
        raise ValueError("Unable to analyze this APK file.") from error
