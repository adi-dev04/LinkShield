import os


def analyze_exe(file_path: str) -> dict:
    findings = []
    try:
        with open(file_path, "rb") as file:
            header = file.read(64)
            if not header.startswith(b"MZ"):
                raise ValueError("Invalid Windows executable file.")
            pe_offset = int.from_bytes(header[60:64], byteorder="little")
            file.seek(pe_offset)
            pe_signature = file.read(4)
            if pe_signature != b"PE\x00\x00":
                raise ValueError("Invalid PE executable signature.")
            file_size = os.path.getsize(file_path)
            if file_size < 1024:
                findings.append(
                    {
                        "title": "Unusually Small Executable",
                        "description": "The executable file is unusually small and deserves further inspection.",
                        "severity": "low",
                    }
                )
            return {
                "file_type": "EXE",
                "file_size": file_size,
                "findings": findings,
                "status": "analyzed",
            }
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("Unable to analyze this EXE file.") from error
