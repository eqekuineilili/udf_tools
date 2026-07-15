"""Entry point for udf-crc: repair UDF descriptor CRC checksums."""
import runpy
from pathlib import Path


def main():
    """Scan and fix CRC checksums for UDF Extended File Entries."""
    script = Path(__file__).parent / "original" / "py-crc.py"
    runpy.run_path(str(script), run_name="__main__")