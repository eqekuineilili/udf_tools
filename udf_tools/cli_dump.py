"""Entry point for udf-dump: UDF descriptor dumper."""
import runpy
from pathlib import Path


def main():
    """Parse and display UDF descriptors from a binary image file."""
    script = Path(__file__).parent / "original" / "py-file-structure.py"
    runpy.run_path(str(script), run_name="__main__")