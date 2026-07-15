"""Entry point for udf-rename: rename embedded FID entries in UDF images."""
import runpy
from pathlib import Path


def main():
    """Rename a file identifier within a UDF Extended File Entry."""
    script = Path(__file__).parent / "original" / "py-renamefile.py"
    runpy.run_path(str(script), run_name="__main__")