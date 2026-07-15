"""Entry point for udf-volume: UDF volume structure parser."""
import runpy
from pathlib import Path


def main():
    """Parse and display UDF volume structure from a hex dump."""
    script = Path(__file__).parent / "original" / "py-volume-structure.py"
    runpy.run_path(str(script), run_name="__main__")