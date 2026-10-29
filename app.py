"""
app.py — Root launcher forwarding to AREE v2.0 Dashboard (ui/app.py).
"""
import runpy
from pathlib import Path

UI_APP_PATH = Path(__file__).parent / "ui" / "app.py"

if __name__ == "__main__":
    runpy.run_path(str(UI_APP_PATH), run_name="__main__")
