from pathlib import Path
import os

BASE_DIR = Path(os.getenv("TED_BASE_DIR", "./workspace"))

XML_DIR = BASE_DIR / "xml"
DB_DIR = BASE_DIR / "db"
EXPORT_DIR = BASE_DIR / "exports"
LAYOUT_DIR = BASE_DIR / "layouts"

for path in (XML_DIR, DB_DIR, EXPORT_DIR, LAYOUT_DIR):
    path.mkdir(parents=True, exist_ok=True)