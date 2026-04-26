"""
db_handler.py — web-ready utility helpers for:
- XML parsing (file-based and RPC-based)
- JSON database load/save
- CSV loading
- Centralized file error handling
"""

from __future__ import annotations

import csv
import json
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union

import jxmlease
from lxml import etree


T = TypeVar("T")


# -----------------------------
# Exceptions
# -----------------------------

class DbHandlerError(Exception):
    """Base exception for db_handler."""


class FileOperationError(DbHandlerError):
    """Raised for file read/write/parse errors with a clear message."""


# -----------------------------
# Error handling decorator
# -----------------------------

def file_error_handler(*, exit_on_error: bool = False) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator factory for handling common file-related exceptions.

    For web integration, default is exit_on_error=False and we raise FileOperationError.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return func(*args, **kwargs)

            except FileNotFoundError as e:
                raise FileOperationError(f"File not found: {getattr(e, 'filename', '') or e}") from e
            except PermissionError as e:
                raise FileOperationError(f"Permission denied: {getattr(e, 'filename', '') or e}") from e
            except IsADirectoryError as e:
                raise FileOperationError(f"Expected a file but got a directory: {getattr(e, 'filename', '') or e}") from e
            except csv.Error as e:
                raise FileOperationError(f"CSV parsing failed: {e}") from e
            except etree.XMLSyntaxError as e:
                raise FileOperationError(f"XML parsing failed: {e}") from e
            except Exception as e:
                raise FileOperationError(f"Unexpected error in {func.__name__}: {e}") from e

        return wrapper
    return decorator


# -----------------------------
# XML parsing
# -----------------------------

@file_error_handler()
def parse_xml(xml_file: Union[str, Path]) -> dict:
    """
    Parse an XML file into a Python dictionary-like structure via jxmlease.
    """
    xml_path = Path(xml_file)
    root = etree.parse(str(xml_path)).getroot()
    return jxmlease.parse(etree.tostring(root, pretty_print=True))

@file_error_handler()
def parse_xml_rpc(rpc_response) -> dict:
    """
    Parse an XML RPC response (lxml Element) into a dictionary-like structure.
    """
    return jxmlease.parse(etree.tostring(rpc_response, pretty_print=True))


# -----------------------------
# JSON DB
# -----------------------------

@file_error_handler()
def load_json_db(db_file: Union[str, Path]) -> dict:
    db_path = Path(db_file)
    with open(db_path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise FileOperationError("JSON contents are not a dict.")
    return obj


@file_error_handler()
def save_json_db(db_output: Union[str, Path], node_db: dict) -> None:
    out_path = Path(db_output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(node_db, f, indent=2, sort_keys=True)

# -----------------------------
# CSV
# -----------------------------

@file_error_handler()
def csv_to_list(csv_file: Union[str, Path]) -> list[list[str]]:
    """
    Read a CSV file and return its contents as a list of rows.
    """
    csv_path = Path(csv_file)
    with open(csv_path, "r", newline="") as f:
        return [row for row in csv.reader(f)]


# -----------------------------
# Dict helper
# -----------------------------

def validate_key(entry: dict, key: str) -> Optional[str]:
    """
    Safely retrieve a key from a dict-like object.

    Returns:
        str(value) if key exists, else None.
    """
    return str(entry.get(key)) if key in entry else None