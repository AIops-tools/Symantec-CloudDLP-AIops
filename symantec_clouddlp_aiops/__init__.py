"""Symantec CloudDLP AIops package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("symantec-clouddlp-aiops")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
