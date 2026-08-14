"""Shared pytest fixtures and configuration.

The repository does not ship a ``pyproject.toml`` yet, so the
project root is added to :data:`sys.path` at import time.  This lets
the test suite find :mod:`shredder_encryptor` without an install
step.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure ``shredder_encryptor`` is importable from the project root.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Ensure ``tools/coverage_analyze.py`` is importable as a top-level module
# for the test suite.  ``tools`` is not a Python package (no __init__.py),
# so we add the directory to ``sys.path`` instead.
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


import pytest  # noqa: E402 - import after sys.path tweak


@pytest.fixture(autouse=True)
def _isolate_default_key_dir() -> None:
    """Reset the default ``persistence`` directory around every test.

    The :mod:`shredder_encryptor.persistence` module exposes a
    ``_reset_default_directory_for_tests`` helper that drops the
    default key directory.  Calling it as a setup/teardown fixture
    keeps state from leaking between tests that touch the store.
    """

    from shredder_encryptor import persistence as persistence_mod

    persistence_mod._reset_default_directory_for_tests()
    yield
    persistence_mod._reset_default_directory_for_tests()
