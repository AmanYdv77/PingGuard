"""
Tests verifying clean, acyclic imports and absence of function-level imports.
"""

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "app"
MODULE_FILES = sorted([f.stem for f in APP_DIR.glob("*.py") if f.name != "__init__.py"])

TEST_ENV = {
    **os.environ,
    "DATABASE_URL": os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
    ),
    "TEST_DATABASE_URL": os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
    ),
    "API_KEY": "test-static-api-key-at-least-24-chars-long",
    "ENVIRONMENT": "test",
}


@pytest.mark.parametrize("module_name", MODULE_FILES)
def test_isolated_module_import_in_subprocess(module_name: str):
    """
    Verify each module in app/ can be imported in isolation in a fresh python subprocess.
    Detects circular imports regardless of import order.
    """
    cmd = [sys.executable, "-c", f"import app.{module_name}"]
    res = subprocess.run(  # noqa: S603  # test executes trusted local sys.executable subprocess
        cmd,
        capture_output=True,
        text=True,
        env=TEST_ENV,
        cwd=str(APP_DIR.parent),
    )
    assert res.returncode == 0, (
        f"Failed importing app.{module_name} in fresh process:\n{res.stderr}"
    )


def test_no_function_level_imports_in_app():
    """
    Verify that every import in app/*.py is at module top level.
    Function-level and lazy imports indicate patch-on-patch code or disguised circular dependencies.
    """
    function_imports = []
    for py_file in APP_DIR.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Import | ast.ImportFrom):
                        # Check if guarded by TYPE_CHECKING
                        function_imports.append(f"{py_file.name}:{subnode.lineno}")

    assert not function_imports, f"Found function-level imports in app/: {function_imports}"


def test_schemas_does_not_import_net():
    """Verify app.schemas never imports from app.net (layered architecture)."""
    schemas_path = APP_DIR / "schemas.py"
    tree = ast.parse(schemas_path.read_text(encoding="utf-8"), filename=str(schemas_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "app.net" not in node.module and node.module != "net", (
                f"app.schemas must not import app.net (found: from {node.module} import ...)"
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert "app.net" not in alias.name, "app.schemas must not import app.net"


def test_ssrf_module_exists():
    """Verify app/ssrf.py exists and exports is_ip_blocked."""
    from app.ssrf import is_ip_blocked

    assert callable(is_ip_blocked)


def test_enums_pure_module_exists():
    """Verify app/enums.py exists and exports MonitorStatus, MonitorMode, PingOutcome."""
    from app.enums import MonitorMode, MonitorStatus, PingOutcome

    assert issubclass(MonitorMode, str)
    assert issubclass(MonitorStatus, str)
    assert issubclass(PingOutcome, str)
