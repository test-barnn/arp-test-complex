import importlib
import re
import os
from pathlib import Path
import pytest

MODULE_PATH = Path(__file__).parent / "user_manager.py"


def _read_source():
    return MODULE_PATH.read_text(encoding="utf-8")


def _extract_function_body(source: str, func_name: str) -> str:
    # Find 'def func_name(...):' and grab indented block following it
    pattern = rf"def\s+{re.escape(func_name)}\s*\([^\)]*\):\n"
    m = re.search(pattern, source)
    if not m:
        return ""
    start = m.end()
    # Capture until next top-level def or end of file
    rest = source[start:]
    # Find next def at column 0
    next_def = re.search(r"\n(?=def\s+\w+\s*\(|$)", "\n" + rest)
    if next_def:
        body = rest[: next_def.start()]
    else:
        body = rest
    return body


def test_calculate_discount_valid_and_invalid():
    # Import module fresh
    import user_manager
    importlib.reload(user_manager)

    # Valid rate within [0,1] returns expected discounted price (price * (1 - rate)).
    discounted = user_manager.calculate_discount(price=100, rate=0.2)
    assert pytest.approx(discounted, rel=1e-6) == 80.0, "Expected discounted price for rate=0.2 is 80.0"

    # Rates out of range must raise ValueError
    with pytest.raises(ValueError):
        user_manager.calculate_discount(price=100, rate=1.5)
    with pytest.raises(ValueError):
        user_manager.calculate_discount(price=100, rate=-0.1)


def test_hash_password_uses_sha256():
    import user_manager
    importlib.reload(user_manager)

    digest = user_manager.hash_password("secret_password_for_tests")
    assert isinstance(digest, str), "hash_password must return a hex string"
    # SHA-256 hex digest is 64 hex characters; MD5 would be 32
    hexstr = digest.lower()
    assert re.fullmatch(r"[0-9a-f]{64}", hexstr), (
        "hash_password must produce a 64-character sha256 hex digest; "
        f"got: {digest}"
    )


def test_source_code_security_and_quality_checks():
    source = _read_source()

    # 1) SECRET_KEY should not be hardcoded as a plain string assignment in source
    secret_key_assign = re.search(r"^\s*SECRET_KEY\s*=\s*['\"]", source, re.M)
    assert not secret_key_assign, (
        "SECRET_KEY appears to be hardcoded as a literal string in user_manager.py. "
        "It must be loaded from the environment (e.g., os.environ.get('SECRET_KEY'))."
    )
    assert "os.environ" in source or "os.getenv" in source, (
        "Module should obtain SECRET_KEY from the environment using os.environ or os.getenv."
    )

    # 2) No use of pickle.loads (unsafe deserialization). Prefer json.loads or other safe methods.
    assert "pickle.loads" not in source, "Found pickle.loads — unsafe deserialization must be removed."

    # 3) No bare except clauses
    bare_except = re.search(r"^\s*except\s*:\s*$", source, re.M)
    assert not bare_except, "Found bare except: clauses; they must be replaced with specific exceptions."

    # 4) process_data should use logging.info instead of print and no TODO comments
    assert "print(" not in source, "Found print() usage; use logging.info()/logging.debug() instead."
    assert "TODO" not in source and "ToDo" not in source, "Found TODO comment; it must be resolved/removed."
    assert "import logging" in source, "logging must be imported and used instead of print()."
    assert "logging.info(" in source or "logging.debug(" in source, (
        "process_data must use structured logging (logging.info/debug) instead of print."
    )

    # 5) SQL queries in get_user and get_all_users must not be built via string interpolation
    get_user_body = _extract_function_body(source, "get_user")
    assert get_user_body, "get_user function not found in user_manager.py"

    # Patterns that indicate unsafe SQL building inside get_user
    unsafe_patterns = [
        r"f[\'\"](?:.*SELECT|.*INSERT|.*UPDATE|.*DELETE)",
        r"\.format\(.*\)",
        r"%\s*\(.*\)",  # e.g. '...% (var)'
        r"\+\s*\w+",  # concatenation with variables
    ]
    for pat in unsafe_patterns:
        if re.search(pat, get_user_body):
            pytest.fail(
                "get_user appears to build SQL queries via string formatting/concatenation. "
                "Queries must use parameterized parameters (e.g., placeholders + parameters)."
            )

    # get_all_users should exist and not use bare except; also check it doesn't build SQL unsafely
    get_all_body = _extract_function_body(source, "get_all_users")
    assert get_all_body, "get_all_users function not found in user_manager.py"
    assert "except:" not in get_all_body, "get_all_users contains a bare except: which must be avoided."
    for pat in unsafe_patterns:
        if re.search(pat, get_all_body):
            pytest.fail(
                "get_all_users appears to build SQL queries via string formatting/concatenation. "
                "Queries must use parameterized parameters."
            )


# Ensure tests are discoverable and runnable directly
if __name__ == "__main__":
    pytest.main([__file__, "-q"])
