import inspect
import re
import hashlib
import os
import pytest

import user_manager


def _get_source():
    try:
        return inspect.getsource(user_manager)
    except OSError:
        # If the source can't be retrieved, fail the test explicitly
        pytest.fail("Could not retrieve source for user_manager module")


def test_calculate_discount_invalid_and_valid():
    # Ensure the function exists
    assert hasattr(user_manager, "calculate_discount"), "Missing calculate_discount"
    calc = getattr(user_manager, "calculate_discount")

    # Invalid rates must raise ValueError
    with pytest.raises(ValueError):
        calc(100, 1.5)
    with pytest.raises(ValueError):
        calc(100, -0.1)

    # Valid rate returns correct value (price - price * rate)
    result = calc(100, 0.2)
    assert isinstance(result, (int, float)), "calculate_discount should return a number"
    assert abs(result - 80.0) < 1e-9, f"Expected 80.0 for price=100, rate=0.2, got {result}"


def test_hash_password_uses_sha256():
    assert hasattr(user_manager, "hash_password"), "Missing hash_password"
    hp = getattr(user_manager, "hash_password")

    pw = "secret-password-for-test"
    hashed = hp(pw)
    assert isinstance(hashed, str), "hash_password must return a hex string"

    # SHA-256 hex digest length is 64 characters
    assert len(hashed) == 64, "hash_password must use SHA-256 (64 hex chars), not MD5"

    # Verify the produced hash matches hashlib.sha256
    expected = hashlib.sha256(pw.encode("utf-8")).hexdigest()
    assert hashed == expected, "hash_password must produce a SHA-256 hex digest"


def test_source_security_and_best_practices():
    src = _get_source()

    # 1) No unsafe pickle.loads
    assert "pickle.loads" not in src, "Unsafe pickle.loads found; should use json.loads or another safe deserializer"

    # 2) No weak MD5 usage
    assert "hashlib.md5" not in src and "md5(" not in src, "MD5 usage detected; must use SHA-256 or stronger"

    # 3) SECRET_KEY must not be hardcoded as a string literal in source
    hardcoded_secret_pattern = re.compile(r"^\s*SECRET_KEY\s*=\s*(['\"]).*\1", re.MULTILINE)
    assert not hardcoded_secret_pattern.search(src), "SECRET_KEY appears hardcoded; must be loaded from environment"

    # 4) SECRET_KEY should be sourced from environment (os.environ or os.getenv)
    assert ("os.environ" in src) or ("os.getenv" in src) or ("os.environ.get" in src), "SECRET_KEY should be loaded from environment"

    # 5) No bare except clauses
    # This checks for 'except:' (without exception type)
    assert "except:" not in src, "Bare except found; replace with specific exception handling"

    # 6) No print() calls; logging.info() should be used instead
    assert "print(" not in src, "print() found; use logging instead"

    # 7) No lingering TODO comments
    assert "TODO" not in src and "ToDo" not in src and "todo" not in src, "TODO comment found; resolve or remove it"

    # 8) Ensure a safe deserializer is present (expect json.loads per acceptance)
    assert "json.loads" in src or "json.load" in src, "json.loads (or json.load) not found; ensure safe deserialization instead of pickle"

    # 9) SQL queries must not use Python string formatting or f-strings.
    # Scan lines containing SQL keywords and assert they don't contain '%' formatting, .format(, or f-strings.
    sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE")
    for lineno, line in enumerate(src.splitlines(), start=1):
        if any(k in line.upper() for k in sql_keywords):
            # If the SQL appears across multiple concatenated lines, this is a best-effort scan.
            problematic_patterns = ["%", ".format(", "f\"", "f\'"]
            for p in problematic_patterns:
                if p in line:
                    pytest.fail(
                        f"Potential unsafe SQL construction on line {lineno}: contains '{p}'. Use parameterized queries instead.\nLine: {line.strip()}"
                    )


def test_get_user_sql_injection_behavior():
    # This test tries to detect a simple SQL injection vulnerability by calling get_user with
    # a malicious-looking username. A secure implementation should not return a different
    # (wider) result for that input than for a normal non-existing username.
    assert hasattr(user_manager, "get_user"), "Missing get_user function"
    get_user = getattr(user_manager, "get_user")

    # Use two unlikely usernames; one is malicious SQL injection payload
    normal_username = "nonexistent_user_12345"
    malicious_username = "admin' OR '1'='1"

    normal_result = get_user(normal_username)
    malicious_result = get_user(malicious_username)

    # For a safe implementation, both should be equivalent (typically None or empty)
    assert malicious_result == normal_result, (
        "get_user appears vulnerable to SQL injection: results differ between a normal nonexistent username"
        " and a SQL-injection-like username"
    )
