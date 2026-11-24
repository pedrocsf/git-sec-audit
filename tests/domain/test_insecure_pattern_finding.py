import hashlib

from domain.entities.insecure_pattern_finding import build_pattern_fingerprint


def test_fingerprint_matches_spec():
    expected = hashlib.sha256("r1\x00a.py\x00x = 1".encode()).hexdigest()
    assert build_pattern_fingerprint("r1", "a.py", "  x   =\t1 ") == expected


def test_fingerprint_ignores_whitespace_differences():
    assert build_pattern_fingerprint("r", "p", "a  b") == build_pattern_fingerprint("r", "p", " a b ")


def test_fingerprint_differs_by_inputs():
    assert build_pattern_fingerprint("r", "p", "a") != build_pattern_fingerprint("r2", "p", "a")
    assert build_pattern_fingerprint("r", "p", "a") != build_pattern_fingerprint("r", "q", "a")
