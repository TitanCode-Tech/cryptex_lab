import pytest
from entropy_utils import analyze_entropy

def test_calculate_shannon_entropy():
    # A single repeating byte has 0 entropy
    result = analyze_entropy(b'A' * 100)
    assert result['shannon_entropy'] == 0.0
    # Fully random 256 bytes (0-255) has exactly 8 bits of entropy
    random_bytes = bytes(range(256))
    result2 = analyze_entropy(random_bytes)
    assert result2['shannon_entropy'] == pytest.approx(8.0)

def test_chi_square_test():
    # Uniform distribution (all 256 bytes) should have a chi-square that signifies uniform
    uniform = bytes(range(256)) * 10
    result = analyze_entropy(uniform)
    assert result['chi_square'] < 300  # Not significantly different from random

    # Non-uniform (highly structured)
    structured = b'A' * 1000 + b'B' * 10
    result2 = analyze_entropy(structured)
    assert result2['chi_square'] > 300  # Significantly different from random
