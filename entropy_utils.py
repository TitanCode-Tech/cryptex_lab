"""
entropy_utils.py
----------------
Statistical entropy analysis helpers.

Calculates Shannon entropy, byte distribution, and chi-square statistics
for identifying encrypted files, random seeds, or structured data.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Any

def _shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (0 to 8 bits)."""
    if not data:
        return 0.0
    
    length = len(data)
    counts = Counter(data)
    
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def _chi_square(data: bytes) -> float:
    """
    Calculate the chi-square statistic for uniform distribution.
    A completely random byte stream should have a flat uniform distribution.
    """
    if not data:
        return 0.0
        
    length = len(data)
    expected_count = length / 256.0
    
    counts = Counter(data)
    
    chi2 = 0.0
    for i in range(256):
        observed = counts.get(i, 0)
        chi2 += ((observed - expected_count) ** 2) / expected_count
        
    return chi2

def analyze_entropy(data: bytes) -> Dict[str, Any]:
    """
    Perform a complete entropy analysis on a given byte sequence.
    Returns statistics and a qualitative 'quality' assessment.
    """
    if not isinstance(data, bytes):
        raise TypeError("analyze_entropy requires bytes input")
        
    if not data:
        return {
            "size_bytes": 0,
            "shannon_entropy": 0.0,
            "chi_square": 0.0,
            "unique_bytes": 0,
            "quality": "EMPTY",
            "notes": ["Input is empty."],
            "byte_distribution": {}
        }

    entropy = _shannon_entropy(data)
    chi2 = _chi_square(data)
    counts = Counter(data)
    unique_bytes = len(counts)
    
    # Assess quality
    # For high-quality encryption/randomness, entropy should be very close to 8.0
    notes = []
    
    if entropy > 7.9:
        quality = "HIGH"
        notes.append("High entropy. Looks like encrypted data, compressed data, or strong randomness.")
    elif entropy > 7.5:
        quality = "MODERATE"
        notes.append("Moderate entropy. Could be encrypted data with headers, or complex machine code.")
    elif entropy > 3.0:
        quality = "LOW"
        notes.append("Low entropy. Typical of text files or lightly structured data.")
    else:
        quality = "POOR"
        notes.append("Poor entropy. Highly predictable or repetitive data.")
        
    if unique_bytes < 256:
        notes.append(f"Only {unique_bytes}/256 possible byte values are present.")

    # A chi-square test with 255 degrees of freedom has a critical value
    # around ~293 at a 5% confidence level. If the value is significantly
    # higher, it strongly suggests non-uniformity.
    if chi2 > 300:
        notes.append("Chi-square statistic indicates the byte distribution is NOT uniform.")
    else:
        notes.append("Chi-square statistic suggests a uniform byte distribution (highly random).")

    return {
        "size_bytes": len(data),
        "shannon_entropy": entropy,
        "chi_square": chi2,
        "unique_bytes": unique_bytes,
        "quality": quality,
        "notes": notes,
        "byte_distribution": dict(counts)
    }
