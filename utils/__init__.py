"""
Utility functions for DNS analysis and web intelligence
"""

from .entropy_calc import (
    calculate_shannon_entropy,
    calculate_domain_entropy,
    entropy_analysis,
    is_high_entropy
)

from .string_operations import (
    levenshtein_distance,
    find_common_substring,
    extract_patterns,
    detect_sequential_patterns,
    compression_ratio,
    detect_encoding_patterns
)

from .stealth_tools import (
    StealthCrawler,
    RequestQueue,
    generate_realistic_referer,
    obfuscate_crawling_pattern
)

from .web_utils import WebAnalyzer

__all__ = [
    'calculate_shannon_entropy',
    'calculate_domain_entropy', 
    'entropy_analysis',
    'is_high_entropy',
    'levenshtein_distance',
    'find_common_substring',
    'extract_patterns',
    'detect_sequential_patterns',
    'compression_ratio',
    'detect_encoding_patterns',
    'StealthCrawler',
    'RequestQueue',
    'generate_realistic_referer',
    'obfuscate_crawling_pattern',
    'WebAnalyzer'
]