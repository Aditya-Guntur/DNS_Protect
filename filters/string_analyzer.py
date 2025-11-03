from typing import List

from models.suspicious_domain import SuspiciousDomain
from utils.string_operations import (
    extract_patterns,
    detect_sequential_patterns,
    detect_encoding_patterns,
)


class StringAnalyzer:
    """
    Performs string-based analysis on a SuspiciousDomain's subdomains and base domain
    to uncover encoding patterns, templates, and sequential generation behavior.
    """

    def __init__(self, max_edit_distance: int = 2):
        self.max_edit_distance = max_edit_distance

    def analyze(self, item: SuspiciousDomain) -> SuspiciousDomain:
        domains: List[str] = [q.subdomain for q in item.queries if q.subdomain] or list(item.unique_subdomains)
        # Include base domain for encoding pattern check
        candidate_strings = domains + [item.base_domain]

        # Pattern extraction across strings
        patterns = extract_patterns(candidate_strings)
        if patterns.get('common_substring'):
            item.add_flag('string', f"common_substring:{patterns['common_substring']}")
        if patterns.get('length_distribution') and max(patterns['length_distribution'].keys(), default=0) > 30:
            item.add_flag('string', 'long_label_distribution')

        # Sequential generation pairs
        seq_pairs = detect_sequential_patterns(domains, max_edit_distance=self.max_edit_distance)
        if len(seq_pairs) >= 3:
            item.add_flag('string', f'sequential_generation_pairs:{len(seq_pairs)}')

        # Encoding-like patterns on base domain and subdomains
        enc_flags_count = 0
        for s in candidate_strings:
            enc = detect_encoding_patterns(s)
            for k, v in enc.items():
                if v:
                    enc_flags_count += 1
        if enc_flags_count >= 3:
            item.add_flag('string', 'encoding_like_patterns')

        # Optional simple score
        score = 0.0
        if any('encoding_like' in f or 'base64' in f for f in item.string_flags):
            score -= 10
        if any('sequential_generation' in f for f in item.string_flags):
            score -= 5
        item.scores['string'] = score
        return item
