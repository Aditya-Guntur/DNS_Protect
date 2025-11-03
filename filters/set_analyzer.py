from collections import Counter
from typing import List

from models.suspicious_domain import SuspiciousDomain


class SetAnalyzer:
    """
    Performs set-based analysis of subdomains for cardinality patterns and
    DGA-like traits.
    """

    def __init__(self):
        self.min_unique_threshold = 10

    def analyze(self, item: SuspiciousDomain) -> SuspiciousDomain:
        subdomains: List[str] = list(item.unique_subdomains) or [q.subdomain for q in item.queries if q.subdomain]
        total = item.total_queries or len(item.queries)
        uniq = len(set(subdomains))

        # Cardinality ratio
        if total > 0:
            ratio = uniq / max(total, 1)
            if ratio > 0.8 and uniq >= self.min_unique_threshold:
                item.add_flag('set', f'high_cardinality_ratio:{ratio:.2f}')

        # Single-use subdomains proportion
        counts = Counter([q.subdomain for q in item.queries if q.subdomain])
        single_use = sum(1 for c in counts.values() if c == 1)
        if counts:
            single_ratio = single_use / len(counts)
            if single_ratio > 0.6 and single_use >= 5:
                item.add_flag('set', f'single_use_subdomains_ratio:{single_ratio:.2f}')

        # Simple DGA-ish heuristic: average label length and consonant/vowel ratio
        if subdomains:
            avg_len = sum(len(s) for s in subdomains) / len(subdomains)
            if avg_len > 20:
                item.add_flag('set', f'long_labels_avg:{avg_len:.1f}')
            vowels = set('aeiou')
            consonant_heavy = 0
            for s in subdomains:
                letters = [ch for ch in s.lower() if ch.isalpha()]
                if not letters:
                    continue
                v = sum(1 for ch in letters if ch in vowels)
                c = sum(1 for ch in letters if ch not in vowels)
                if c >= 3 * max(v, 1):
                    consonant_heavy += 1
            if subdomains and consonant_heavy / len(subdomains) > 0.5:
                item.add_flag('set', 'consonant_heavy_labels')

        # basic score
        score = 0.0
        if any('high_cardinality' in f for f in item.set_flags):
            score -= 10
        if any('single_use' in f for f in item.set_flags):
            score -= 10
        if any('long_labels' in f for f in item.set_flags):
            score -= 5
        item.scores['set'] = score
        return item
