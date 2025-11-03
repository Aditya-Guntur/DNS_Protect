import re
from typing import List

from models.suspicious_domain import SuspiciousDomain


class SemanticAnalyzer:
    """
    Very lightweight semantic analysis of domain names.
    Flags suspicious keywords, homoglyph-like patterns, and brand impersonation hints.
    """

    SUSPICIOUS_KEYWORDS = [
        'login', 'update', 'verify', 'secure', 'bank', 'account', 'reset', 'wallet',
        'support', 'invoice', 'payment', 'auth', 'signin', 'pay', 'gift', 'bonus'
    ]

    def analyze(self, item: SuspiciousDomain) -> SuspiciousDomain:
        domain = item.base_domain.lower()
        labels = [p for p in domain.split('.') if p]

        # Suspicious keywords
        for word in self.SUSPICIOUS_KEYWORDS:
            for label in labels:
                if word in label:
                    item.add_flag('semantic', f'keyword:{word}')

        # Homoglyph-like repeated confusable characters (simplified)
        if re.search(r'[il1]{3,}', domain):
            item.add_flag('semantic', 'homoglyph_like_sequence')

        # Brand impersonation heuristic: label with brand + hyphen + extra
        common_brands = ['google', 'apple', 'microsoft', 'amazon', 'facebook']
        for label in labels:
            for brand in common_brands:
                if re.match(rf'^{brand}[-_][a-z0-9]+', label):
                    item.add_flag('semantic', f'brand_impersonation:{brand}')

        # simple score
        score = 0.0
        if any('keyword:' in f for f in item.semantic_flags):
            score -= 5
        if any('brand_impersonation' in f for f in item.semantic_flags):
            score -= 15
        item.scores['semantic'] = score
        return item
