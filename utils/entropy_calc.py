import math
from collections import Counter
from typing import List

def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy for a string
    Higher entropy indicates more randomness/unpredictability
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(text.lower())
    text_length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_domain_entropy(domain: str) -> float:
    """
    Calculate entropy specifically for domain names
    Removes dots and focuses on subdomain entropy
    """
    # Remove dots and convert to lowercase
    clean_domain = domain.replace('.', '').lower()
    return calculate_shannon_entropy(clean_domain)

def calculate_subdomain_entropy(subdomain: str) -> float:
    """
    Calculate entropy for just the subdomain part
    """
    if not subdomain:
        return 0.0
    return calculate_shannon_entropy(subdomain.lower())

def entropy_analysis(domains: List[str]) -> dict:
    """
    Analyze entropy statistics for a list of domains
    """
    if not domains:
        return {
            'count': 0,
            'mean_entropy': 0.0,
            'max_entropy': 0.0,
            'min_entropy': 0.0,
            'high_entropy_count': 0,
            'high_entropy_threshold': 4.0
        }
    
    entropies = [calculate_domain_entropy(domain) for domain in domains]
    high_entropy_threshold = 4.0
    high_entropy_count = sum(1 for e in entropies if e > high_entropy_threshold)
    
    return {
        'count': len(domains),
        'mean_entropy': sum(entropies) / len(entropies),
        'max_entropy': max(entropies),
        'min_entropy': min(entropies),
        'high_entropy_count': high_entropy_count,
        'high_entropy_threshold': high_entropy_threshold,
        'high_entropy_ratio': high_entropy_count / len(entropies)
    }

def is_high_entropy(text: str, threshold: float = 4.0) -> bool:
    """
    Check if text has high entropy (indicates randomness)
    Default threshold of 4.0 is good for detecting random strings
    """
    return calculate_shannon_entropy(text) > threshold

def entropy_score_domain(domain: str) -> dict:
    """
    Comprehensive entropy scoring for a domain
    """
    parts = domain.lower().split('.')
    
    scores = {
        'full_domain': calculate_domain_entropy(domain),
        'subdomain': 0.0,
        'base_domain': 0.0,
        'is_suspicious': False
    }
    
    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2])
        scores['subdomain'] = calculate_subdomain_entropy(subdomain)
    
    if len(parts) >= 2:
        base_domain = '.'.join(parts[-2:])
        scores['base_domain'] = calculate_shannon_entropy(base_domain.replace('.', ''))
    
    # Mark as suspicious if any component has high entropy
    scores['is_suspicious'] = (
        scores['full_domain'] > 4.0 or 
        scores['subdomain'] > 4.0
    )
    
    return scores