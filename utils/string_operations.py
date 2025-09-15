import re
import zlib
from typing import List, Tuple, Set
from difflib import SequenceMatcher

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein (edit) distance between two strings
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def find_common_substring(strings: List[str]) -> str:
    """
    Find the longest common substring among a list of strings
    """
    if not strings:
        return ""
    
    if len(strings) == 1:
        return strings[0]
    
    # Start with the first string
    common = strings[0]
    
    for string in strings[1:]:
        # Find longest common substring between current common and this string
        new_common = ""
        for i in range(len(common)):
            for j in range(i + 1, len(common) + 1):
                substr = common[i:j]
                if substr in string and len(substr) > len(new_common):
                    new_common = substr
        common = new_common
        
        if not common:
            break
    
    return common

def extract_patterns(domains: List[str]) -> dict:
    """
    Extract common patterns from a list of domains
    """
    if not domains:
        return {}
    
    patterns = {
        'common_prefix': "",
        'common_suffix': "",
        'common_substring': "",
        'numerical_patterns': [],
        'alphabetical_patterns': [],
        'length_distribution': {},
        'character_sets': set()
    }
    
    # Find common prefix
    if len(domains) > 1:
        common_prefix = domains[0]
        for domain in domains[1:]:
            common_prefix = ''.join(c1 for c1, c2 in zip(common_prefix, domain) if c1 == c2)
        patterns['common_prefix'] = common_prefix
    
    # Find common suffix
    if len(domains) > 1:
        common_suffix = domains[0][::-1]
        for domain in domains[1:]:
            common_suffix = ''.join(c1 for c1, c2 in zip(common_suffix, domain[::-1]) if c1 == c2)
        patterns['common_suffix'] = common_suffix[::-1]
    
    # Find longest common substring
    patterns['common_substring'] = find_common_substring(domains)
    
    # Analyze numerical patterns
    for domain in domains:
        numbers = re.findall(r'\d+', domain)
        patterns['numerical_patterns'].extend(numbers)
    
    # Analyze alphabetical patterns
    for domain in domains:
        alpha_only = re.sub(r'[^a-zA-Z]', '', domain)
        if alpha_only:
            patterns['alphabetical_patterns'].append(alpha_only)
    
    # Length distribution
    for domain in domains:
        length = len(domain)
        patterns['length_distribution'][length] = patterns['length_distribution'].get(length, 0) + 1
    
    # Character sets used
    for domain in domains:
        patterns['character_sets'].update(set(domain.lower()))
    
    return patterns

def detect_sequential_patterns(domains: List[str], max_edit_distance: int = 2) -> List[Tuple[str, str, int]]:
    """
    Detect sequential patterns in domain names
    Returns list of (domain1, domain2, edit_distance) for sequential patterns
    """
    sequential_pairs = []
    
    for i in range(len(domains)):
        for j in range(i + 1, len(domains)):
            distance = levenshtein_distance(domains[i], domains[j])
            if distance <= max_edit_distance:
                sequential_pairs.append((domains[i], domains[j], distance))
    
    return sequential_pairs

def compression_ratio(text: str) -> float:
    """
    Calculate compression ratio for text
    Higher compression ratio indicates more repetitive patterns
    """
    if not text:
        return 0.0
    
    original_size = len(text.encode('utf-8'))
    compressed_size = len(zlib.compress(text.encode('utf-8')))
    
    if original_size == 0:
        return 0.0
    
    return compressed_size / original_size

def analyze_compression_patterns(domains: List[str]) -> dict:
    """
    Analyze compression patterns in domain list
    """
    if not domains:
        return {}
    
    # Compress individual domains
    individual_ratios = [compression_ratio(domain) for domain in domains]
    
    # Compress the entire domain list as one string
    combined_text = '\n'.join(domains)
    combined_ratio = compression_ratio(combined_text)
    
    return {
        'individual_ratios': individual_ratios,
        'mean_individual_ratio': sum(individual_ratios) / len(individual_ratios),
        'combined_ratio': combined_ratio,
        'compression_efficiency': 1.0 - combined_ratio,  # Higher means more patterns
        'pattern_detection': combined_ratio < 0.7  # Threshold for pattern detection
    }

def detect_encoding_patterns(domain: str) -> dict:
    """
    Detect various encoding patterns in domain names
    """
    patterns = {
        'base64_like': False,
        'hex_like': False,
        'binary_like': False,
        'url_encoded': False,
        'has_numbers': False,
        'has_special_chars': False
    }
    
    # Remove dots for analysis
    clean_domain = domain.replace('.', '')
    
    # Base64-like pattern (alphanumeric + some special chars)
    if re.match(r'^[A-Za-z0-9+/=]+$', clean_domain) and len(clean_domain) % 4 == 0:
        patterns['base64_like'] = True
    
    # Hex-like pattern
    if re.match(r'^[A-Fa-f0-9]+$', clean_domain) and len(clean_domain) % 2 == 0:
        patterns['hex_like'] = True
    
    # Binary-like pattern (mostly 0s and 1s)
    if re.match(r'^[01]+$', clean_domain):
        patterns['binary_like'] = True
    
    # URL encoded patterns
    if '%' in domain:
        patterns['url_encoded'] = True
    
    # Contains numbers
    patterns['has_numbers'] = bool(re.search(r'\d', domain))
    
    # Contains special characters (non-alphanumeric, non-dot, non-dash)
    patterns['has_special_chars'] = bool(re.search(r'[^a-zA-Z0-9.\-]', domain))
    
    return patterns

def similarity_score(s1: str, s2: str) -> float:
    """
    Calculate similarity score between two strings (0-1)
    Uses SequenceMatcher for more sophisticated similarity
    """
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()

def find_similar_domains(target: str, domain_list: List[str], threshold: float = 0.8) -> List[Tuple[str, float]]:
    """
    Find domains similar to target domain
    Returns list of (domain, similarity_score) for domains above threshold
    """
    similar = []
    
    for domain in domain_list:
        score = similarity_score(target, domain)
        if score >= threshold:
            similar.append((domain, score))
    
    # Sort by similarity score (descending)
    similar.sort(key=lambda x: x[1], reverse=True)
    
    return similar