"""
INTELLIGENCE.PY - THE BRAIN

This is the central intelligence module that coordinates all analysis components
and makes final determinations about domain legitimacy, suspiciousness, and fake website detection.

RESPONSIBILITIES:
=================

1. LEGITIMACY ASSESSMENT:
   - Combines results from all analyzers
   - Scores domains on legitimacy scale (0-100)
   - Categories: LEGITIMATE, SUSPICIOUS, LIKELY_FAKE, CONFIRMED_FAKE, UNKNOWN

2. SUSPICIOUS DOMAIN DETECTION:
   - Analyzes statistical patterns from filters
   - Identifies DNS tunneling and covert channels
   - Detects domain generation algorithms (DGA)

3. FAKE WEBSITE DETECTION:
   - Integrates web crawler results
   - Analyzes website history and registration patterns
   - Detects brand impersonation and phishing attempts
   - Verifies business legitimacy

4. DECISION MAKING:
   - Weighs evidence from multiple sources
   - Applies confidence scoring
   - Generates actionable recommendations
   - Handles conflicting signals

ANALYSIS INTEGRATION:
====================

This module receives input from:
- filters/statistical_filter.py (statistical anomalies)
- filters/string_analyzer.py (string patterns) 
- filters/set_analyzer.py (set-based analysis)
- advanced_analysis/semantic_analyzer.py (domain semantics)
- advanced_analysis/stealth_crawler.py (web presence)
- advanced_analysis/website_history.py (domain history)

OUTPUT CATEGORIES:
==================

LEGITIMATE:
- Well-established domains with clear business purpose
- Strong web presence and social media
- Valid SSL, proper registration
- Normal DNS query patterns

SUSPICIOUS: 
- Mixed signals requiring further investigation
- Some anomalous patterns but not conclusive
- New domains with limited history
- Unusual but potentially legitimate use cases

LIKELY_FAKE:
- Multiple red flags indicating deception
- Domain generation patterns
- No legitimate web presence
- Suspicious registration patterns

CONFIRMED_FAKE:
- Clear evidence of malicious intent
- Known phishing/malware domains
- Obvious brand impersonation
- Active DNS tunneling detected

UNKNOWN:
- Insufficient data for classification
- Analysis errors or failures
- Domains requiring manual review

SCORING ALGORITHM:
==================

The intelligence module will implement a weighted scoring system:

Base Score: 50 (neutral)

POSITIVE INDICATORS (+points):
- Domain age > 1 year (+15)
- Valid SSL certificate (+10)
- Active website with content (+15)
- Social media presence (+10)
- Business listings/registrations (+10)
- Normal DNS query patterns (+10)
- Established nameservers (+5)
- Contact information present (+5)

NEGATIVE INDICATORS (-points):
- High entropy in subdomains (-20)
- Excessive query frequency (-15)
- Single-use domain pattern (-15)
- No web presence (-10)
- Recent registration (-10)
- Privacy-protected WHOIS (-5)
- Suspicious query types (-10)
- Blacklist presence (-30)

CONFIDENCE SCORING:
===================

Each analysis component provides confidence levels:
- High confidence: Clear indicators present
- Medium confidence: Some indicators, mixed signals  
- Low confidence: Limited data or conflicting evidence

Final recommendations include confidence assessment.

FUTURE ENHANCEMENTS:
====================

- Machine learning integration for pattern recognition
- Threat intelligence feed integration
- Real-time blacklist checking
- Advanced semantic analysis with NLP models
- Behavioral analysis over time
- Integration with SIEM systems

"""

import sys
import os
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from enum import Enum

# Add modules to path
sys.path.append(os.path.dirname(__file__))

class LegitimacyLevel(Enum):
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious" 
    LIKELY_FAKE = "likely_fake"
    CONFIRMED_FAKE = "confirmed_fake"
    UNKNOWN = "unknown"

class Intelligence:
    """
    The central brain that processes all analysis results and makes final determinations
    """
    
    def __init__(self):
        self.analysis_results = {}
        self.final_assessments = {}

    def analyze_domain(self, domain: str, analysis_data: Dict) -> Dict:
        """
        Main analysis function - the brain processes all data and makes decisions
        
        analysis_data should contain:
        - statistical_flags: from statistical filter
        - string_patterns: from string analyzer  
        - set_analysis: from set analyzer
        - semantic_analysis: from semantic analyzer
        - web_crawl_results: from stealth crawler
        - website_history: from website history analyzer
        """
        # Calculate weighted legitimacy score based on provided analysis_data
        score = 50  # base
        positives = []
        negatives = []
        risk_factors = []

        # Extract commonly expected inputs (all optional, robust to missing)
        statistical_flags = (analysis_data.get('statistical_flags') or [])
        string_flags = (analysis_data.get('string_patterns') or [])
        set_flags = (analysis_data.get('set_analysis') or [])
        semantic_flags = (analysis_data.get('semantic_analysis') or [])
        web_profile = analysis_data.get('web_crawl_results')  # expected shape similar to WebsiteProfile dict
        website_history = analysis_data.get('website_history') or {}
        blacklist = None

        # POSITIVE INDICATORS
        # Domain age > 1 year (+15)
        age_days = None
        if web_profile and isinstance(web_profile, dict):
            age_days = web_profile.get('age_days')
            blacklist = web_profile.get('blacklist')
        elif hasattr(web_profile, 'age_days'):
            age_days = getattr(web_profile, 'age_days')
            blacklist = getattr(web_profile, 'blacklist', None)

        if isinstance(age_days, int) and age_days > 365:
            score += 15
            positives.append('domain_age>1y')

        # Valid SSL (+10)
        valid_ssl = None
        if web_profile:
            valid_ssl = web_profile.get('valid_ssl') if isinstance(web_profile, dict) else getattr(web_profile, 'valid_ssl', None)
        if valid_ssl:
            score += 10
            positives.append('valid_ssl')

        # Active website with content (+15)
        content_length = None
        if web_profile:
            content_length = web_profile.get('content_length') if isinstance(web_profile, dict) else getattr(web_profile, 'content_length', None)
        if isinstance(content_length, int) and content_length > 500:
            score += 15
            positives.append('active_site_content')

        # Social media presence (+10) — placeholder heuristic: any True
        if web_profile:
            social_presence = web_profile.get('social_presence') if isinstance(web_profile, dict) else getattr(web_profile, 'social_presence', {})
            if isinstance(social_presence, dict) and any(social_presence.values()):
                score += 10
                positives.append('social_presence')

        # Normal DNS query patterns (+10) — if no major statistical flags
        major_stat_flags = [f for f in statistical_flags if any(k in f for k in ['high_frequency', 'high_entropy', 'single_use', 'txt_heavy', 'rapid_subdomain', 'high_cardinality'])]
        if not major_stat_flags:
            score += 10
            positives.append('normal_dns_patterns')

        # Established nameservers (+5)
        if web_profile:
            ns = web_profile.get('name_servers') if isinstance(web_profile, dict) else getattr(web_profile, 'name_servers', [])
            if ns and len(ns) >= 2:
                score += 5
                positives.append('established_ns')

        # Contact information present (+5) — heuristic via page content length and links
        if isinstance(content_length, int) and content_length > 1000:
            score += 5
            positives.append('contact_info_signals')

        # NEGATIVE INDICATORS
        # High entropy in subdomains (-20)
        if any('high_entropy' in f for f in statistical_flags):
            score -= 20
            negatives.append('high_entropy_subdomains')

        # Excessive query frequency (-15)
        if any('high_frequency' in f for f in statistical_flags):
            score -= 15
            negatives.append('excessive_query_frequency')

        # Single-use domain pattern (-15)
        if any('single_use_pattern' in f or 'single_use_subdomains' in f for f in (statistical_flags + list(set_flags))):
            score -= 15
            negatives.append('single_use_pattern')

        # No web presence (-10)
        if web_profile:
            http_ok = web_profile.get('http_accessible') if isinstance(web_profile, dict) else getattr(web_profile, 'http_accessible', False)
            https_ok = web_profile.get('https_accessible') if isinstance(web_profile, dict) else getattr(web_profile, 'https_accessible', False)
            if not http_ok and not https_ok:
                score -= 10
                negatives.append('no_web_presence')

        # Recent registration (-10)
        if isinstance(age_days, int) and age_days < 90:
            score -= 10
            negatives.append('recent_registration')

        # Privacy-protected WHOIS (-5)
        if web_profile:
            privacy = web_profile.get('privacy_protected') if isinstance(web_profile, dict) else getattr(web_profile, 'privacy_protected', False)
            if privacy:
                score -= 5
                negatives.append('privacy_protected')

        # Suspicious query types (-10)
        if any('txt_heavy' in f for f in statistical_flags):
            score -= 10
            negatives.append('suspicious_query_types')

        # Blacklist presence (-30)
        blacklisted = False
        if isinstance(blacklist, dict) and any(blacklist.values()):
            blacklisted = True
            score -= 30
            negatives.append('blacklisted')

        # Additional risk factors from other analyzers
        for fl in list(string_flags) + list(set_flags) + list(semantic_flags):
            if isinstance(fl, str):
                risk_factors.append(fl)

        # Confidence scoring based on number of sources available
        sources = 0
        if statistical_flags: sources += 1
        if string_flags: sources += 1
        if set_flags: sources += 1
        if semantic_flags: sources += 1
        if web_profile: sources += 1
        if website_history: sources += 1
        confidence = min(1.0, 0.2 + 0.15 * sources)  # 0.2 base + 0.15 per source up to 1.0

        # Determine legitimacy level
        level = LegitimacyLevel.UNKNOWN
        recommendation = 'INVESTIGATE'

        # Hard override for confirmed fake
        if blacklisted or (any('txt_heavy' in f for f in statistical_flags) and any('high_entropy' in f for f in statistical_flags)):
            level = LegitimacyLevel.CONFIRMED_FAKE
            recommendation = 'BLOCK'
        else:
            if score >= 75:
                level = LegitimacyLevel.LEGITIMATE
                recommendation = 'ALLOW'
            elif score >= 60:
                level = LegitimacyLevel.SUSPICIOUS
                recommendation = 'MONITOR'
            elif score >= 40:
                level = LegitimacyLevel.LIKELY_FAKE
                recommendation = 'INVESTIGATE'
            else:
                level = LegitimacyLevel.CONFIRMED_FAKE
                recommendation = 'BLOCK'

        assessment = {
            'domain': domain,
            'timestamp': datetime.now(),
            'legitimacy_level': level,
            'legitimacy_score': max(0, min(100, int(score))),  # clamp to 0-100
            'confidence': round(confidence, 2),  # 0-1 scale
            'evidence': {
                'positive_indicators': positives,
                'negative_indicators': negatives,
                'risk_factors': risk_factors
            },
            'recommendation': recommendation,
            'detailed_analysis': analysis_data
        }
        # Save to final assessments
        self.final_assessments[domain] = assessment
        return assessment

    def bulk_analyze(self, domains_data: Dict[str, Dict]) -> Dict[str, Dict]:
        """
        Analyze multiple domains in batch
        """
        results = {}
        for domain, data in domains_data.items():
            results[domain] = self.analyze_domain(domain, data)
        return results

    def get_high_risk_domains(self) -> List[str]:
        """
        Return domains classified as high risk
        """
        high_risk = []
        for domain, assessment in self.final_assessments.items():
            if assessment['legitimacy_level'] in [LegitimacyLevel.LIKELY_FAKE, LegitimacyLevel.CONFIRMED_FAKE]:
                high_risk.append(domain)
        return high_risk

    def generate_report(self) -> Dict:
        """
        Generate comprehensive analysis report
        """
        return {
            'total_domains_analyzed': len(self.final_assessments),
            'legitimacy_breakdown': self._get_legitimacy_breakdown(),
            'high_risk_domains': self.get_high_risk_domains(),
            'recommendations': self._generate_recommendations()
        }

    def _get_legitimacy_breakdown(self) -> Dict[str, int]:
        """Get count breakdown by legitimacy level"""
        breakdown = {level.value: 0 for level in LegitimacyLevel}
        for assessment in self.final_assessments.values():
            level = assessment['legitimacy_level'].value
            breakdown[level] += 1
        return breakdown

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations: List[str] = []

        breakdown = self._get_legitimacy_breakdown()
        high_risk = self.get_high_risk_domains()

        if high_risk:
            recommendations.append(f"Block or sinkhole {len(high_risk)} high-risk domains")

        # Identify common negative indicators to suggest threshold tuning
        flag_counter: Dict[str, int] = {}
        for ass in self.final_assessments.values():
            for neg in ass['evidence'].get('negative_indicators', []):
                flag_counter[neg] = flag_counter.get(neg, 0) + 1

        if flag_counter.get('high_entropy_subdomains', 0) >= 3:
            recommendations.append('Tighten high-entropy thresholds or enable deeper inspection')
        if flag_counter.get('excessive_query_frequency', 0) >= 3:
            recommendations.append('Rate-limit or investigate sources with high DNS query rates')
        if flag_counter.get('single_use_pattern', 0) >= 3:
            recommendations.append('Inspect potential DNS tunneling with many single-use subdomains')

        # General monitoring advice
        if breakdown.get(LegitimacyLevel.SUSPICIOUS.value, 0) > 0:
            recommendations.append('Enable monitoring for suspicious domains and collect more telemetry')

        return recommendations