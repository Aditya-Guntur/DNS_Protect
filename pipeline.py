import logging
from typing import Dict, Any, List

from parsers.pcap_parser import PCAPParser
from parsers.dns_extractor import DNSExtractor
from filters.statistical_filter import StatisticalFilter
from filters.string_analyzer import StringAnalyzer
from filters.set_analyzer import SetAnalyzer
from intelligence import Intelligence
from utils.web_utils import WebAnalyzer

logger = logging.getLogger(__name__)


def run_pcap_pipeline(pcap_path: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Orchestrates: PCAP -> DNSQuery -> StatisticalFilter -> (String/Set analyzers)
    -> Web checks (optional) -> Intelligence scoring -> Report
    """
    enable_web = bool(config.get("pipeline", {}).get("enable_web_checks", False))

    # Initialize components
    extractor = DNSExtractor()
    stat_filter = StatisticalFilter()
    str_analyzer = StringAnalyzer()
    set_analyzer = SetAnalyzer()
    brain = Intelligence()
    web = WebAnalyzer() if enable_web else None

    # Apply threshold overrides if present
    thresholds = config.get("statistical_thresholds") or {}
    if thresholds:
        stat_filter.update_thresholds(thresholds)

    # 1) Parse PCAP and extract DNS queries
    queries = []
    logger.info(f"Reading PCAP: %s", pcap_path)
    with PCAPParser(pcap_path) as parser:
        for pkt in parser.parse_packets():
            queries.extend(extractor.extract_dns_from_packet(pkt))
    logger.info("Extracted %d DNS queries", len(queries))

    # 2) Run statistical filter
    suspicious_domains = stat_filter.process_dns_queries(queries)
    logger.info("Statistical filter flagged %d domains", len(suspicious_domains))

    # 3) String and Set analyzers
    for item in suspicious_domains:
        str_analyzer.analyze(item)
        set_analyzer.analyze(item)

    # 4) Prepare analysis data for Intelligence
    results: Dict[str, Dict[str, Any]] = {}
    for item in suspicious_domains:
        domain = item.base_domain
        analysis_data: Dict[str, Any] = {
            'statistical_flags': list(item.statistical_flags),
            'string_patterns': list(item.string_flags),
            'set_analysis': list(item.set_flags),
            'semantic_analysis': list(item.semantic_flags),
            'website_history': {},
        }

        # Optional web checks
        if web is not None:
            web_profile = {
                **web.check_domain_accessibility(domain),
                **{'valid_ssl': False, 'name_servers': [], 'age_days': None, 'privacy_protected': False},
                'blacklist': web.check_blacklist_status(domain),
            }
            ssl_info = web.get_ssl_certificate_info(domain)
            if ssl_info:
                web_profile['valid_ssl'] = bool(ssl_info.get('valid_ssl'))
            whois_info = web.get_whois_info(domain)
            if whois_info:
                web_profile['name_servers'] = whois_info.get('name_servers') or []
                web_profile['age_days'] = whois_info.get('age_days')
                web_profile['privacy_protected'] = bool(whois_info.get('privacy_protected'))
            # rough content length from metadata if accessible
            if web_profile.get('http_accessible') or web_profile.get('https_accessible'):
                try:
                    meta = web.extract_page_metadata((web_profile.get('final_url') or f"https://{domain}"))
                    web_profile['content_length'] = meta.get('content_length', 0)
                except Exception:
                    web_profile['content_length'] = 0
            analysis_data['web_crawl_results'] = web_profile

        results[domain] = brain.analyze_domain(domain, analysis_data)

    # 5) Final report
    report = brain.generate_report()
    report['extractor_stats'] = extractor.get_statistics()
    report['filter_stats'] = stat_filter.get_statistics()
    report['assessments'] = results
    return report
