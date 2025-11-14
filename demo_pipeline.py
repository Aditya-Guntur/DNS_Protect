from datetime import datetime

from intelligence import Intelligence


def main():
    brain = Intelligence()

    # Construct sample analysis data for a few domains
    domains_data = {
        'example.com': {
            'statistical_flags': [],
            'string_patterns': [],
            'set_analysis': [],
            'semantic_analysis': [],
            'web_crawl_results': {
                'http_accessible': True,
                'https_accessible': True,
                'valid_ssl': True,
                'content_length': 2500,
                'name_servers': ['ns1.example.com', 'ns2.example.com'],
                'age_days': 2000,
                'privacy_protected': False,
                'blacklist': {
                    'google_safe_browsing': False,
                    'malware_domain_list': False,
                    'phishtank': False,
                    'spamhaus': False
                },
                'social_presence': {
                    'twitter': True
                }
            },
            'website_history': {}
        },
        'suspicious-tunnel.net': {
            'statistical_flags': [
                'high_entropy_10_subdomains_0.85_ratio',
                'txt_heavy_0.90_ratio',
                'rapid_subdomain_generation_3.2_per_min'
            ],
            'string_patterns': ['encoding_like_patterns', 'sequential_generation_pairs:5'],
            'set_analysis': ['high_cardinality_ratio:0.92', 'single_use_subdomains_ratio:0.75'],
            'semantic_analysis': ['keyword:verify'],
            'web_crawl_results': {
                'http_accessible': False,
                'https_accessible': False,
                'valid_ssl': False,
                'content_length': 0,
                'age_days': 10,
                'privacy_protected': True,
                'blacklist': {
                    'google_safe_browsing': False,
                    'malware_domain_list': True,
                },
                'social_presence': {}
            },
            'website_history': {}
        },
        'newco.io': {
            'statistical_flags': ['mixed_query_types_4_types'],
            'string_patterns': [],
            'set_analysis': [],
            'semantic_analysis': [],
            'web_crawl_results': {
                'http_accessible': True,
                'https_accessible': True,
                'valid_ssl': True,
                'content_length': 700,
                'age_days': 45,
                'privacy_protected': True,
                'blacklist': {},
                'social_presence': {}
            },
            'website_history': {}
        }
    }

    results = brain.bulk_analyze(domains_data)

    print('Results:')
    for d, r in results.items():
        print(f"- {d}: level={r['legitimacy_level'].value}, score={r['legitimacy_score']}, conf={r['confidence']}")

    report = brain.generate_report()
    print('\nReport:')
    for k, v in report.items():
        print(f"{k}: {v}")


if __name__ == '__main__':
    main()
