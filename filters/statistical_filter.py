import sys
import os
from datetime import datetime, timedelta
from typing import List, Dict, Set
from collections import defaultdict, Counter

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from models.dns_query import DNSQuery
from models.suspicious_domain import SuspiciousDomain
from utils.entropy_calc import calculate_domain_entropy, calculate_subdomain_entropy

class StatisticalFilter:
    """
    First stage filter: Statistical analysis to identify potentially suspicious domains
    Creates initial suspicious domain list based on frequency, entropy, and behavioral patterns
    """
    
    def __init__(self):
        # Detection thresholds (configurable)
        self.thresholds = {
            'frequency_per_minute': 10,
            'max_subdomain_length': 20,
            'high_entropy_threshold': 4.0,
            'min_analysis_window_minutes': 5
        }
        
        # Internal tracking
        self.domain_stats = defaultdict(lambda: {
            'queries': [],
            'unique_subdomains': set(),
            'source_ips': set(),
            'query_types': Counter(),
            'first_seen': None,
            'last_seen': None
        })
        
        self.suspicious_domains = {}
        self.total_queries_processed = 0
        
    def process_dns_queries(self, queries: List[DNSQuery]) -> List[SuspiciousDomain]:
        """
        Process a batch of DNS queries and identify suspicious domains
        Returns list of domains flagged as suspicious
        """
        print(f"Processing {len(queries)} DNS queries...")
        
        # Update domain statistics
        for query in queries:
            self._update_domain_stats(query)
            self.total_queries_processed += 1
        
        # Analyze and flag suspicious domains
        newly_suspicious = self._analyze_domains()
        
        print(f"Identified {len(newly_suspicious)} suspicious domains from {len(queries)} queries")
        return newly_suspicious
    
    def _update_domain_stats(self, query: DNSQuery):
        """Update tracking statistics for a domain"""
        base_domain = query.base_domain
        stats = self.domain_stats[base_domain]
        
        # Add query to list
        stats['queries'].append(query)
        
        # Track unique subdomains
        if query.subdomain:
            stats['unique_subdomains'].add(query.subdomain)
        
        # Track source IPs
        stats['source_ips'].add(query.source_ip)
        
        # Track query types
        stats['query_types'][query.query_type] += 1
        
        # Update time bounds
        if stats['first_seen'] is None or query.timestamp < stats['first_seen']:
            stats['first_seen'] = query.timestamp
        if stats['last_seen'] is None or query.timestamp > stats['last_seen']:
            stats['last_seen'] = query.timestamp
    
    def _analyze_domains(self) -> List[SuspiciousDomain]:
        """Analyze collected domain statistics and flag suspicious ones"""
        newly_suspicious = []
        
        for base_domain, stats in self.domain_stats.items():
            # Skip if already flagged as suspicious
            if base_domain in self.suspicious_domains:
                continue
            
            # Skip if insufficient data
            if len(stats['queries']) < 2:
                continue
            
            # Perform statistical analysis
            flags = self._check_statistical_indicators(base_domain, stats)
            
            if flags:
                # Create SuspiciousDomain object
                suspicious_domain = SuspiciousDomain(
                    base_domain=base_domain,
                    first_seen=stats['first_seen'],
                    last_seen=stats['last_seen']
                )
                
                # Add all queries to the suspicious domain
                for query in stats['queries']:
                    suspicious_domain.add_query(query)
                
                # Add flags
                for flag in flags:
                    suspicious_domain.add_flag("statistical", flag)
                
                # Store and add to results
                self.suspicious_domains[base_domain] = suspicious_domain
                newly_suspicious.append(suspicious_domain)
                
                print(f"Flagged {base_domain}: {', '.join(flags)}")
        
        return newly_suspicious
    
    def _check_statistical_indicators(self, base_domain: str, stats: Dict) -> List[str]:
        """Check for statistical indicators of suspicious behavior"""
        flags = []
        
        # 1. High frequency check
        time_window = (stats['last_seen'] - stats['first_seen']).total_seconds() / 60
        if time_window > 0:
            frequency = len(stats['queries']) / time_window
            if frequency > self.thresholds['frequency_per_minute']:
                flags.append(f"high_frequency_{frequency:.1f}_per_min")
        
        # 2. Long subdomain check
        for subdomain in stats['unique_subdomains']:
            if len(subdomain) > self.thresholds['max_subdomain_length']:
                flags.append(f"long_subdomain_{len(subdomain)}_chars")
                break
        
        # 3. High entropy check
        high_entropy_count = 0
        for subdomain in stats['unique_subdomains']:
            entropy = calculate_subdomain_entropy(subdomain)
            if entropy > self.thresholds['high_entropy_threshold']:
                high_entropy_count += 1
        
        if high_entropy_count > 0:
            ratio = high_entropy_count / len(stats['unique_subdomains'])
            flags.append(f"high_entropy_{high_entropy_count}_subdomains_{ratio:.2f}_ratio")
        
        # 4. Single-use domain pattern
        single_use_count = 0
        subdomain_counts = Counter()
        for query in stats['queries']:
            if query.subdomain:
                subdomain_counts[query.subdomain] += 1
        
        for count in subdomain_counts.values():
            if count == 1:
                single_use_count += 1
        
        if single_use_count > 5:  # More than 5 single-use subdomains
            single_use_ratio = single_use_count / len(subdomain_counts)
            flags.append(f"single_use_pattern_{single_use_count}_domains_{single_use_ratio:.2f}_ratio")
        
        # 5. Unusual query type patterns
        total_queries = sum(stats['query_types'].values())
        if total_queries > 10:
            # Check for predominantly TXT queries (often used in DNS tunneling)
            txt_ratio = stats['query_types'].get('TXT', 0) / total_queries
            if txt_ratio > 0.8:
                flags.append(f"txt_heavy_{txt_ratio:.2f}_ratio")
            
            # Check for mixed query types (unusual for normal browsing)
            unique_types = len(stats['query_types'])
            if unique_types > 3:
                flags.append(f"mixed_query_types_{unique_types}_types")
        
        # 6. Rapid subdomain generation
        if len(stats['unique_subdomains']) > 20:
            if time_window > 0:
                subdomain_rate = len(stats['unique_subdomains']) / time_window
                if subdomain_rate > 2:  # More than 2 unique subdomains per minute
                    flags.append(f"rapid_subdomain_generation_{subdomain_rate:.1f}_per_min")
        
        # 7. High cardinality ratio
        if total_queries > 10:
            cardinality_ratio = len(stats['unique_subdomains']) / total_queries
            if cardinality_ratio > 0.8:
                flags.append(f"high_cardinality_{cardinality_ratio:.2f}_ratio")
        
        return flags
    
    def get_all_suspicious_domains(self) -> List[SuspiciousDomain]:
        """Get all domains currently flagged as suspicious"""
        return list(self.suspicious_domains.values())
    
    def get_statistics(self) -> Dict:
        """Get filter statistics"""
        return {
            'total_queries_processed': self.total_queries_processed,
            'unique_domains_seen': len(self.domain_stats),
            'suspicious_domains_count': len(self.suspicious_domains),
            'suspicious_domains': list(self.suspicious_domains.keys()),
            'detection_rate': len(self.suspicious_domains) / max(len(self.domain_stats), 1),
            'thresholds': self.thresholds
        }
    
    def update_thresholds(self, new_thresholds: Dict):
        """Update detection thresholds"""
        self.thresholds.update(new_thresholds)
        print(f"Updated thresholds: {self.thresholds}")
    
    def clear_old_data(self, hours: int = 24):
        """Clear domain statistics older than specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        domains_to_remove = []
        for domain, stats in self.domain_stats.items():
            if stats['last_seen'] < cutoff_time:
                domains_to_remove.append(domain)
        
        for domain in domains_to_remove:
            del self.domain_stats[domain]
            if domain in self.suspicious_domains:
                del self.suspicious_domains[domain]
        
        print(f"Cleared {len(domains_to_remove)} old domain entries")
    
    def export_suspicious_domains(self, filename: str):
        """Export suspicious domains to file"""
        with open(filename, 'w') as f:
            f.write("Domain,First_Seen,Last_Seen,Query_Count,Unique_Subdomains,Flags\n")
            
            for domain in self.suspicious_domains.values():
                flags_str = ';'.join(domain.statistical_flags)
                f.write(f"{domain.base_domain},{domain.first_seen},{domain.last_seen},"
                       f"{domain.total_queries},{len(domain.unique_subdomains)},{flags_str}\n")
        
        print(f"Exported {len(self.suspicious_domains)} suspicious domains to {filename}")

# Example usage and testing
if __name__ == "__main__":
    # Test the statistical filter
    filter_engine = StatisticalFilter()
    
    # Create some test DNS queries
    test_queries = [
        DNSQuery("normal.example.com", datetime.now(), "192.168.1.1", "A"),
        DNSQuery("test1.suspicious.com", datetime.now(), "192.168.1.2", "A"),
        DNSQuery("test2.suspicious.com", datetime.now(), "192.168.1.2", "A"),
        DNSQuery("abcdef123456.suspicious.com", datetime.now(), "192.168.1.2", "A"),
        DNSQuery("xyz789.suspicious.com", datetime.now(), "192.168.1.2", "TXT"),
    ]
    
    # Process queries
    suspicious = filter_engine.process_dns_queries(test_queries)
    
    # Print results
    print("\nFilter Statistics:")
    stats = filter_engine.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\nSuspicious Domains:")
    for domain in suspicious:
        print(f"- {domain.base_domain}: {domain.statistical_flags}")