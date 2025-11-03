from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Set, Dict, Optional

from .dns_query import DNSQuery


@dataclass
class SuspiciousDomain:
    """
    Aggregates DNS activity and flags for a base domain detected as suspicious
    by early-stage filters. Subsequent analyzers can enrich this object with
    additional context and flags.
    """
    base_domain: str
    first_seen: datetime
    last_seen: datetime

    total_queries: int = 0
    unique_subdomains: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)

    # Flags by category (e.g., 'statistical', 'string', 'set', 'semantic')
    statistical_flags: List[str] = field(default_factory=list)
    string_flags: List[str] = field(default_factory=list)
    set_flags: List[str] = field(default_factory=list)
    semantic_flags: List[str] = field(default_factory=list)

    # Raw queries retained for downstream analysis
    queries: List[DNSQuery] = field(default_factory=list)

    # Optional scores by analyzer
    scores: Dict[str, float] = field(default_factory=dict)

    def add_query(self, query: DNSQuery) -> None:
        self.queries.append(query)
        self.total_queries += 1
        if query.subdomain:
            self.unique_subdomains.add(query.subdomain)
        self.source_ips.add(query.source_ip)
        # Maintain time bounds
        if query.timestamp < self.first_seen:
            self.first_seen = query.timestamp
        if query.timestamp > self.last_seen:
            self.last_seen = query.timestamp

    def add_flag(self, category: str, flag: str) -> None:
        category_map = {
            'statistical': self.statistical_flags,
            'string': self.string_flags,
            'set': self.set_flags,
            'semantic': self.semantic_flags,
        }
        (category_map.get(category) or self.statistical_flags).append(flag)

    @property
    def all_flags(self) -> List[str]:
        flags = []
        flags.extend(self.statistical_flags)
        flags.extend(self.string_flags)
        flags.extend(self.set_flags)
        flags.extend(self.semantic_flags)
        return flags
