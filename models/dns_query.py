from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class DNSQuery:
    """Core DNS query data structure"""
    domain: str
    timestamp: datetime
    source_ip: str
    query_type: str
    destination_ip: Optional[str] = None
    response_code: Optional[int] = None
    
    def __post_init__(self):
        """Clean and validate data after initialization"""
        self.domain = self.domain.lower().strip()
        if not self.domain.endswith('.'):
            self.domain += '.'
    
    @property
    def subdomain(self) -> str:
        """Extract subdomain part"""
        parts = self.domain.rstrip('.').split('.')
        if len(parts) <= 2:
            return ""
        return '.'.join(parts[:-2])
    
    @property
    def base_domain(self) -> str:
        """Extract base domain (last two parts)"""
        parts = self.domain.rstrip('.').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return self.domain.rstrip('.')
    
    @property
    def tld(self) -> str:
        """Extract top-level domain"""
        parts = self.domain.rstrip('.').split('.')
        return parts[-1] if parts else ""
    
    def __str__(self) -> str:
        return f"DNSQuery({self.domain} from {self.source_ip} at {self.timestamp})"