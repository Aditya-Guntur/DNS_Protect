"""
    Data models for DNS covert communication detection system
    """

from .dns_query import DNSQuery
from .suspicious_domain import SuspiciousDomain
from .website_profile import WebsiteProfile

__all__ = ['DNSQuery', 'SuspiciousDomain', 'WebsiteProfile']