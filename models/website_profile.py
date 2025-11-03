from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class WebsiteProfile:
    """
    Snapshot of a website/domain's externally observable properties
    produced by web crawling, SSL, WHOIS, and DNS record checks.
    """
    domain: str

    # Accessibility
    http_accessible: bool = False
    https_accessible: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    final_url: Optional[str] = None
    response_time: Optional[float] = None

    # SSL
    has_ssl: bool = False
    valid_ssl: bool = False
    ssl_issuer: Optional[Dict] = None
    ssl_subject: Optional[Dict] = None
    ssl_valid_from: Optional[datetime] = None
    ssl_valid_to: Optional[datetime] = None
    ssl_days_until_expiry: Optional[int] = None

    # WHOIS
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    privacy_protected: bool = False
    age_days: Optional[int] = None

    # DNS records
    dns_records: Dict[str, List[str]] = field(default_factory=dict)

    # Page metadata
    title: Optional[str] = None
    description: Optional[str] = None
    keywords: Optional[str] = None
    content_length: int = 0
    language: Optional[str] = None
    charset: Optional[str] = None
    social_tags: Dict[str, str] = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)

    # Blacklist and social presence (placeholders)
    blacklist: Dict[str, bool] = field(default_factory=dict)
    social_presence: Dict[str, bool] = field(default_factory=dict)

    # Errors (if any)
    errors: List[str] = field(default_factory=list)
