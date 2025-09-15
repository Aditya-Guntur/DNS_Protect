import requests
import socket
import ssl
import whois
import dns.resolver
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple
import re
from datetime import datetime
import time

class WebAnalyzer:
    """Utilities for web analysis and domain verification"""
    
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        
        # Common headers for legitimate-looking requests
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def check_domain_accessibility(self, domain: str) -> Dict[str, any]:
        """Check if domain is accessible via HTTP/HTTPS"""
        result = {
            'domain': domain,
            'http_accessible': False,
            'https_accessible': False,
            'http_status': None,
            'https_status': None,
            'redirects': [],
            'final_url': None,
            'response_time': None,
            'error': None
        }
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            url = f"{protocol}://{domain}"
            
            try:
                start_time = time.time()
                response = self.session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    verify=False  # Don't verify SSL for accessibility check
                )
                response_time = time.time() - start_time
                
                if protocol == 'https':
                    result['https_accessible'] = True
                    result['https_status'] = response.status_code
                else:
                    result['http_accessible'] = True
                    result['http_status'] = response.status_code
                
                result['response_time'] = response_time
                result['final_url'] = response.url
                
                # Track redirects
                if response.history:
                    result['redirects'] = [r.url for r in response.history]
                
                break  # If one protocol works, we have accessibility
                
            except Exception as e:
                if protocol == 'https':
                    result['https_status'] = f"Error: {str(e)}"
                else:
                    result['http_status'] = f"Error: {str(e)}"
                    result['error'] = str(e)
        
        return result
    
    def get_ssl_certificate_info(self, domain: str) -> Dict[str, any]:
        """Get SSL certificate information"""
        result = {
            'has_ssl': False,
            'valid_ssl': False,
            'issuer': None,
            'subject': None,
            'valid_from': None,
            'valid_to': None,
            'days_until_expiry': None,
            'error': None
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    result['has_ssl'] = True
                    result['valid_ssl'] = True
                    
                    if cert:
                        result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        result['subject'] = dict(x[0] for x in cert.get('subject', []))
                        
                        # Parse dates
                        not_after = cert.get('notAfter')
                        if not_after:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            result['valid_to'] = expiry_date
                            result['days_until_expiry'] = (expiry_date - datetime.now()).days
                        
                        not_before = cert.get('notBefore')
                        if not_before:
                            result['valid_from'] = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_whois_info(self, domain: str) -> Dict[str, any]:
        """Get WHOIS information for domain"""
        result = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'privacy_protected': False,
            'age_days': None,
            'error': None
        }
        
        try:
            # Remove protocol if present
            clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            
            w = whois.whois(clean_domain)
            
            result['registrar'] = w.registrar
            result['creation_date'] = w.creation_date
            result['expiration_date'] = w.expiration_date
            result['updated_date'] = w.updated_date
            result['name_servers'] = w.name_servers if w.name_servers else []
            result['status'] = w.status if w.status else []
            
            # Calculate age
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                result['age_days'] = (datetime.now() - creation_date).days
            
            # Check for privacy protection (common indicators)
            privacy_indicators = [
                'privacy', 'private', 'redacted', 'whoisguard', 'proxy',
                'domains by proxy', 'perfect privacy'
            ]
            
            whois_text = str(w).lower()
            result['privacy_protected'] = any(indicator in whois_text for indicator in privacy_indicators)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get various DNS records for domain"""
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception:
                pass  # Record type not found or error
        
        return records
    
    def extract_page_metadata(self, url: str) -> Dict[str, any]:
        """Extract metadata from webpage"""
        result = {
            'title': None,
            'description': None,
            'keywords': None,
            'content_length': 0,
            'language': None,
            'charset': None,
            'social_tags': {},
            'links': [],
            'images': [],
            'error': None
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            content = response.text
            result['content_length'] = len(content)
            
            # Extract basic meta information
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                result['title'] = title_match.group(1).strip()
            
            # Extract meta tags
            meta_pattern = r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\'][^>]*>'
            meta_matches = re.findall(meta_pattern, content, re.IGNORECASE)
            
            for name, content_val in meta_matches:
                if name.lower() == 'description':
                    result['description'] = content_val
                elif name.lower() == 'keywords':
                    result['keywords'] = content_val
                elif name.lower() == 'language':
                    result['language'] = content_val
            
            # Extract links
            link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
            links = re.findall(link_pattern, content, re.IGNORECASE)
            result['links'] = [urljoin(url, link) for link in links[:50]]  # Limit to first 50
            
            # Extract images
            img_pattern = r'<img[^>]*src=["\']([^"\']+)["\'][^>]*>'
            images = re.findall(img_pattern, content, re.IGNORECASE)
            result['images'] = [urljoin(url, img) for img in images[:20]]  # Limit to first 20
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_blacklist_status(self, domain: str) -> Dict[str, bool]:
        """Check domain against known blacklists (simplified)"""
        # This is a simplified version - in practice, you'd integrate with actual blacklist APIs
        blacklist_results = {
            'google_safe_browsing': False,
            'malware_domain_list': False,
            'phishtank': False,
            'spamhaus': False
        }
        
        # Placeholder - would integrate with actual APIs:
        # - Google Safe Browsing API
        # - PhishTank API
        # - Spamhaus
        # - VirusTotal
        
        return blacklist_results
    
    def estimate_website_traffic(self, domain: str) -> Dict[str, any]:
        """Estimate website traffic and popularity (simplified)"""
        # This would integrate with services like:
        # - Alexa (discontinued)
        # - SimilarWeb API
        # - SEMrush API
        # - Ahrefs API
        
        return {
            'estimated_monthly_visits': None,
            'bounce_rate': None,
            'avg_session_duration': None,
            'pages_per_session': None,
            'traffic_sources': {},
            'error': 'Traffic estimation not implemented'
        }
    
    def find_social_media_presence(self, domain: str, company_name: str = None) -> Dict[str, bool]:
        """Look for social media presence (simplified)"""
        social_platforms = {
            'facebook': False,
            'twitter': False,
            'linkedin': False,
            'instagram': False,
            'youtube': False
        }
        
        # This would search for social media profiles
        # - Search for company name on each platform
        # - Look for verified accounts
        # - Check domain links in profiles
        
        return social_platforms
    
    def scan_for_contact_info(self, content: str) -> Dict[str, List[str]]:
        """Scan webpage content for contact information"""
        contacts = {
            'emails': [],
            'phones': [],
            'addresses': []
        }
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        contacts['emails'] = re.findall(email_pattern, content)
        
        # Phone pattern (simplified)
        phone_pattern = r'(?:\+?1[-.\s]?)?\(?[2-9][0-8][0-9]\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        contacts['phones'] = re.findall(phone_pattern, content)
        
        # Remove duplicates
        contacts['emails'] = list(set(contacts['emails']))
        contacts['phones'] = list(set(contacts['phones']))
        
        return contacts