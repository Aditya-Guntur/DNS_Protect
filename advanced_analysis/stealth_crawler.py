from typing import Dict

from utils.web_utils import WebAnalyzer
from models.website_profile import WebsiteProfile


class StealthCrawler:
    """
    Lightweight web presence checker that uses WebAnalyzer
    utilities with conservative timeouts. This does NOT attempt to
    evade bot detection beyond using common headers.
    """

    def __init__(self, timeout: int = 8):
        self.web = WebAnalyzer(timeout=timeout)

    def crawl(self, domain: str) -> WebsiteProfile:
        profile = WebsiteProfile(domain=domain)

        # Accessibility
        access = self.web.check_domain_accessibility(domain)
        profile.http_accessible = access.get('http_accessible', False)
        profile.https_accessible = access.get('https_accessible', False)
        profile.http_status = access.get('http_status')
        profile.https_status = access.get('https_status')
        profile.final_url = access.get('final_url')
        profile.response_time = access.get('response_time')
        if access.get('error'):
            profile.errors.append(access['error'])

        # SSL
        ssl_info = self.web.get_ssl_certificate_info(domain)
        profile.has_ssl = ssl_info.get('has_ssl', False)
        profile.valid_ssl = ssl_info.get('valid_ssl', False)
        profile.ssl_issuer = ssl_info.get('issuer')
        profile.ssl_subject = ssl_info.get('subject')
        profile.ssl_valid_from = ssl_info.get('valid_from')
        profile.ssl_valid_to = ssl_info.get('valid_to')
        profile.ssl_days_until_expiry = ssl_info.get('days_until_expiry')
        if ssl_info.get('error'):
            profile.errors.append(ssl_info['error'])

        # WHOIS
        who = self.web.get_whois_info(domain)
        profile.registrar = who.get('registrar')
        profile.creation_date = who.get('creation_date')
        profile.expiration_date = who.get('expiration_date')
        profile.updated_date = who.get('updated_date')
        profile.name_servers = who.get('name_servers') or []
        profile.status = who.get('status') or []
        profile.privacy_protected = who.get('privacy_protected', False)
        profile.age_days = who.get('age_days')
        if who.get('error'):
            profile.errors.append(who['error'])

        # DNS records
        profile.dns_records = self.web.get_dns_records(domain)

        # Page meta (only if accessible)
        url = profile.final_url or (f"https://{domain}" if profile.https_accessible else f"http://{domain}")
        if profile.http_accessible or profile.https_accessible:
            meta = self.web.extract_page_metadata(url)
            profile.title = meta.get('title')
            profile.description = meta.get('description')
            profile.keywords = meta.get('keywords')
            profile.content_length = meta.get('content_length', 0)
            profile.language = meta.get('language')
            profile.charset = meta.get('charset')
            profile.social_tags = meta.get('social_tags') or {}
            profile.links = meta.get('links') or []
            profile.images = meta.get('images') or []
            if meta.get('error'):
                profile.errors.append(meta['error'])

        # Blacklist and social presence (placeholders)
        profile.blacklist = self.web.check_blacklist_status(domain)
        profile.social_presence = self.web.find_social_media_presence(domain)

        return profile
