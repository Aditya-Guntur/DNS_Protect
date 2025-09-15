import random
import time
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass
import queue

@dataclass
class ProxyConfig:
    """Configuration for proxy rotation"""
    http_proxies: List[str]
    https_proxies: List[str]
    rotation_interval: int = 300  # seconds

class StealthCrawler:
    """Anti-detection tools for web crawling"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        self.accept_languages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.8,es;q=0.6',
            'en-CA,en;q=0.9',
            'en-AU,en;q=0.9'
        ]
        
        self.current_proxy_index = 0
        self.proxy_config: Optional[ProxyConfig] = None
        self.request_count = 0
        self.last_request_time = 0
        
    def get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        return random.choice(self.user_agents)
    
    def get_random_accept_language(self) -> str:
        """Get a random accept language header"""
        return random.choice(self.accept_languages)
    
    def get_stealth_headers(self) -> Dict[str, str]:
        """Generate realistic HTTP headers"""
        headers = {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': self.get_random_accept_language(),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Randomly add some additional headers
        if random.random() < 0.3:
            headers['Cache-Control'] = 'no-cache'
        
        if random.random() < 0.2:
            headers['Pragma'] = 'no-cache'
        
        return headers
    
    def calculate_delay(self, base_delay: float = 1.0, jitter: float = 0.5) -> float:
        """Calculate delay with jitter to avoid detection"""
        # Add random jitter
        jitter_amount = random.uniform(-jitter, jitter)
        delay = base_delay + jitter_amount
        
        # Ensure minimum delay
        return max(0.1, delay)
    
    def respect_rate_limit(self, requests_per_minute: int = 10):
        """Enforce rate limiting"""
        current_time = time.time()
        
        if self.last_request_time > 0:
            time_since_last = current_time - self.last_request_time
            min_interval = 60.0 / requests_per_minute
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def setup_proxy_rotation(self, proxy_config: ProxyConfig):
        """Setup proxy rotation configuration"""
        self.proxy_config = proxy_config
    
    def get_current_proxy(self) -> Optional[Dict[str, str]]:
        """Get current proxy configuration"""
        if not self.proxy_config or not self.proxy_config.http_proxies:
            return None
        
        proxy_url = self.proxy_config.http_proxies[self.current_proxy_index]
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def rotate_proxy(self):
        """Rotate to next proxy"""
        if self.proxy_config and self.proxy_config.http_proxies:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_config.http_proxies)
    
    def get_random_timeout(self, base_timeout: int = 10) -> int:
        """Get randomized timeout value"""
        return base_timeout + random.randint(-2, 5)

class RequestQueue:
    """Queue system for managing crawl requests with delays"""
    
    def __init__(self, max_workers: int = 3, requests_per_minute: int = 10):
        self.queue = queue.Queue()
        self.max_workers = max_workers
        self.requests_per_minute = requests_per_minute
        self.workers = []
        self.stealth_crawler = StealthCrawler()
        self.results = {}
        self.running = False
    
    def add_request(self, url: str, callback=None, **kwargs):
        """Add a request to the queue"""
        request_data = {
            'url': url,
            'callback': callback,
            'kwargs': kwargs,
            'timestamp': time.time()
        }
        self.queue.put(request_data)
    
    def worker(self):
        """Worker thread for processing requests"""
        while self.running:
            try:
                request = self.queue.get(timeout=1)
                
                # Respect rate limiting
                self.stealth_crawler.respect_rate_limit(self.requests_per_minute)
                
                # Add random delay
                delay = self.stealth_crawler.calculate_delay()
                time.sleep(delay)
                
                # Process the request (this would be implemented by the caller)
                if request['callback']:
                    result = request['callback'](request['url'], **request['kwargs'])
                    self.results[request['url']] = result
                
                self.queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")
    
    def start(self):
        """Start the worker threads"""
        self.running = True
        for i in range(self.max_workers):
            worker_thread = threading.Thread(target=self.worker)
            worker_thread.daemon = True
            worker_thread.start()
            self.workers.append(worker_thread)
    
    def stop(self):
        """Stop the worker threads"""
        self.running = False
        
        # Wait for queue to empty
        self.queue.join()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)

def generate_realistic_referer(target_domain: str) -> str:
    """Generate a realistic referer header"""
    search_engines = [
        'https://www.google.com/search?q=',
        'https://www.bing.com/search?q=',
        'https://duckduckgo.com/?q=',
        'https://search.yahoo.com/search?p='
    ]
    
    social_media = [
        'https://www.facebook.com/',
        'https://twitter.com/',
        'https://www.linkedin.com/',
        'https://www.reddit.com/'
    ]
    
    # 60% chance of search engine referer
    if random.random() < 0.6:
        search_engine = random.choice(search_engines)
        query_terms = target_domain.split('.')[0]  # Use domain name as search term
        return f"{search_engine}{query_terms}"
    
    # 20% chance of social media referer
    elif random.random() < 0.8:
        return random.choice(social_media)
    
    # 20% chance of direct access (no referer)
    else:
        return ""

def obfuscate_crawling_pattern(base_urls: List[str], decoy_ratio: float = 0.3) -> List[str]:
    """Add decoy requests to obfuscate crawling pattern"""
    popular_sites = [
        'https://www.google.com',
        'https://www.wikipedia.org',
        'https://www.github.com',
        'https://www.stackoverflow.com',
        'https://www.reddit.com',
        'https://www.youtube.com',
        'https://www.amazon.com',
        'https://www.microsoft.com'
    ]
    
    decoy_count = int(len(base_urls) * decoy_ratio)
    decoys = random.sample(popular_sites, min(decoy_count, len(popular_sites)))
    
    # Combine and shuffle
    all_urls = base_urls + decoys
    random.shuffle(all_urls)
    
    return all_urls

def create_session_fingerprint() -> Dict[str, str]:
    """Create consistent session fingerprint for a crawling session"""
    stealth = StealthCrawler()
    
    # Pick consistent values for this session
    user_agent = stealth.get_random_user_agent()
    accept_language = stealth.get_random_accept_language()
    
    # Generate session-specific values
    screen_resolution = random.choice(['1920x1080', '1366x768', '1440x900', '1536x864'])
    timezone = random.choice(['UTC-8', 'UTC-5', 'UTC+0', 'UTC+1'])
    
    return {
        'user_agent': user_agent,
        'accept_language': accept_language,
        'screen_resolution': screen_resolution,
        'timezone': timezone
    }