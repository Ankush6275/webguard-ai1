import re
import urllib.parse
from datetime import datetime
import whois

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'account', 'update', 'verify', 'login',
            'bank', 'paypal', 'amazon', 'microsoft', 'google',
            'free', 'click', 'win', 'prize', 'urgent'
        ]
        
    def extract_features(self, url):
        """Extract features for ML model"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equal'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_and'] = url.count('&')
        features['num_exclamation'] = url.count('!')
        features['num_space'] = url.count(' ')
        features['num_tilde'] = url.count('~')
        features['num_comma'] = url.count(',')
        features['num_plus'] = url.count('+')
        features['num_asterisk'] = url.count('*')
        features['num_hashtag'] = url.count('#')
        features['num_dollar'] = url.count('$')
        features['num_percent'] = url.count('%')
        
        # Domain analysis
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        features['domain_length'] = len(domain)
        features['subdomain_count'] = domain.count('.') - 1
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['has_ip'] = 1 if self._is_ip_address(domain) else 0
        
        # Suspicious keyword detection
        features['suspicious_keywords'] = sum(1 for keyword in self.suspicious_keywords if keyword.lower() in url.lower())
        
        return features
    
    def _is_ip_address(self, domain):
        """Check if domain is IP address"""
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(ip_pattern.match(domain))
    
    def get_domain_info(self, url):
        """Get domain registration information"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            domain_info = whois.whois(domain)
            
            return {
                'creation_date': domain_info.creation_date,
                'expiration_date': domain_info.expiration_date,
                'registrar': domain_info.registrar,
                'age_days': self._calculate_domain_age(domain_info.creation_date)
            }
        except:
            return None
    
    def _calculate_domain_age(self, creation_date):
        """Calculate domain age in days"""
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = datetime.now() - creation_date
            return age.days
        return 0
