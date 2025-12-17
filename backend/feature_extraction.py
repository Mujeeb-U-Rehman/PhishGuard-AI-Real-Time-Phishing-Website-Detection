"""
Feature Extraction for Phishing URL Detection
Extracts features from URLs for the ML model
"""

import re
from urllib.parse import urlparse
import whois
from datetime import datetime

def extract_features(url):
    """
    Extract features from a URL for phishing detection
    Returns a dictionary of features matching the training dataset
    
    Features based on the PhishGuard dataset:
    - URL-based features (length, special characters, etc.)
    - Domain-based features
    - Directory-based features
    - File-based features
    - Parameter-based features
    - External services features
    """
    
    features = {}
    
    try:
        # Parse the URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # 1. having_ip_address: -1 if IP address in URL, 1 otherwise
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        )
        features['having_ip_address'] = -1 if ip_pattern.search(url) else 1
        
        # 2. url_length: -1 if length >= 54, 0 if 54 > length >= 75, 1 otherwise
        url_len = len(url)
        if url_len < 54:
            features['url_length'] = 1
        elif url_len <= 75:
            features['url_length'] = 0
        else:
            features['url_length'] = -1
        
        # 3. shortining_service: -1 if using URL shortening service, 1 otherwise
        shortening_services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd']
        features['shortining_service'] = -1 if any(service in url for service in shortening_services) else 1
        
        # 4. having_at_symbol: -1 if @ in URL, 1 otherwise
        features['having_at_symbol'] = -1 if '@' in url else 1
        
        # 5. double_slash_redirecting: -1 if // appears after position 7, 1 otherwise
        double_slash_pos = url.find('//')
        features['double_slash_redirecting'] = -1 if double_slash_pos > 7 else 1
        
        # 6. prefix_suffix: -1 if - in domain, 1 otherwise
        features['prefix_suffix'] = -1 if '-' in domain else 1
        
        # 7. having_sub_domain: Count of dots in domain
        dot_count = domain.count('.')
        if dot_count == 1:
            features['having_sub_domain'] = 1
        elif dot_count == 2:
            features['having_sub_domain'] = 0
        else:
            features['having_sub_domain'] = -1
        
        # 8. sslfinal_state: Check for HTTPS
        if parsed.scheme == 'https':
            features['sslfinal_state'] = 1
        else:
            features['sslfinal_state'] = -1
        
        # 9. domain_registration_length: Try to get WHOIS info
        try:
            domain_info = whois.whois(domain)
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    expiration = domain_info.expiration_date[0]
                else:
                    expiration = domain_info.expiration_date
                
                if isinstance(domain_info.creation_date, list):
                    creation = domain_info.creation_date[0]
                else:
                    creation = domain_info.creation_date
                
                age = (expiration - creation).days
                features['domain_registration_length'] = 1 if age >= 365 else -1
            else:
                features['domain_registration_length'] = -1
        except:
            features['domain_registration_length'] = -1
        
        # 10. favicon: Simplified check (assume 1 for same domain)
        features['favicon'] = 1
        
        # 11. port: -1 if non-standard port, 1 otherwise
        features['port'] = -1 if parsed.port and parsed.port not in [80, 443] else 1
        
        # 12. https_token: -1 if "https" in domain part, 1 otherwise
        features['https_token'] = -1 if 'https' in domain else 1
        
        # 13. request_url: Simplified (assume 1 for now)
        features['request_url'] = 1
        
        # 14. url_of_anchor: Simplified (assume 1 for now)
        features['url_of_anchor'] = 1
        
        # 15. links_in_tags: Simplified (assume 1 for now)
        features['links_in_tags'] = 1
        
        # 16. sfh (Server Form Handler): Simplified
        features['sfh'] = 1
        
        # 17. submitting_to_email: -1 if mailto in URL, 1 otherwise
        features['submitting_to_email'] = -1 if 'mailto:' in url else 1
        
        # 18. abnormal_url: Simplified check
        features['abnormal_url'] = 1
        
        # 19. redirect: Count of // in URL
        redirect_count = url.count('//')
        features['redirect'] = -1 if redirect_count > 1 else 1
        
        # 20. on_mouseover: Simplified (assume 1)
        features['on_mouseover'] = 1
        
        # 21. rightclick: Simplified (assume 1)
        features['rightclick'] = 1
        
        # 22. popupwindow: Simplified (assume 1)
        features['popupwindow'] = 1
        
        # 23. iframe: Simplified (assume 1)
        features['iframe'] = 1
        
        # 24. age_of_domain: Try to get domain age
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation = domain_info.creation_date[0]
                else:
                    creation = domain_info.creation_date
                age = (datetime.now() - creation).days
                features['age_of_domain'] = 1 if age >= 180 else -1
            else:
                features['age_of_domain'] = -1
        except:
            features['age_of_domain'] = -1
        
        # 25. dnsrecord: Simplified
        features['dnsrecord'] = 1
        
        # 26. web_traffic: Simplified
        features['web_traffic'] = 1
        
        # 27. page_rank: Simplified
        features['page_rank'] = 1
        
        # 28. google_index: Simplified
        features['google_index'] = 1
        
        # 29. links_pointing_to_page: Simplified
        features['links_pointing_to_page'] = 1
        
        # 30. statistical_report: Simplified
        features['statistical_report'] = 1
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default safe values with correct feature names
        features = {
            'having_ip_address': 1,
            'url_length': 1,
            'shortining_service': 1,
            'having_at_symbol': 1,
            'double_slash_redirecting': 1,
            'prefix_suffix': 1,
            'having_sub_domain': 1,
            'sslfinal_state': 1,
            'domain_registration_length': 1,
            'favicon': 1,
            'port': 1,
            'https_token': 1,
            'request_url': 1,
            'url_of_anchor': 1,
            'links_in_tags': 1,
            'sfh': 1,
            'submitting_to_email': 1,
            'abnormal_url': 1,
            'redirect': 1,
            'on_mouseover': 1,
            'rightclick': 1,
            'popupwindow': 1,
            'iframe': 1,
            'age_of_domain': 1,
            'dnsrecord': 1,
            'web_traffic': 1,
            'page_rank': 1,
            'google_index': 1,
            'links_pointing_to_page': 1,
            'statistical_report': 1
        }
    
    return features
