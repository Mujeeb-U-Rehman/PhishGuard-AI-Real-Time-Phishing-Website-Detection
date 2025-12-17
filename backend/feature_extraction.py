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
        
        # 1. having_IP_Address: -1 if IP address in URL, 1 otherwise
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        )
        features['having_IP_Address'] = -1 if ip_pattern.search(url) else 1
        
        # 2. URL_Length: -1 if length >= 54, 0 if 54 > length >= 75, 1 otherwise
        url_length = len(url)
        if url_length < 54:
            features['URL_Length'] = 1
        elif url_length <= 75:
            features['URL_Length'] = 0
        else:
            features['URL_Length'] = -1
        
        # 3. Shortining_Service: -1 if using URL shortening service, 1 otherwise
        shortening_services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd']
        features['Shortining_Service'] = -1 if any(service in url for service in shortening_services) else 1
        
        # 4. having_At_Symbol: -1 if @ in URL, 1 otherwise
        features['having_At_Symbol'] = -1 if '@' in url else 1
        
        # 5. double_slash_redirecting: -1 if // appears after position 7, 1 otherwise
        double_slash_pos = url.find('//')
        features['double_slash_redirecting'] = -1 if double_slash_pos > 7 else 1
        
        # 6. Prefix_Suffix: -1 if - in domain, 1 otherwise
        features['Prefix_Suffix'] = -1 if '-' in domain else 1
        
        # 7. having_Sub_Domain: Count of dots in domain
        dot_count = domain.count('.')
        if dot_count == 1:
            features['having_Sub_Domain'] = 1
        elif dot_count == 2:
            features['having_Sub_Domain'] = 0
        else:
            features['having_Sub_Domain'] = -1
        
        # 8. SSLfinal_State: Check for HTTPS
        if parsed.scheme == 'https':
            features['SSLfinal_State'] = 1
        else:
            features['SSLfinal_State'] = -1
        
        # 9. Domain_registeration_length: Try to get WHOIS info
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
                features['Domain_registeration_length'] = 1 if age >= 365 else -1
            else:
                features['Domain_registeration_length'] = -1
        except:
            features['Domain_registeration_length'] = -1
        
        # 10. Favicon: Simplified check (assume -1 for external, 1 for same domain)
        features['Favicon'] = 1
        
        # 11. port: -1 if non-standard port, 1 otherwise
        features['port'] = -1 if parsed.port and parsed.port not in [80, 443] else 1
        
        # 12. HTTPS_token: -1 if "https" in domain part, 1 otherwise
        features['HTTPS_token'] = -1 if 'https' in domain else 1
        
        # 13. Request_URL: Simplified (assume 1 for now)
        features['Request_URL'] = 1
        
        # 14. URL_of_Anchor: Simplified (assume 1 for now)
        features['URL_of_Anchor'] = 1
        
        # 15. Links_in_tags: Simplified (assume 1 for now)
        features['Links_in_tags'] = 1
        
        # 16. SFH (Server Form Handler): Simplified
        features['SFH'] = 1
        
        # 17. Submitting_to_email: -1 if mailto in URL, 1 otherwise
        features['Submitting_to_email'] = -1 if 'mailto:' in url else 1
        
        # 18. Abnormal_URL: Simplified check
        features['Abnormal_URL'] = 1
        
        # 19. Redirect: Count of // in URL
        redirect_count = url.count('//')
        features['Redirect'] = -1 if redirect_count > 1 else 1
        
        # 20. on_mouseover: Simplified (assume 1)
        features['on_mouseover'] = 1
        
        # 21. RightClick: Simplified (assume 1)
        features['RightClick'] = 1
        
        # 22. popUpWidnow: Simplified (assume 1)
        features['popUpWidnow'] = 1
        
        # 23. Iframe: Simplified (assume 1)
        features['Iframe'] = 1
        
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
        
        # 25. DNSRecord: Simplified
        features['DNSRecord'] = 1
        
        # 26. web_traffic: Simplified
        features['web_traffic'] = 1
        
        # 27. Page_Rank: Simplified
        features['Page_Rank'] = 1
        
        # 28. Google_Index: Simplified
        features['Google_Index'] = 1
        
        # 29. Links_pointing_to_page: Simplified
        features['Links_pointing_to_page'] = 1
        
        # 30. Statistical_report: Simplified
        features['Statistical_report'] = 1
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default safe values
        features = {f'feature_{i}': 1 for i in range(30)}
    
    return features
