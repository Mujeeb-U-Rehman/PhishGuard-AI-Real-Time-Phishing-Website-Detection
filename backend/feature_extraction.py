"""
Feature Extraction for Phishing URL Detection
Extracts features from URLs for the ML model
"""

import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup


def _fetch_page(url, timeout=5):
    """Fetch the HTML content of a URL."""
    try:
        response = requests.get(url, timeout=timeout, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36'
        }, allow_redirects=True)
        return response
    except requests.exceptions.SSLError:
        try:
            response = requests.get(url, timeout=timeout, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
            }, verify=False, allow_redirects=True)
            return response
        except Exception:
            return None
    except Exception:
        return None


def _get_domain(url):
    """Extract the base domain from a URL."""
    parsed = urlparse(url)
    domain = parsed.netloc
    # Remove port number if present
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain


def extract_features(url):
    """
    Extract features from a URL for phishing detection.
    Returns a dictionary of features matching the training dataset.
    Fetches the actual webpage to extract content-based features.
    """

    features = {}

    try:
        # Parse the URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        hostname = domain.split(':')[0] if ':' in domain else domain

        # Fetch the webpage for content-based feature extraction
        response = _fetch_page(url)
        soup = None
        page_text = ''
        if response is not None:
            page_text = response.text
            try:
                soup = BeautifulSoup(page_text, 'html.parser')
            except Exception:
                soup = None

        # 1. having_ip_address: -1 if IP address in URL, 1 otherwise
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])'
        )
        hex_ip = re.compile(r'0x[0-9a-fA-F]+')
        features['having_ip_address'] = (
            -1 if ip_pattern.search(url) or hex_ip.search(url) else 1
        )

        # 2. url_length: 1 if < 54, 0 if 54-75, -1 if > 75
        url_len = len(url)
        if url_len < 54:
            features['url_length'] = 1
        elif url_len <= 75:
            features['url_length'] = 0
        else:
            features['url_length'] = -1

        # 3. shortining_service: -1 if URL shortening service, 1 otherwise
        shortening_services = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
            'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im',
            'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl',
            'snipurl.com', 'short.to', 'budurl.com', 'ping.fm',
            'post.ly', 'just.as', 'bkite.com', 'snipr.com',
            'fic.kr', 'loopt.us', 'doiop.com', 'short.ie',
            'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly',
            'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly',
            'cutt.ly', 'rb.gy'
        ]
        features['shortining_service'] = (
            -1 if any(service in url.lower() for service in shortening_services)
            else 1
        )

        # 4. having_at_symbol: -1 if @ in URL, 1 otherwise
        features['having_at_symbol'] = -1 if '@' in url else 1

        # 5. double_slash_redirecting: -1 if // after protocol, 1 otherwise
        protocol_end = url.find('://') + 3 if '://' in url else 0
        features['double_slash_redirecting'] = (
            -1 if url[protocol_end:].find('//') >= 0 else 1
        )

        # 6. prefix_suffix: -1 if - in domain, 1 otherwise
        features['prefix_suffix'] = -1 if '-' in hostname else 1

        # 7. having_sub_domain: based on dot count in domain
        # Remove www. prefix for counting
        clean_domain = hostname
        if clean_domain.startswith('www.'):
            clean_domain = clean_domain[4:]
        dot_count = clean_domain.count('.')
        if dot_count <= 1:
            features['having_sub_domain'] = 1
        elif dot_count == 2:
            features['having_sub_domain'] = 0
        else:
            features['having_sub_domain'] = -1

        # 8. sslfinal_state: Check for HTTPS and SSL certificate validity
        if parsed.scheme == 'https':
            if response is not None and response.url.startswith('https'):
                features['sslfinal_state'] = 1
            else:
                features['sslfinal_state'] = 0
        else:
            features['sslfinal_state'] = -1

        # 9. domain_registration_length
        try:
            domain_info = whois.whois(hostname)
            if domain_info.expiration_date and domain_info.creation_date:
                expiration = domain_info.expiration_date
                if isinstance(expiration, list):
                    expiration = expiration[0]
                creation = domain_info.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age = (expiration - creation).days
                features['domain_registration_length'] = (
                    1 if age >= 365 else -1
                )
            else:
                features['domain_registration_length'] = -1
        except Exception:
            features['domain_registration_length'] = -1

        # 10. favicon: Check if favicon is loaded from external domain
        if soup:
            favicon_external = False
            icons = soup.find_all(
                'link', rel=lambda r: r and 'icon' in ''.join(r).lower()
            )
            for icon in icons:
                href = icon.get('href', '')
                if href.startswith('http'):
                    icon_domain = _get_domain(href)
                    if icon_domain and hostname not in icon_domain:
                        favicon_external = True
                        break
            features['favicon'] = -1 if favicon_external else 1
        else:
            features['favicon'] = -1

        # 11. port: -1 if non-standard port, 1 otherwise
        features['port'] = (
            -1 if parsed.port and parsed.port not in [80, 443] else 1
        )

        # 12. https_token: -1 if "https" appears in domain part, 1 otherwise
        features['https_token'] = -1 if 'https' in hostname.lower() else 1

        # 13. request_url: % of external objects (images, scripts, etc.)
        if soup:
            total = 0
            external = 0
            for tag in soup.find_all(['img', 'script', 'link']):
                src = tag.get('src') or tag.get('href') or ''
                if src and src.startswith('http'):
                    total += 1
                    src_domain = _get_domain(src)
                    if src_domain and hostname not in src_domain:
                        external += 1
                elif src:
                    total += 1
            if total == 0:
                features['request_url'] = 1
            else:
                ratio = external / total
                features['request_url'] = -1 if ratio >= 0.5 else 1
        else:
            features['request_url'] = -1

        # 14. url_of_anchor: % of anchors pointing to different domain
        if soup:
            anchors = soup.find_all('a')
            total_anchors = len(anchors)
            if total_anchors == 0:
                features['url_of_anchor'] = -1
            else:
                unsafe = 0
                for a in anchors:
                    href = a.get('href', '')
                    if (not href or href == '#' or
                            href.startswith('javascript') or
                            href.startswith('mailto')):
                        unsafe += 1
                    elif href.startswith('http'):
                        anchor_domain = _get_domain(href)
                        if anchor_domain and hostname not in anchor_domain:
                            unsafe += 1
                ratio = unsafe / total_anchors
                if ratio < 0.31:
                    features['url_of_anchor'] = 1
                elif ratio < 0.67:
                    features['url_of_anchor'] = 0
                else:
                    features['url_of_anchor'] = -1
        else:
            features['url_of_anchor'] = -1

        # 15. links_in_tags: % of links in <meta>, <script>, <link> tags
        if soup:
            total_tags = 0
            external_tags = 0
            for tag in soup.find_all(['meta', 'script', 'link']):
                attr = tag.get('href') or tag.get('src') or tag.get('content', '')
                if attr and attr.startswith('http'):
                    total_tags += 1
                    tag_domain = _get_domain(attr)
                    if tag_domain and hostname not in tag_domain:
                        external_tags += 1
                elif attr:
                    total_tags += 1
            if total_tags == 0:
                features['links_in_tags'] = 1
            else:
                ratio = external_tags / total_tags
                if ratio < 0.17:
                    features['links_in_tags'] = 1
                elif ratio < 0.81:
                    features['links_in_tags'] = 0
                else:
                    features['links_in_tags'] = -1
        else:
            features['links_in_tags'] = -1

        # 16. sfh (Server Form Handler): Check form actions
        if soup:
            forms = soup.find_all('form')
            if not forms:
                features['sfh'] = -1
            else:
                sfh_suspicious = False
                for form in forms:
                    action = form.get('action', '')
                    if not action or action == 'about:blank':
                        sfh_suspicious = True
                        break
                    if action.startswith('http'):
                        form_domain = _get_domain(action)
                        if form_domain and hostname not in form_domain:
                            sfh_suspicious = True
                            break
                features['sfh'] = -1 if sfh_suspicious else 1
        else:
            features['sfh'] = -1

        # 17. submitting_to_email: -1 if mailto in page, 1 otherwise
        has_mailto = 'mailto:' in url
        if soup:
            has_mailto = has_mailto or 'mailto:' in page_text.lower()
            has_mailto = has_mailto or bool(
                soup.find('input', {'type': 'email'}) and
                soup.find('form', action=re.compile(r'mailto:', re.I))
            )
        features['submitting_to_email'] = -1 if has_mailto else 1

        # 18. abnormal_url: Check if hostname is present in WHOIS identity
        try:
            domain_info = whois.whois(hostname)
            if domain_info.domain_name:
                dn = domain_info.domain_name
                if isinstance(dn, list):
                    dn = dn[0]
                features['abnormal_url'] = (
                    1 if dn.lower() in hostname.lower() else -1
                )
            else:
                features['abnormal_url'] = -1
        except Exception:
            features['abnormal_url'] = -1

        # 19. redirect: Number of redirects (0 if <=1, 1 if >=2)
        if response is not None:
            redirect_count = len(response.history)
            features['redirect'] = 1 if redirect_count >= 2 else 0
        else:
            features['redirect'] = 0

        # 20. on_mouseover: Check for onmouseover events in HTML
        if page_text:
            features['on_mouseover'] = (
                -1 if 'onmouseover' in page_text.lower() else 1
            )
        else:
            features['on_mouseover'] = 1

        # 21. rightclick: Check if right-click is disabled
        if page_text:
            page_lower = page_text.lower()
            features['rightclick'] = (
                -1 if ('event.button==2' in page_lower or
                       'event.button == 2' in page_lower or
                       'contextmenu' in page_lower)
                else 1
            )
        else:
            features['rightclick'] = 1

        # 22. popupwindow: Check for popup window code
        if page_text:
            features['popupwindow'] = (
                -1 if ('window.open' in page_text or
                       'alert(' in page_text or
                       'window.prompt' in page_text)
                else 1
            )
        else:
            features['popupwindow'] = 1

        # 23. iframe: Check for iframe usage
        if soup:
            iframes = soup.find_all('iframe')
            # Check for hidden iframes
            hidden_iframe = False
            for iframe in iframes:
                style = iframe.get('style', '')
                width = iframe.get('width', '')
                height = iframe.get('height', '')
                if ('display:none' in style.replace(' ', '') or
                        'visibility:hidden' in style.replace(' ', '') or
                        'border:0' in style.replace(' ', '') or
                        width == '0' or height == '0' or
                        'frameBorder' in str(iframe)):
                    hidden_iframe = True
                    break
            features['iframe'] = -1 if hidden_iframe else 1
        else:
            features['iframe'] = 1

        # 24. age_of_domain: domain age in days
        try:
            domain_info = whois.whois(hostname)
            if domain_info.creation_date:
                creation = domain_info.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age = (datetime.now() - creation).days
                features['age_of_domain'] = 1 if age >= 180 else -1
            else:
                features['age_of_domain'] = -1
        except Exception:
            features['age_of_domain'] = -1

        # 25. dnsrecord: Check if DNS record exists
        try:
            socket.gethostbyname(hostname)
            features['dnsrecord'] = 1
        except Exception:
            features['dnsrecord'] = -1

        # 26. web_traffic: Estimate from page content complexity
        if soup:
            links = len(soup.find_all('a'))
            scripts = len(soup.find_all('script'))
            if links > 20 and scripts > 5:
                features['web_traffic'] = 1
            elif links > 5 or scripts > 2:
                features['web_traffic'] = 0
            else:
                features['web_traffic'] = -1
        else:
            features['web_traffic'] = -1

        # 27. page_rank: Based on domain characteristics
        # Well-known TLDs and longer domains tend to have higher page rank
        well_known_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        has_known_tld = any(hostname.endswith(tld) for tld in well_known_tlds)
        features['page_rank'] = 1 if has_known_tld else -1

        # 28. google_index: Check if page has proper meta tags (proxy)
        if soup:
            meta_tags = soup.find_all('meta')
            has_description = any(
                m.get('name', '').lower() == 'description' for m in meta_tags
            )
            features['google_index'] = 1 if has_description else -1
        else:
            features['google_index'] = -1

        # 29. links_pointing_to_page: Count external links
        if soup:
            links = soup.find_all('a')
            external_links = 0
            for a in links:
                href = a.get('href', '')
                if href.startswith('http'):
                    if hostname not in _get_domain(href):
                        external_links += 1
            if external_links == 0:
                features['links_pointing_to_page'] = -1
            elif external_links <= 2:
                features['links_pointing_to_page'] = 0
            else:
                features['links_pointing_to_page'] = 1
        else:
            features['links_pointing_to_page'] = 0

        # 30. statistical_report: Check for suspicious patterns
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'login', r'signin', r'verify', r'account',
            r'update', r'secure', r'banking', r'confirm'
        ]
        url_lower = url.lower()
        suspicious_count = sum(
            1 for p in suspicious_patterns
            if re.search(p, url_lower)
        )
        features['statistical_report'] = -1 if suspicious_count >= 2 else 1

    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default values indicating a suspicious URL
        features = {
            'having_ip_address': 1,
            'url_length': -1,
            'shortining_service': 1,
            'having_at_symbol': 1,
            'double_slash_redirecting': 1,
            'prefix_suffix': -1,
            'having_sub_domain': -1,
            'sslfinal_state': -1,
            'domain_registration_length': -1,
            'favicon': -1,
            'port': 1,
            'https_token': 1,
            'request_url': -1,
            'url_of_anchor': -1,
            'links_in_tags': -1,
            'sfh': -1,
            'submitting_to_email': 1,
            'abnormal_url': -1,
            'redirect': 0,
            'on_mouseover': 1,
            'rightclick': 1,
            'popupwindow': 1,
            'iframe': 1,
            'age_of_domain': -1,
            'dnsrecord': -1,
            'web_traffic': -1,
            'page_rank': -1,
            'google_index': -1,
            'links_pointing_to_page': 0,
            'statistical_report': -1
        }

    return features
