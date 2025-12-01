"""
URL Safety Checker
Analyzes URLs for potential security threats and safety issues
"""
import requests
import re
from urllib.parse import urlparse
from typing import Dict, List, Optional
import time

class URLSafetyChecker:
    """URL safety and security analyzer"""
    
    def __init__(self):
        self.malicious_domains = [
            'malware.com', 'phishing.com', 'scam.org', 'virus.net',
            'fake-bank.com', 'suspicious-site.net', 'malicious-download.org'
        ]
        self.suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Suspicious subdomain
            r'\d{10,}',  # Long numeric sequences
            r'[a-zA-Z0-9]{30,}',  # Very long random strings
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # Free domains
        ]
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 't.co',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        ]
        
    def analyze_url(self, url: str) -> Dict:
        """Analyze a URL for safety and security issues"""
        try:
            if not url or not url.strip():
                return {
                    'success': False,
                    'error': 'No URL provided'
                }
            
            url = url.strip()
            
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            analysis = {
                'url': url,
                'domain': domain,
                'safety_score': 100,
                'risk_level': 'Safe',
                'warnings': [],
                'recommendations': [],
                'technical_details': {
                    'scheme': parsed_url.scheme,
                    'path': parsed_url.path,
                    'query': parsed_url.query,
                    'analysis_timestamp': time.time()
                }
            }
            
            # Check for HTTPS
            if parsed_url.scheme != 'https':
                analysis['warnings'].append('⚠️ Not using HTTPS - data may not be encrypted')
                analysis['safety_score'] -= 20
                analysis['recommendations'].append('Look for HTTPS version of this site')
            
            # Check for known malicious domains
            for malicious_domain in self.malicious_domains:
                if malicious_domain in domain:
                    analysis['warnings'].append(f'🚨 Known malicious domain detected: {malicious_domain}')
                    analysis['safety_score'] -= 50
                    analysis['recommendations'].append('Avoid this website completely')
            
            # Check for URL shorteners
            for shortener in self.url_shorteners:
                if shortener in domain:
                    analysis['warnings'].append(f'🔗 URL shortener detected: {shortener}')
                    analysis['safety_score'] -= 15
                    analysis['recommendations'].append('Be cautious with shortened URLs - they can hide the real destination')
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    analysis['warnings'].append(f'🔍 Suspicious URL pattern detected')
                    analysis['safety_score'] -= 10
                    analysis['recommendations'].append('Verify this URL is legitimate before visiting')
            
            # Check domain characteristics
            if len(domain.split('.')) > 3:
                analysis['warnings'].append('🔍 Multiple subdomains detected')
                analysis['safety_score'] -= 5
            
            if any(char.isdigit() for char in domain.replace('.', '')):
                if not any(word in domain for word in ['api', 'cdn', 'static']):
                    analysis['warnings'].append('🔍 Domain contains numbers (potentially suspicious)')
                    analysis['safety_score'] -= 5
            
            # Try to get basic information about the site
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                analysis['technical_details']['status_code'] = response.status_code
                analysis['technical_details']['final_url'] = response.url
                
                if response.url != url:
                    analysis['warnings'].append(f'🔄 URL redirects to: {response.url}')
                    analysis['safety_score'] -= 5
                
                # Check for basic security headers
                security_headers = ['strict-transport-security', 'x-frame-options']
                missing_headers = []
                for header in security_headers:
                    if header not in [h.lower() for h in response.headers.keys()]:
                        missing_headers.append(header)
                
                if missing_headers:
                    analysis['warnings'].append(f'🛡️ Missing security headers: {", ".join(missing_headers)}')
                    analysis['safety_score'] -= 10
                else:
                    analysis['recommendations'].append('✅ Good security headers detected')
                    
            except requests.RequestException as e:
                analysis['warnings'].append('🌐 Could not verify website accessibility')
                analysis['technical_details']['connection_error'] = str(e)
                analysis['safety_score'] -= 15
            
            # Determine risk level
            if analysis['safety_score'] >= 80:
                analysis['risk_level'] = 'Safe'
                analysis['risk_color'] = 'success'
            elif analysis['safety_score'] >= 60:
                analysis['risk_level'] = 'Low Risk'
                analysis['risk_color'] = 'info'
            elif analysis['safety_score'] >= 40:
                analysis['risk_level'] = 'Medium Risk'
                analysis['risk_color'] = 'warning'
            elif analysis['safety_score'] >= 20:
                analysis['risk_level'] = 'High Risk'
                analysis['risk_color'] = 'danger'
            else:
                analysis['risk_level'] = 'Very High Risk'
                analysis['risk_color'] = 'danger'
            
            # Add general recommendations
            analysis['recommendations'].extend([
                'Always verify the website URL before entering sensitive information',
                'Look for HTTPS (secure) connections',
                'Be cautious of shortened URLs from unknown sources',
                'Keep your browser and antivirus software updated'
            ])
            
            return {
                'success': True,
                'analysis': analysis
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'URL analysis failed: {str(e)}'
            }
    
    def get_demo_urls(self) -> List[Dict]:
        """Get demonstration URLs for testing"""
        return [
            {
                'name': 'Safe HTTPS Site',
                'url': 'https://www.google.com',
                'description': 'Legitimate secure website'
            },
            {
                'name': 'HTTP Site (Less Secure)',
                'url': 'http://example.com',
                'description': 'Site without HTTPS encryption'
            },
            {
                'name': 'URL Shortener',
                'url': 'https://bit.ly/test-link',
                'description': 'Shortened URL (exercise caution)'
            },
            {
                'name': 'GitHub Repository',
                'url': 'https://github.com/shadow00075/Security_Suite',
                'description': 'Your own GitHub repository'
            },
            {
                'name': 'Educational Site',
                'url': 'https://www.owasp.org',
                'description': 'OWASP security foundation'
            }
        ]