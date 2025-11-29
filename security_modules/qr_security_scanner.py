"""
QR Code Security Scanner
Analyzes QR codes for security threats including malicious URLs, phishing attempts, and suspicious content
"""
import requests
import re
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, List

class QRCodeSecurityScanner:
    def __init__(self):
        self.malicious_domains = [
            'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 't.co', 'short.link',
            'malware.com', 'phishing.com', 'scam.org', 'virus.net'
        ]
        self.suspicious_keywords = [
            'urgent', 'verify', 'confirm', 'account', 'suspended', 'blocked',
            'click here', 'act now', 'limited time', 'free money', 'winner',
            'congratulations', 'prize', 'lottery', 'bitcoin', 'crypto',
            'investment', 'guarantee', 'risk-free', 'download now'
        ]
        
    def analyze_qr_from_text(self, content: str) -> Dict:
        """
        Analyze QR code content from text input
        """
        try:
            if not content or not content.strip():
                return {
                    'success': False,
                    'error': 'No content provided for analysis'
                }
            
            content = content.strip()
            
            analysis = {
                'content_type': self._identify_content_type(content),
                'security_score': 0,
                'risk_level': 'Unknown',
                'warnings': [],
                'recommendations': [],
                'technical_details': {
                    'content_length': len(content),
                    'content_preview': content[:100] + '...' if len(content) > 100 else content,
                    'suspicious_patterns': [],
                    'analysis_timestamp': time.time()
                }
            }
            
            # Perform security analysis based on content type
            if analysis['content_type'] == 'URL':
                self._analyze_url_security(content, analysis)
            elif analysis['content_type'] == 'WiFi':
                self._analyze_wifi_security(content, analysis)
            elif analysis['content_type'] == 'SMS':
                self._analyze_sms_security(content, analysis)
            elif analysis['content_type'] == 'Email':
                self._analyze_email_security(content, analysis)
            elif analysis['content_type'] == 'Phone':
                self._analyze_phone_security(content, analysis)
            else:
                self._analyze_general_security(content, analysis)
            
            # Calculate overall security score and risk level
            self._calculate_security_score(analysis)
            
            return {
                'success': True,
                'analysis': analysis
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"QR content analysis failed: {str(e)}"
            }
    
    def _identify_content_type(self, content: str) -> str:
        """Identify the type of content in the QR code"""
        content_lower = content.lower().strip()
        
        # URL patterns
        if content_lower.startswith(('http://', 'https://', 'ftp://', 'www.')):
            return 'URL'
        
        # WiFi QR code pattern
        if content_lower.startswith('wifi:'):
            return 'WiFi'
        
        # SMS pattern
        if content_lower.startswith(('sms:', 'smsto:')):
            return 'SMS'
        
        # Email patterns
        if content_lower.startswith(('mailto:', 'email:')):
            return 'Email'
        
        # Phone patterns
        if content_lower.startswith(('tel:', 'phone:')):
            return 'Phone'
        
        # vCard pattern
        if content.startswith('BEGIN:VCARD'):
            return 'vCard'
        
        # Bitcoin/Crypto patterns
        if content_lower.startswith(('bitcoin:', 'ethereum:', 'btc:')):
            return 'Cryptocurrency'
        
        # Geographic coordinates
        if content_lower.startswith(('geo:', 'maps:')):
            return 'Location'
        
        # Check if it's just a URL without protocol
        url_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        if url_pattern.match(content):
            return 'URL'
        
        # Check if it looks like an email
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if email_pattern.match(content):
            return 'Email'
        
        # Check if it looks like a phone number
        phone_pattern = re.compile(r'^[\+]?[1-9]?[\d\s\-\(\)]{7,15}$')
        if phone_pattern.match(content):
            return 'Phone'
        
        return 'Text'
    
    def _analyze_url_security(self, url: str, analysis: Dict):
        """Analyze URL security"""
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            analysis['technical_details']['domain'] = domain
            analysis['technical_details']['scheme'] = parsed_url.scheme
            analysis['technical_details']['path'] = parsed_url.path
            
            # Check for HTTPS
            if parsed_url.scheme != 'https':
                analysis['warnings'].append('Non-HTTPS connection - data may not be encrypted')
                analysis['security_score'] -= 15
            
            # Check for malicious domains
            for malicious_domain in self.malicious_domains:
                if malicious_domain in domain:
                    analysis['warnings'].append(f'Known suspicious domain detected: {malicious_domain}')
                    analysis['security_score'] -= 30
                    analysis['technical_details']['suspicious_patterns'].append(f'malicious_domain:{malicious_domain}')
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'IP address instead of domain'),
                (r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.', 'Suspicious subdomain pattern'),
                (r'\d{10,}', 'Long numeric sequences'),
                (r'[a-zA-Z0-9]{20,}', 'Long random strings'),
                (r'\.tk$|\.ml$|\.ga$|\.cf$', 'Free domain service'),
                (r'bit\.ly|tinyurl|ow\.ly|goo\.gl|t\.co', 'URL shortener')
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    analysis['warnings'].append(f'Suspicious pattern: {description}')
                    analysis['security_score'] -= 10
                    analysis['technical_details']['suspicious_patterns'].append(f'pattern:{description}')
            
            # Check for suspicious keywords in URL
            for keyword in self.suspicious_keywords:
                if keyword.lower() in url.lower():
                    analysis['warnings'].append(f'Suspicious keyword detected: {keyword}')
                    analysis['security_score'] -= 5
                    analysis['technical_details']['suspicious_patterns'].append(f'keyword:{keyword}')
            
            # Try to get HTTP headers (if possible)
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                analysis['technical_details']['status_code'] = response.status_code
                analysis['technical_details']['final_url'] = response.url
                
                if response.url != url:
                    analysis['warnings'].append(f'URL redirects to: {response.url}')
                    analysis['security_score'] -= 5
                
                # Check security headers
                security_headers = ['strict-transport-security', 'x-frame-options', 'x-content-type-options']
                missing_headers = []
                for header in security_headers:
                    if header not in [h.lower() for h in response.headers.keys()]:
                        missing_headers.append(header)
                
                if missing_headers:
                    analysis['warnings'].append(f'Missing security headers: {", ".join(missing_headers)}')
                    analysis['security_score'] -= 5
                    
            except requests.RequestException:
                analysis['warnings'].append('Could not verify URL accessibility')
                analysis['security_score'] -= 10
            
            # Add recommendations
            analysis['recommendations'].extend([
                'Verify the domain is legitimate before visiting',
                'Check if HTTPS is available for secure connection',
                'Be cautious of shortened URLs',
                'Scan with antivirus before downloading anything'
            ])
            
        except Exception as e:
            analysis['warnings'].append(f'URL analysis error: {str(e)}')
    
    def _analyze_wifi_security(self, wifi_content: str, analysis: Dict):
        """Analyze WiFi QR code security"""
        try:
            # Parse WiFi QR format: WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:false;;
            wifi_params = {}
            parts = wifi_content.split(';')
            
            for part in parts:
                if ':' in part:
                    key, value = part.split(':', 1)
                    wifi_params[key.upper()] = value
            
            analysis['technical_details']['wifi_params'] = wifi_params
            
            # Check security type
            security_type = wifi_params.get('T', '').upper()
            if security_type in ['NONE', 'OPEN', '']:
                analysis['warnings'].append('Open WiFi network - no password protection')
                analysis['security_score'] -= 25
            elif security_type == 'WEP':
                analysis['warnings'].append('WEP encryption is outdated and insecure')
                analysis['security_score'] -= 20
            elif security_type in ['WPA', 'WPA2']:
                analysis['security_score'] += 10
            elif security_type == 'WPA3':
                analysis['security_score'] += 15
            
            # Check password strength
            password = wifi_params.get('P', '')
            if password:
                if len(password) < 8:
                    analysis['warnings'].append('WiFi password is too short')
                    analysis['security_score'] -= 15
                elif len(password) < 12:
                    analysis['warnings'].append('WiFi password could be stronger')
                    analysis['security_score'] -= 5
                
                # Check for common weak passwords
                weak_passwords = ['password', '123456789', 'admin', 'guest', 'default']
                if password.lower() in weak_passwords:
                    analysis['warnings'].append('WiFi uses a common weak password')
                    analysis['security_score'] -= 20
            
            # Check network name
            ssid = wifi_params.get('S', '')
            if ssid:
                # Check for suspicious network names
                suspicious_ssids = ['free', 'public', 'guest', 'open', 'wifi']
                if any(suspicious in ssid.lower() for suspicious in suspicious_ssids):
                    analysis['warnings'].append('Network name suggests public/open access')
                    analysis['security_score'] -= 10
            
            analysis['recommendations'].extend([
                'Verify the network name with the owner',
                'Ensure you trust the network provider',
                'Use VPN when connecting to shared networks',
                'Check for WPA3 security if available'
            ])
            
        except Exception as e:
            analysis['warnings'].append(f'WiFi analysis error: {str(e)}')
    
    def _analyze_sms_security(self, sms_content: str, analysis: Dict):
        """Analyze SMS QR code security"""
        try:
            # Parse SMS format: SMS:+1234567890:Message text here
            parts = sms_content.split(':', 2)
            if len(parts) >= 2:
                phone_number = parts[1] if len(parts) > 1 else ''
                message = parts[2] if len(parts) > 2 else ''
                
                analysis['technical_details']['phone_number'] = phone_number
                analysis['technical_details']['message'] = message
                
                # Check for suspicious keywords in message
                if message:
                    for keyword in self.suspicious_keywords:
                        if keyword.lower() in message.lower():
                            analysis['warnings'].append(f'Suspicious keyword in message: {keyword}')
                            analysis['security_score'] -= 10
                
                # Check for premium rate numbers
                if phone_number.startswith(('900', '+1900', '1900')):
                    analysis['warnings'].append('Premium rate number detected - charges may apply')
                    analysis['security_score'] -= 15
                
                # Check for international numbers
                if phone_number.startswith('+') and not phone_number.startswith('+1'):
                    analysis['warnings'].append('International number detected - verify legitimacy')
                    analysis['security_score'] -= 5
            
            analysis['recommendations'].extend([
                'Verify the sender identity before responding',
                'Be cautious of unexpected messages',
                'Check for premium rate charges',
                'Do not share personal information via SMS'
            ])
            
        except Exception as e:
            analysis['warnings'].append(f'SMS analysis error: {str(e)}')
    
    def _analyze_email_security(self, email_content: str, analysis: Dict):
        """Analyze email QR code security"""
        try:
            # Parse email format: mailto:user@domain.com?subject=Subject&body=Body
            if email_content.startswith('mailto:'):
                email_content = email_content[7:]  # Remove mailto:
            
            parts = email_content.split('?', 1)
            email_address = parts[0]
            params = parse_qs(parts[1]) if len(parts) > 1 else {}
            
            analysis['technical_details']['email_address'] = email_address
            analysis['technical_details']['subject'] = params.get('subject', [''])[0]
            analysis['technical_details']['body'] = params.get('body', [''])[0]
            
            # Check email domain
            if '@' in email_address:
                domain = email_address.split('@')[1]
                
                # Check for suspicious domains
                suspicious_domains = ['tempmail', '10minutemail', 'guerrillamail', 'mailinator']
                if any(suspicious in domain.lower() for suspicious in suspicious_domains):
                    analysis['warnings'].append('Temporary/disposable email service detected')
                    analysis['security_score'] -= 15
            
            # Check subject and body for suspicious content
            subject = params.get('subject', [''])[0]
            body = params.get('body', [''])[0]
            
            for keyword in self.suspicious_keywords:
                if keyword.lower() in subject.lower() or keyword.lower() in body.lower():
                    analysis['warnings'].append(f'Suspicious keyword detected: {keyword}')
                    analysis['security_score'] -= 5
            
            analysis['recommendations'].extend([
                'Verify the sender email address',
                'Check email content for phishing attempts',
                'Be cautious of unexpected email requests',
                'Do not share sensitive information via email'
            ])
            
        except Exception as e:
            analysis['warnings'].append(f'Email analysis error: {str(e)}')
    
    def _analyze_phone_security(self, phone_content: str, analysis: Dict):
        """Analyze phone number QR code security"""
        try:
            # Parse phone format: tel:+1234567890
            phone_number = phone_content.replace('tel:', '').replace('phone:', '')
            analysis['technical_details']['phone_number'] = phone_number
            
            # Check for premium rate numbers
            premium_prefixes = ['900', '976', '540']
            for prefix in premium_prefixes:
                if phone_number.replace('+1', '').startswith(prefix):
                    analysis['warnings'].append(f'Premium rate number detected (prefix: {prefix})')
                    analysis['security_score'] -= 20
            
            # Check for international numbers
            if phone_number.startswith('+') and not phone_number.startswith('+1'):
                analysis['warnings'].append('International number - verify legitimacy and charges')
                analysis['security_score'] -= 5
            
            analysis['recommendations'].extend([
                'Verify the phone number legitimacy',
                'Check for potential charges before calling',
                'Be cautious of unknown international numbers',
                'Research the number online if suspicious'
            ])
            
        except Exception as e:
            analysis['warnings'].append(f'Phone analysis error: {str(e)}')
    
    def _analyze_general_security(self, content: str, analysis: Dict):
        """Analyze general text content for security issues"""
        try:
            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                if keyword.lower() in content.lower():
                    analysis['warnings'].append(f'Suspicious keyword detected: {keyword}')
                    analysis['security_score'] -= 5
            
            # Check for potential data patterns
            patterns = [
                (r'\b\d{16}\b', 'Credit card number pattern'),
                (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN pattern'),
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
                (r'\b\d{10,11}\b', 'Phone number pattern'),
                (r'password[:\s]*\w+', 'Password disclosure'),
                (r'pin[:\s]*\d+', 'PIN disclosure')
            ]
            
            for pattern, description in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    analysis['warnings'].append(f'Sensitive data pattern detected: {description}')
                    analysis['security_score'] -= 10
                    analysis['technical_details']['suspicious_patterns'].append(f'data_pattern:{description}')
            
            analysis['recommendations'].extend([
                'Verify the source of this QR code',
                'Be cautious of sharing personal information',
                'Check for any sensitive data exposure',
                'Consider the context of where you found this code'
            ])
            
        except Exception as e:
            analysis['warnings'].append(f'General analysis error: {str(e)}')
    
    def _calculate_security_score(self, analysis: Dict):
        """Calculate overall security score and risk level"""
        score = max(0, min(100, analysis['security_score'] + 50))  # Normalize to 0-100
        analysis['security_score'] = score
        
        if score >= 80:
            analysis['risk_level'] = 'Low'
            analysis['risk_color'] = 'success'
        elif score >= 60:
            analysis['risk_level'] = 'Medium'
            analysis['risk_color'] = 'warning'
        elif score >= 40:
            analysis['risk_level'] = 'High'
            analysis['risk_color'] = 'danger'
        else:
            analysis['risk_level'] = 'Critical'
            analysis['risk_color'] = 'danger'
        
        # Add general recommendations based on risk level
        if analysis['risk_level'] in ['High', 'Critical']:
            analysis['recommendations'].insert(0, 'CAUTION: This QR code shows multiple security concerns')
        elif analysis['risk_level'] == 'Medium':
            analysis['recommendations'].insert(0, 'Exercise caution when using this QR code')
        else:
            analysis['recommendations'].insert(0, 'This QR code appears to be relatively safe')

    def get_quick_examples(self) -> List[Dict]:
        """Get quick examples for testing"""
        return [
            {
                'name': 'Legitimate HTTPS URL',
                'content': 'https://www.google.com',
                'description': 'Safe website with HTTPS'
            },
            {
                'name': 'Suspicious HTTP URL',
                'content': 'http://bit.ly/urgent-verify-account',
                'description': 'URL shortener with suspicious keywords'
            },
            {
                'name': 'Secure WiFi Network',
                'content': 'WIFI:T:WPA2;S:MySecureNetwork;P:StrongPassword123;H:false;;',
                'description': 'WPA2 protected WiFi with strong password'
            },
            {
                'name': 'Open WiFi Network',
                'content': 'WIFI:T:NONE;S:FreeWiFi;P:;H:false;;',
                'description': 'Open WiFi network (no password)'
            },
            {
                'name': 'Suspicious SMS',
                'content': 'SMS:+19001234567:Congratulations! You won $1000! Click here to claim your prize now!',
                'description': 'Premium number with suspicious message'
            },
            {
                'name': 'Safe Email Contact',
                'content': 'mailto:contact@example.com?subject=Hello',
                'description': 'Simple email contact'
            }
        ]