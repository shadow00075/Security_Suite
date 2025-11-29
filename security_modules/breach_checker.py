import hashlib
import requests
import time
from typing import Dict, List, Optional

class BreachChecker:
    """Password breach checker using Have I Been Pwned API and local checks"""
    
    def __init__(self):
        self.hibp_api_url = "https://api.pwnedpasswords.com/range/"
        self.common_passwords = [
            "password", "123456", "password123", "admin", "qwerty", "letmein",
            "welcome", "monkey", "1234567890", "abc123", "111111", "123123",
            "password1", "1234", "12345", "123456789", "welcome123", "admin123",
            "root", "toor", "pass", "test", "guest", "info", "adm", "mysql",
            "user", "administrator", "oracle", "ftp", "pi", "puppet", "ansible",
            "ec2-user", "vagrant", "azureuser", "demo", "test123", "default"
        ]
        
    def check_password_breach(self, password: str) -> Dict:
        """Check if password has been compromised in data breaches"""
        try:
            # First check against common passwords
            common_check = self._check_common_passwords(password)
            if common_check['is_common']:
                return {
                    'breached': True,
                    'breach_count': 'Very High (Common Password)',
                    'risk_level': 'Critical',
                    'source': 'Common Password Database',
                    'recommendations': self._get_security_recommendations('critical'),
                    'safe_to_use': False,
                    'details': common_check
                }
            
            # Check against Have I Been Pwned API
            hibp_result = self._check_hibp_api(password)
            
            # Analyze results
            risk_level = self._assess_risk_level(hibp_result['breach_count'])
            
            return {
                'breached': hibp_result['breached'],
                'breach_count': hibp_result['breach_count'],
                'risk_level': risk_level,
                'source': 'Have I Been Pwned API',
                'recommendations': self._get_security_recommendations(risk_level.lower()),
                'safe_to_use': not hibp_result['breached'] or hibp_result['breach_count'] < 10,
                'details': {
                    'hash_prefix': hibp_result.get('hash_prefix', ''),
                    'api_response_time': hibp_result.get('response_time', 0),
                    'common_password_check': common_check
                }
            }
            
        except Exception as e:
            return self._handle_error(e, password)
    
    def _check_common_passwords(self, password: str) -> Dict:
        """Check if password is in common passwords list"""
        password_lower = password.lower()
        
        # Direct match
        if password_lower in [p.lower() for p in self.common_passwords]:
            return {
                'is_common': True,
                'type': 'Direct match',
                'severity': 'Critical'
            }
        
        # Check for common patterns
        patterns = self._check_common_patterns(password_lower)
        if patterns['found']:
            return {
                'is_common': True,
                'type': 'Pattern match',
                'patterns': patterns['patterns'],
                'severity': 'High'
            }
        
        return {'is_common': False}
    
    def _check_common_patterns(self, password: str) -> Dict:
        """Check for common password patterns"""
        patterns_found = []
        
        # Sequential numbers
        if any(seq in password for seq in ['123456', '654321', '111111', '000000']):
            patterns_found.append('Sequential numbers')
        
        # Keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', 'qwertyuiop', 'asdfghjkl']
        if any(pattern in password for pattern in keyboard_patterns):
            patterns_found.append('Keyboard pattern')
        
        # Common words with numbers
        if any(word in password for word in ['password', 'admin', 'user', 'login']):
            patterns_found.append('Common word base')
        
        # Year patterns
        import re
        if re.search(r'(19|20)\d{2}', password):
            patterns_found.append('Year pattern')
        
        return {
            'found': len(patterns_found) > 0,
            'patterns': patterns_found
        }
    
    def _check_hibp_api(self, password: str) -> Dict:
        """Check password against Have I Been Pwned API"""
        try:
            start_time = time.time()
            
            # Create SHA-1 hash of password
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            hash_prefix = sha1_hash[:5]
            hash_suffix = sha1_hash[5:]
            
            # Query HIBP API with k-anonymity
            response = requests.get(
                f"{self.hibp_api_url}{hash_prefix}",
                timeout=10,
                headers={'User-Agent': 'Capstone-Security-Suite-Breach-Checker/1.0'}
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Parse response to find our hash
                for line in response.text.strip().split('\n'):
                    hash_part, count = line.split(':')
                    if hash_part == hash_suffix:
                        return {
                            'breached': True,
                            'breach_count': int(count),
                            'hash_prefix': hash_prefix,
                            'response_time': response_time
                        }
                
                # Hash not found in breaches
                return {
                    'breached': False,
                    'breach_count': 0,
                    'hash_prefix': hash_prefix,
                    'response_time': response_time
                }
            
            elif response.status_code == 404:
                # No breaches found for this prefix
                return {
                    'breached': False,
                    'breach_count': 0,
                    'hash_prefix': hash_prefix,
                    'response_time': response_time
                }
            
            else:
                raise Exception(f"HIBP API returned status code: {response.status_code}")
        
        except requests.RequestException as e:
            # Fallback to offline check only
            return {
                'breached': False,
                'breach_count': 0,
                'error': f"API unavailable: {str(e)}",
                'fallback_mode': True
            }
    
    def _assess_risk_level(self, breach_count: int) -> str:
        """Assess risk level based on breach count"""
        if breach_count == 0:
            return 'Safe'
        elif breach_count < 10:
            return 'Low'
        elif breach_count < 100:
            return 'Medium' 
        elif breach_count < 1000:
            return 'High'
        else:
            return 'Critical'
    
    def _get_security_recommendations(self, risk_level: str) -> List[str]:
        """Get security recommendations based on risk level"""
        base_recommendations = [
            "Use a unique password for each account",
            "Consider using a password manager",
            "Enable two-factor authentication where possible"
        ]
        
        if risk_level == 'critical':
            return [
                "⚠️  URGENT: Change this password immediately!",
                "This password is extremely common and appears in major data breaches",
                "Use a completely different, unique password",
                "Enable 2FA on all accounts using this password"
            ] + base_recommendations
        
        elif risk_level == 'high':
            return [
                "🔴 HIGH RISK: This password has been compromised many times",
                "Change this password as soon as possible",
                "Generate a new, unique password"
            ] + base_recommendations
        
        elif risk_level == 'medium':
            return [
                "🟡 MODERATE RISK: This password appears in some data breaches",
                "Consider changing this password",
                "Monitor accounts for suspicious activity"
            ] + base_recommendations
        
        elif risk_level == 'low':
            return [
                "🟢 LOW RISK: Password found in few breaches",
                "Consider changing if used for important accounts"
            ] + base_recommendations
        
        else:  # safe
            return [
                "✅ Good news! This password hasn't been found in known data breaches",
                "Continue following good password practices"
            ] + base_recommendations
    
    def _handle_error(self, error: Exception, password: str) -> Dict:
        """Handle errors in breach checking"""
        # Still check for common passwords as fallback
        common_check = self._check_common_passwords(password)
        
        if common_check['is_common']:
            return {
                'breached': True,
                'breach_count': 'Unknown (Common Password)',
                'risk_level': 'Critical',
                'source': 'Local Database (API Error)',
                'recommendations': self._get_security_recommendations('critical'),
                'safe_to_use': False,
                'error': str(error),
                'details': common_check
            }
        
        return {
            'breached': None,
            'breach_count': 'Unknown',
            'risk_level': 'Unknown',
            'source': 'Error',
            'recommendations': [
                "Unable to check breach status due to error",
                "Please try again or use a different password",
                "Follow general password security best practices"
            ],
            'safe_to_use': None,
            'error': str(error)
        }
    
    def get_password_security_tips(self) -> List[str]:
        """Get general password security tips"""
        return [
            "Use at least 12 characters",
            "Include uppercase and lowercase letters",
            "Include numbers and special characters",
            "Avoid dictionary words and personal information",
            "Don't reuse passwords across multiple accounts",
            "Use a reputable password manager",
            "Enable two-factor authentication",
            "Regularly update important passwords",
            "Be wary of phishing attempts",
            "Monitor your accounts for suspicious activity"
        ]
    
    def check_multiple_passwords(self, passwords: List[str]) -> Dict:
        """Check multiple passwords for breaches"""
        results = []
        summary = {
            'total_checked': len(passwords),
            'breached_count': 0,
            'safe_count': 0,
            'error_count': 0
        }
        
        for i, password in enumerate(passwords):
            result = self.check_password_breach(password)
            result['password_index'] = i + 1
            results.append(result)
            
            if result.get('breached') is True:
                summary['breached_count'] += 1
            elif result.get('breached') is False:
                summary['safe_count'] += 1
            else:
                summary['error_count'] += 1
        
        return {
            'results': results,
            'summary': summary,
            'recommendations': self._get_batch_recommendations(summary)
        }
    
    def _get_batch_recommendations(self, summary: Dict) -> List[str]:
        """Get recommendations for batch password checking"""
        recommendations = []
        
        if summary['breached_count'] > 0:
            recommendations.append(f"🔴 {summary['breached_count']} password(s) found in data breaches - change immediately!")
        
        if summary['safe_count'] > 0:
            recommendations.append(f"✅ {summary['safe_count']} password(s) appear safe from known breaches")
        
        if summary['error_count'] > 0:
            recommendations.append(f"⚠️  {summary['error_count']} password(s) could not be checked due to errors")
        
        recommendations.extend([
            "Review all flagged passwords and change as needed",
            "Consider using a password manager for all accounts",
            "Enable 2FA on all important accounts"
        ])
        
        return recommendations