"""
Web Security Headers Checker
Analyzes HTTP security headers for web applications
"""
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
import re

class SecurityHeadersChecker:
    """Web security headers analyzer"""
    
    def __init__(self):
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'importance': 'high',
                'recommendation': 'max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and data injection attacks',
                'importance': 'high',
                'recommendation': "default-src 'self'; script-src 'self'"
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'importance': 'medium',
                'recommendation': 'DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'importance': 'medium',
                'recommendation': 'nosniff'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'importance': 'medium',
                'recommendation': 'strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser feature permissions',
                'importance': 'medium',
                'recommendation': 'geolocation=(), microphone=(), camera=()'
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS protection (deprecated)',
                'importance': 'low',
                'recommendation': '1; mode=block'
            }
        }
        
        self.dangerous_headers = {
            'Server': 'Reveals server information',
            'X-Powered-By': 'Reveals technology stack',
            'X-AspNet-Version': 'Reveals ASP.NET version',
            'X-AspNetMvc-Version': 'Reveals ASP.NET MVC version'
        }
    
    def analyze_headers(self, target_url: str) -> Dict:
        """Analyze security headers for a given URL"""
        try:
            # Ensure URL has protocol
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            
            # Make request with custom headers
            headers = {
                'User-Agent': 'Security-Headers-Checker/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
            
            # Analyze headers and format for frontend
            headers_analysis = self._analyze_security_headers_detailed(response.headers)
            missing_headers = self._find_missing_headers(response.headers)
            information_disclosure = self._check_information_disclosure(response.headers)
            cookie_security = self._analyze_cookies(response.cookies)
            
            results = {
                'url': target_url,
                'status_code': response.status_code,
                'headers_analysis': headers_analysis,
                'missing_headers': missing_headers,
                'information_disclosure': information_disclosure,
                'cookie_security': cookie_security,
                'security_score': 0,
                'grade': 'F',
                'recommendations': [],
                'summary': {
                    'secure_headers': 0,
                    'insecure_headers': 0,
                    'missing_headers': len(missing_headers)
                }
            }
            
            # Calculate security score and summary
            score, summary = self._calculate_security_score_and_summary(headers_analysis, missing_headers, information_disclosure)
            results['security_score'] = score
            results['grade'] = self._calculate_grade(score)
            results['summary'] = summary
            
            # Generate recommendations
            recommendations = self._generate_recommendations(results)
            results['recommendations'] = recommendations
            
            return results
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Headers analysis failed: {str(e)}",
                'results': {}
            }
    
    def _analyze_security_headers_detailed(self, headers: dict) -> Dict:
        """Analyze present security headers with detailed frontend-compatible format"""
        analysis = {}
        
        for header_name, header_info in self.security_headers.items():
            header_value = headers.get(header_name)
            
            if header_value:
                assessment = self._assess_header_value(header_name, header_value)
                analysis[header_name] = {
                    'present': True,
                    'secure': assessment == 'good',
                    'value': header_value,
                    'description': header_info['description'],
                    'recommendation': header_info['recommendation'] if assessment != 'good' else 'Header is properly configured',
                    'assessment': assessment
                }
            else:
                analysis[header_name] = {
                    'present': False,
                    'secure': False,
                    'value': None,
                    'description': header_info['description'],
                    'recommendation': f"Add header: {header_name}: {header_info['recommendation']}",
                    'assessment': 'missing'
                }
        
        return analysis
    
    def _calculate_security_score_and_summary(self, headers_analysis: Dict, missing_headers: List, disclosures: List) -> tuple:
        """Calculate overall security score and summary statistics"""
        score = 100
        secure_headers = 0
        insecure_headers = 0
        
        # Analyze each header
        for header_name, header_data in headers_analysis.items():
            if header_data['present']:
                if header_data['secure']:
                    secure_headers += 1
                else:
                    insecure_headers += 1
                    # Deduct for insecure headers
                    importance = self.security_headers.get(header_name, {}).get('importance', 'low')
                    if importance == 'high':
                        score -= 15
                    elif importance == 'medium':
                        score -= 10
                    else:
                        score -= 5
            else:
                # Deduct for missing headers
                importance = self.security_headers.get(header_name, {}).get('importance', 'low')
                if importance == 'high':
                    score -= 20
                elif importance == 'medium':
                    score -= 10
                else:
                    score -= 5
        
        # Deduct for information disclosure
        score -= len(disclosures) * 5
        
        summary = {
            'secure_headers': secure_headers,
            'insecure_headers': insecure_headers,
            'missing_headers': len(missing_headers)
        }
        
        return max(0, min(100, score)), summary
    
    def _assess_header_value(self, header_name: str, header_value: str) -> str:
        """Assess the quality of a security header value"""
        header_lower = header_name.lower()
        value_lower = header_value.lower()
        
        if header_lower == 'strict-transport-security':
            if 'max-age=' in value_lower:
                max_age_match = re.search(r'max-age=(\d+)', value_lower)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age >= 31536000:  # 1 year
                        return 'good'
                    elif max_age >= 86400:  # 1 day
                        return 'adequate'
                    else:
                        return 'weak'
            return 'weak'
        
        elif header_lower == 'content-security-policy':
            if "'unsafe-eval'" in value_lower or "'unsafe-inline'" in value_lower:
                return 'weak'
            elif "default-src 'self'" in value_lower:
                return 'good'
            else:
                return 'adequate'
        
        elif header_lower == 'x-frame-options':
            if value_lower in ['deny', 'sameorigin']:
                return 'good'
            else:
                return 'adequate'
        
        elif header_lower == 'x-content-type-options':
            if value_lower == 'nosniff':
                return 'good'
            else:
                return 'adequate'
        
        elif header_lower == 'referrer-policy':
            good_policies = [
                'strict-origin-when-cross-origin',
                'strict-origin',
                'same-origin',
                'no-referrer'
            ]
            if value_lower in good_policies:
                return 'good'
            else:
                return 'adequate'
        
        return 'adequate'
    
    def _find_missing_headers(self, headers: dict) -> List[Dict]:
        """Find missing security headers"""
        missing = []
        
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                missing.append({
                    'name': header_name,
                    'importance': header_info['importance'],
                    'description': header_info['description'],
                    'recommendation': f"Add: {header_name}: {header_info['recommendation']}"
                })
        
        return missing
    
    def _check_information_disclosure(self, headers: dict) -> List[Dict]:
        """Check for headers that disclose sensitive information"""
        disclosures = []
        
        for header_name, description in self.dangerous_headers.items():
            if header_name in headers:
                disclosures.append({
                    'header': header_name,
                    'value': headers[header_name],
                    'risk': description,
                    'recommendation': f"Remove or obfuscate the {header_name} header"
                })
        
        return disclosures
    
    def _analyze_cookies(self, cookies) -> Dict:
        """Analyze cookie security attributes"""
        analysis = {
            'total_cookies': len(cookies),
            'secure_cookies': 0,
            'httponly_cookies': 0,
            'samesite_cookies': 0,
            'issues': []
        }
        
        for cookie in cookies:
            if cookie.secure:
                analysis['secure_cookies'] += 1
            else:
                analysis['issues'].append(f"Cookie '{cookie.name}' missing Secure flag")
            
            if hasattr(cookie, 'httponly') and cookie.httponly:
                analysis['httponly_cookies'] += 1
            else:
                analysis['issues'].append(f"Cookie '{cookie.name}' missing HttpOnly flag")
            
            if hasattr(cookie, 'samesite') and cookie.samesite:
                analysis['samesite_cookies'] += 1
            else:
                analysis['issues'].append(f"Cookie '{cookie.name}' missing SameSite attribute")
        
        return analysis
    
    def _calculate_security_score(self, results: Dict) -> int:
        """Calculate overall security score"""
        score = 100
        
        headers_analysis = results.get('headers_analysis', [])
        missing_headers = results.get('missing_headers', [])
        disclosures = results.get('information_disclosure', [])
        
        # Deduct for missing headers
        for header in missing_headers:
            importance = header.get('importance', 'low')
            if importance == 'high':
                score -= 20
            elif importance == 'medium':
                score -= 10
            else:
                score -= 5
        
        # Deduct for weak header values
        for header in headers_analysis:
            if header.get('assessment') == 'weak':
                score -= 15
            elif header.get('assessment') == 'adequate':
                score -= 5
        
        # Deduct for information disclosure
        score -= len(disclosures) * 5
        
        # Deduct for cookie issues
        cookie_analysis = results.get('cookie_security', {})
        score -= len(cookie_analysis.get('issues', [])) * 3
        
        return max(0, min(100, score))
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade based on score"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        score = results.get('security_score', 0)
        grade = results.get('grade', 'F')
        
        # Overall assessment
        if grade in ['A', 'B']:
            recommendations.append(f"✅ Good security posture (Grade: {grade}, Score: {score}/100)")
        elif grade in ['C', 'D']:
            recommendations.append(f"⚠️ Moderate security issues (Grade: {grade}, Score: {score}/100)")
        else:
            recommendations.append(f"❗ Poor security configuration (Grade: {grade}, Score: {score}/100)")
        
        # Missing headers recommendations
        missing_headers = results.get('missing_headers', [])
        high_importance_missing = [h for h in missing_headers if h.get('importance') == 'high']
        
        if high_importance_missing:
            recommendations.append("🚨 Critical: Add high-importance security headers (HSTS, CSP)")
        
        # Information disclosure recommendations
        disclosures = results.get('information_disclosure', [])
        if disclosures:
            recommendations.append("🔒 Remove server information disclosure headers")
        
        # Cookie security recommendations
        cookie_issues = results.get('cookie_security', {}).get('issues', [])
        if cookie_issues:
            recommendations.append("🍪 Secure cookie attributes (Secure, HttpOnly, SameSite)")
        
        # Specific improvements
        headers_analysis = results.get('headers_analysis', [])
        weak_headers = [h for h in headers_analysis if h.get('assessment') == 'weak']
        
        if weak_headers:
            recommendations.append("🔧 Strengthen weak security header configurations")
        
        return recommendations
    
    def bulk_check(self, urls: List[str]) -> Dict:
        """Check multiple URLs for security headers"""
        results = {}
        
        for url in urls:
            try:
                result = self.analyze_headers(url)
                results[url] = result
            except Exception as e:
                results[url] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def generate_security_report(self, results: Dict) -> str:
        """Generate a detailed security report"""
        if not results.get('success'):
            return "Error generating report: " + results.get('error', 'Unknown error')
        
        data = results.get('results', {})
        report_lines = []
        
        report_lines.append(f"=== Security Headers Report for {data.get('url', 'Unknown')} ===")
        report_lines.append(f"Overall Grade: {data.get('grade', 'F')} ({data.get('security_score', 0)}/100)")
        report_lines.append("")
        
        # Headers analysis
        report_lines.append("Security Headers Analysis:")
        for header in data.get('headers_analysis', []):
            status = "✅" if header.get('status') == 'present' else "❌"
            assessment = header.get('assessment', 'unknown')
            report_lines.append(f"  {status} {header.get('name')}: {assessment}")
        
        report_lines.append("")
        
        # Recommendations
        report_lines.append("Recommendations:")
        for rec in data.get('recommendations', []):
            report_lines.append(f"  • {rec}")
        
        return "\n".join(report_lines)