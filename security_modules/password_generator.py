import random
import string
import re
import math
import secrets
import unicodedata
import datetime
from collections import Counter
from typing import Dict, List, Tuple

class PasswordGenerator:
    """Intelligent password generator with tiered security approach and enhanced strength analysis"""
    
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "0O1lI"
        
    def evaluate_password_tier(self, password: str) -> Dict:
        """Evaluate password and determine security tier"""
        strength = self.calculate_strength(password)
        score = strength['score']
        
        if score >= 80:
            return {
                'tier': 'strong',
                'needs_questions': False,
                'message': 'Your password is strong! No additional questions needed.',
                'recommendations': ['Your password meets high security standards.'],
                'warning_level': 'success'
            }
        elif score >= 50:
            return {
                'tier': 'moderate',
                'needs_questions': True,
                'question_count': 3,
                'message': 'Your password is moderate. Please answer a few security questions to strengthen your profile.',
                'recommendations': [
                    'Consider adding more special characters',
                    'Increase password length to 12+ characters',
                    'Mix uppercase and lowercase letters'
                ],
                'warning_level': 'warning'
            }
        else:
            return {
                'tier': 'weak',
                'needs_questions': True,
                'question_count': 10,
                'message': 'Your password is weak and needs improvement.',
                'recommendations': [
                    'Increase password length significantly (16+ characters)',
                    'Use a mix of uppercase, lowercase, numbers, and symbols',
                    'Avoid common words and patterns',
                    'Consider using a password manager'
                ],
                'warning_level': 'danger',
                'requires_improvement': True
            }
    
    def get_security_questions_for_tier(self, tier: str) -> List[str]:
        """Get appropriate questions based on security tier"""
        all_questions = [
            "How many different types of accounts do you use this password for?",
            "Do you share computers with others?", 
            "How often do you change your passwords?",
            "Do you use password managers?",
            "How sensitive is the data this password protects?",
            "Do you access accounts from public computers/networks?",
            "How many people might need to know this password?",
            "Do you write down your passwords?",
            "How tech-savvy are potential attackers in your environment?",
            "What's the maximum length password the system accepts?"
        ]
        
        if tier == 'moderate':
            # Return 3 most critical questions
            return all_questions[:3]
        elif tier == 'weak':
            # Return all questions for comprehensive assessment
            return all_questions
        else:
            return []
        
    def handle_weak_password_attempts(self, attempt_count: int, system_sensitivity: str = "standard") -> Dict:
        """Handle repeated weak password attempts with friendly negotiation"""
        if attempt_count == 1:
            return {
                'blocked': False,
                'message': 'I understand you may prefer simpler passwords! However, this password might not provide the best protection for your account.',
                'suggestion': 'Would you like me to suggest some ways to strengthen it while keeping it manageable for you?',
                'warning_level': 'info',
                'show_negotiations': True,
                'negotiations': [
                    {
                        'title': 'Try a longer version',
                        'description': 'Keep your current password but make it longer by adding numbers or your favorite symbols',
                        'example': 'If your password is "sunshine", try "sunshine2024!" or "sunshine@home"'
                    },
                    {
                        'title': 'Add additional security layers',
                        'description': 'Keep your current password and add two-factor authentication (2FA)',
                        'benefits': ['Get text codes when you log in', 'Much safer even with a simple password', 'Easy to set up']
                    }
                ]
            }
        elif attempt_count == 2:
            return {
                'blocked': False,
                'message': 'I really want to help you stay secure! Let me offer you some friendly alternatives that might work better for you.',
                'suggestion': 'Would any of these options work for you?',
                'warning_level': 'warning',
                'show_negotiations': True,
                'negotiations': [
                    {
                        'title': 'One-Time Password (OTP) System',
                        'description': 'Use your preferred password plus get unique codes via email/SMS',
                        'benefits': ['Keep using passwords you like', 'Extra security codes sent to your phone', 'Industry standard protection']
                    },
                    {
                        'title': 'Passphrase approach',
                        'description': 'Use a sentence instead of a complex password',
                        'example': 'Instead of "p@ssW0rd!" try "I love pizza on Fridays!"',
                        'benefits': ['Easy to remember', 'Naturally long and secure', 'Can include spaces']
                    },
                    {
                        'title': 'Biometric backup',
                        'description': 'Use your fingerprint or face recognition with a simple password',
                        'benefits': ['Quick and easy access', 'Highly secure', 'No need to remember complex passwords']
                    }
                ]
            }
        elif attempt_count >= 3:
            sensitivity_message = self._get_sensitivity_message(system_sensitivity)
            return {
                'blocked': False,
                'message': f'I completely understand - password complexity can be challenging! {sensitivity_message}',
                'suggestion': 'Let me help you find the best security solution for your needs.',
                'warning_level': 'warning',
                'show_final_options': True,
                'final_options': [
                    {
                        'title': 'Use our Smart Password Generator',
                        'description': 'I\'ll create a secure password and show you memory techniques to remember it',
                        'action': 'generate_smart_password'
                    },
                    {
                        'title': 'Accept with Enhanced Security',
                        'description': 'Keep your password and add multiple security layers (2FA + monitoring)',
                        'action': 'accept_with_enhanced_security'
                    },
                    {
                        'title': 'Get Security Consultation',
                        'description': 'Speak with our security team about the best options for your situation',
                        'action': 'request_consultation'
                    }
                ]
            }
        else:
            return {
                'blocked': False,
                'message': 'Let\'s work together to find a password solution that works for you!',
                'suggestion': 'I\'m here to help make security easy and manageable.',
                'warning_level': 'info'
            }

    def _get_sensitivity_message(self, system_sensitivity: str) -> str:
        """Get appropriate message based on system sensitivity"""
        messages = {
            'high': 'Since this system handles highly sensitive information, we do need strong security measures in place.',
            'critical': 'This system contains critical data that requires robust protection measures.',
            'financial': 'For financial systems, regulatory compliance requires enhanced security protocols.',
            'healthcare': 'Healthcare data protection laws require us to maintain high security standards.',
            'government': 'Government security protocols mandate strong authentication measures.',
            'standard': 'While security is important, I want to find an approach that works for you.'
        }
        return messages.get(system_sensitivity, messages['standard'])
    
    def suggest_additional_security(self, password_strength: str) -> Dict:
        """Suggest additional security layers for weak passwords"""
        suggestions = {
            'weak': {
                'primary': 'Let\'s add some extra security layers to protect your account! 🛡️',
                'options': [
                    {
                        'name': 'Two-Factor Authentication (2FA)',
                        'description': 'Get a code on your phone when you log in',
                        'difficulty': 'Easy',
                        'setup_time': '2-3 minutes',
                        'security_boost': 'Very High',
                        'user_friendly': True
                    },
                    {
                        'name': 'One-Time Password (OTP)',
                        'description': 'Use your password plus unique codes via email/SMS',
                        'difficulty': 'Very Easy',
                        'setup_time': '1 minute',
                        'security_boost': 'High',
                        'user_friendly': True
                    },
                    {
                        'name': 'Biometric Authentication',
                        'description': 'Use fingerprint or face recognition as backup',
                        'difficulty': 'Easy',
                        'setup_time': '1-2 minutes',
                        'security_boost': 'Very High',
                        'user_friendly': True,
                        'requires_hardware': True
                    },
                    {
                        'name': 'Email Notifications',
                        'description': 'Get alerts when someone accesses your account',
                        'difficulty': 'Very Easy',
                        'setup_time': '30 seconds',
                        'security_boost': 'Medium',
                        'user_friendly': True
                    },
                    {
                        'name': 'Account Monitoring',
                        'description': 'Automatic detection of suspicious login attempts',
                        'difficulty': 'Automatic',
                        'setup_time': 'Instant',
                        'security_boost': 'Medium',
                        'user_friendly': True
                    }
                ],
                'message': 'Don\'t worry about having a complex password - these security features will keep you safe! Pick any combination that feels comfortable.',
                'enthusiasm': 'You can stay secure without memorizing complicated passwords! 🎯'
            },
            'moderate': {
                'primary': 'Your password is good! Want to make it even more secure?',
                'options': [
                    {
                        'name': 'Two-Factor Authentication',
                        'description': 'Add an extra layer of protection',
                        'difficulty': 'Easy',
                        'security_boost': 'High',
                        'user_friendly': True
                    },
                    {
                        'name': 'Login Alerts',
                        'description': 'Know when someone accesses your account',
                        'difficulty': 'Very Easy',
                        'security_boost': 'Medium',
                        'user_friendly': True
                    }
                ],
                'message': 'Your password is decent, but extra security never hurts!',
                'enthusiasm': 'You\'re on the right track! 👍'
            }
        }
        
        return suggestions.get(password_strength, {})

    def generate_passphrase(self, word_count: int = 4, separator: str = " ") -> Dict:
        """Generate memorable passphrase instead of complex password"""
        word_lists = {
            'adjectives': ['amazing', 'bright', 'clever', 'delighted', 'elegant', 'fantastic', 'graceful', 'happy', 'incredible', 'joyful'],
            'nouns': ['butterfly', 'mountain', 'ocean', 'rainbow', 'sunshine', 'garden', 'melody', 'adventure', 'treasure', 'journey'],
            'verbs': ['dancing', 'flying', 'singing', 'laughing', 'exploring', 'creating', 'discovering', 'building', 'growing', 'shining'],
            'numbers': ['2024', '100', '2025', '50', '365', '7', '12', '24']
        }
        
        # Generate passphrase with pattern: adjective + noun + verb + number
        if word_count >= 4:
            words = [
                random.choice(word_lists['adjectives']),
                random.choice(word_lists['nouns']),
                random.choice(word_lists['verbs']),
                random.choice(word_lists['numbers'])
            ]
        else:
            # Simplified version
            all_words = word_lists['adjectives'] + word_lists['nouns'] + word_lists['verbs']
            words = random.sample(all_words, word_count)
            words.append(random.choice(word_lists['numbers']))
        
        passphrase = separator.join(words)
        
        # Add optional capitalization for first letters
        if separator == " ":
            passphrase = passphrase.title()
        
        return {
            'passphrase': passphrase,
            'word_count': len(words),
            'estimated_strength': 'Strong',
            'memory_tip': f'Remember: {words[0]} {words[1]} is {words[2]} in {words[-1]}',
            'length': len(passphrase),
            'user_friendly': True
        }

    def create_memory_aid(self, password: str) -> Dict:
        """Create memory aids for complex passwords"""
        aids = []
        
        # Pattern recognition
        if len(password) >= 8:
            aids.append({
                'type': 'chunking',
                'description': f'Break it into chunks: {password[:3]}-{password[3:6]}-{password[6:]}',
                'tip': 'Remember each chunk separately, then combine them'
            })
        
        # Character mapping
        char_map = {
            '@': 'at sign', '!': 'exclamation', '#': 'hash', '$': 'dollar',
            '&': 'and symbol', '*': 'star', '+': 'plus'
        }
        
        special_chars = [c for c in password if c in char_map]
        if special_chars:
            aids.append({
                'type': 'symbol_story',
                'description': f'Special characters story: {", ".join([char_map.get(c, c) for c in special_chars])}',
                'tip': 'Create a mental image or story using these symbols'
            })
        
        # First letter technique
        if len(password) >= 6:
            aids.append({
                'type': 'acronym',
                'description': f'First letters could stand for a phrase you create',
                'example': 'Create a sentence where each word starts with these letters'
            })
        
        return {
            'memory_aids': aids,
            'general_tips': [
                'Practice typing it a few times',
                'Use it regularly to build muscle memory',
                'Write down hints (not the password) if needed'
            ]
        }
    
    def analyze_security_profile(self, answers: Dict) -> Dict:
        """Analyze security questions to provide personalized recommendations"""
        recommendations = {
            'recommended_length': 12,
            'include_symbols': True,
            'include_numbers': True,
            'include_uppercase': True,
            'exclude_ambiguous': False,
            'reasoning': [],
            'security_level': 'medium'
        }
        
        # Question 1: Number of accounts (more accounts = longer passwords)
        account_count = answers.get('q1', '1-3')
        if 'many' in account_count.lower() or '10+' in account_count:
            recommendations['recommended_length'] = max(16, recommendations['recommended_length'])
            recommendations['reasoning'].append("Increased length for multiple account usage")
            
        # Question 2: Shared computers
        shared_computers = answers.get('q2', 'no').lower()
        if 'yes' in shared_computers:
            recommendations['exclude_ambiguous'] = True
            recommendations['recommended_length'] = max(14, recommendations['recommended_length'])
            recommendations['reasoning'].append("Avoiding ambiguous characters for shared environments")
            
        # Question 3: Password change frequency
        change_freq = answers.get('q3', 'rarely').lower()
        if 'rarely' in change_freq or 'never' in change_freq:
            recommendations['recommended_length'] = max(16, recommendations['recommended_length'])
            recommendations['security_level'] = 'high'
            recommendations['reasoning'].append("Longer password for infrequent changes")
            
        # Question 4: Password manager usage
        uses_manager = answers.get('q4', 'no').lower()
        if 'yes' in uses_manager:
            recommendations['recommended_length'] = max(20, recommendations['recommended_length'])
            recommendations['include_symbols'] = True
            recommendations['reasoning'].append("Maximum security with password manager")
            
        # Question 5: Data sensitivity
        sensitivity = answers.get('q5', 'medium').lower()
        if 'high' in sensitivity or 'critical' in sensitivity:
            recommendations['recommended_length'] = max(18, recommendations['recommended_length'])
            recommendations['security_level'] = 'high'
            recommendations['reasoning'].append("Enhanced security for sensitive data")
            
        # Question 6: Public network access
        public_access = answers.get('q6', 'no').lower()
        if 'yes' in public_access:
            recommendations['recommended_length'] = max(15, recommendations['recommended_length'])
            recommendations['reasoning'].append("Stronger password for public network exposure")
            
        # Question 7: Shared password
        shared_password = answers.get('q7', '1').lower()
        if any(word in shared_password for word in ['multiple', 'several', 'many']):
            recommendations['exclude_ambiguous'] = True
            recommendations['reasoning'].append("Avoiding confusion in shared passwords")
            
        # Question 8: Writing down passwords
        written_down = answers.get('q8', 'no').lower()
        if 'yes' in written_down:
            recommendations['exclude_ambiguous'] = True
            recommendations['reasoning'].append("Clear characters for written passwords")
            
        # Question 9: Threat level
        threat_level = answers.get('q9', 'low').lower()
        if 'high' in threat_level:
            recommendations['recommended_length'] = max(20, recommendations['recommended_length'])
            recommendations['security_level'] = 'maximum'
            recommendations['reasoning'].append("Maximum security for high-threat environment")
            
        # Question 10: System constraints
        max_length = answers.get('q10', 'unlimited')
        if max_length.isdigit():
            max_len = int(max_length)
            if max_len < recommendations['recommended_length']:
                recommendations['recommended_length'] = max_len
                recommendations['reasoning'].append(f"Limited to system maximum of {max_len} characters")
        
        return recommendations
    
    def generate_password(self, length: int = 12, include_symbols: bool = True, 
                         include_numbers: bool = True, include_uppercase: bool = True,
                         exclude_ambiguous: bool = False) -> str:
        """Generate a password based on specified criteria"""
        
        # Build character set
        chars = self.lowercase
        
        if include_uppercase:
            chars += self.uppercase
        if include_numbers:
            chars += self.digits
        if include_symbols:
            chars += self.symbols
            
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in self.ambiguous)
        
        # Ensure at least one character from each required set
        password = []
        
        if include_uppercase:
            password.append(random.choice(self.uppercase))
        if include_numbers:
            password.append(random.choice(self.digits))
        if include_symbols:
            password.append(random.choice(self.symbols))
        
        # Fill the rest randomly
        remaining_length = length - len(password)
        password.extend(random.choices(chars, k=remaining_length))
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)
    
    def calculate_strength(self, password: str) -> Dict:
        """Enhanced password strength calculation with comprehensive security analysis"""
        if not password:
            return {'score': 0, 'level': 'Very Weak', 'entropy': 0, 'warnings': ['Password is empty']}
        
        # Initialize scoring components
        score = 0
        warnings = []
        details = []
        entropy = 0
        
        # Length analysis (enhanced)
        length = len(password)
        if length >= 16:
            score += 30
            details.append(f"Excellent length ({length} characters)")
        elif length >= 12:
            score += 25
            details.append(f"Good length ({length} characters)")
        elif length >= 8:
            score += 15
            details.append(f"Adequate length ({length} characters)")
            warnings.append("Consider using 12+ characters for better security")
        else:
            score += max(0, length * 2)
            warnings.append(f"Password too short ({length} characters). Use 12+ characters")
        
        # Character set diversity (enhanced)
        char_sets = {
            'lowercase': bool(re.search(r'[a-z]', password)),
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'digits': bool(re.search(r'\d', password)),
            'symbols': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'extended': bool(re.search(r'[^\x00-\x7F]', password))  # Non-ASCII characters
        }
        
        active_sets = sum(char_sets.values())
        if active_sets >= 4:
            score += 25
            details.append(f"Excellent character diversity ({active_sets} character types)")
        elif active_sets == 3:
            score += 20
            details.append(f"Good character diversity ({active_sets} character types)")
        elif active_sets == 2:
            score += 10
            details.append(f"Fair character diversity ({active_sets} character types)")
            warnings.append("Add more character types (symbols, uppercase, etc.)")
        else:
            warnings.append("Use multiple character types for better security")
        
        # Calculate entropy
        charset_size = 0
        if char_sets['lowercase']: charset_size += 26
        if char_sets['uppercase']: charset_size += 26
        if char_sets['digits']: charset_size += 10
        if char_sets['symbols']: charset_size += 32  # Common symbols
        if char_sets['extended']: charset_size += 100  # Estimate for extended chars
        
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            if entropy >= 60:
                score += 20
                details.append(f"High entropy ({entropy:.1f} bits)")
            elif entropy >= 40:
                score += 15
                details.append(f"Good entropy ({entropy:.1f} bits)")
            elif entropy >= 28:
                score += 10
                details.append(f"Fair entropy ({entropy:.1f} bits)")
            else:
                warnings.append(f"Low entropy ({entropy:.1f} bits)")
        
        # Basic pattern detection
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 10
            warnings.append("Contains repeated characters")
        
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            score -= 15
            warnings.append("Contains sequential patterns")
        
        # Common password patterns
        common_patterns = ['password', 'admin', '1234', 'qwerty', 'letmein']
        for pattern in common_patterns:
            if pattern in password.lower():
                score -= 10  # Reduced penalty
                warnings.append(f"Contains common pattern: {pattern}")
        
        # Advanced pattern analysis (with reduced impact)
        pattern_results = self._analyze_advanced_patterns(password)
        score += max(-15, pattern_results['score'])  # Limit penalty
        warnings.extend(pattern_results['warnings'])
        details.extend(pattern_results['details'])
        
        # Dictionary word check (with reduced impact)
        dict_results = self._check_dictionary_words(password)
        score += max(-15, dict_results['score'])  # Limit penalty
        warnings.extend(dict_results['warnings'])
        details.extend(dict_results['details'])
        
        # Repetition analysis (with reduced impact)
        repeat_results = self._analyze_repetitions(password)
        score += max(-10, repeat_results['score'])  # Limit penalty
        warnings.extend(repeat_results['warnings'])
        details.extend(repeat_results['details'])
        
        # Personal information detection (with reduced impact)
        personal_results = self._detect_personal_info(password)
        score += max(-10, personal_results['score'])  # Limit penalty
        warnings.extend(personal_results['warnings'])
        details.extend(personal_results['details'])
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Determine strength level with enhanced criteria
        if score >= 90:
            level = 'Exceptional'
        elif score >= 80:
            level = 'Very Strong'
        elif score >= 65:
            level = 'Strong'
        elif score >= 45:
            level = 'Moderate'
        elif score >= 25:
            level = 'Weak'
        else:
            level = 'Very Weak'
        
        # Time to crack estimation
        crack_time = self._estimate_crack_time(entropy, charset_size)
        
        return {
            'score': score,
            'level': level,
            'entropy': round(entropy, 2),
            'charset_size': charset_size,
            'crack_time': crack_time,
            'warnings': warnings,
            'details': details,
            'character_analysis': char_sets,
            'security_rating': self._get_security_rating(score),
            'improvement_suggestions': self._get_improvement_suggestions(score, char_sets, length),
            'analysis_summary': {
                'length_analysis': f"{length} characters",
                'character_diversity': f"{active_sets} character types",
                'pattern_issues': len(pattern_results['warnings']),
                'dictionary_issues': len(dict_results['warnings']),
                'personal_info_issues': len(personal_results['warnings'])
            }
        }
    
    def _analyze_advanced_patterns(self, password: str) -> Dict:
        """Analyze password for advanced patterns and vulnerabilities"""
        score = 0
        warnings = []
        details = []
        
        # Keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '!@#$%^&*()', 'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm'
        ]
        
        for pattern in keyboard_patterns:
            if pattern in password.lower() and len(pattern) >= 3:
                score -= 15
                warnings.append(f"Contains keyboard pattern: {pattern}")
        
        # L33t speak detection
        leet_patterns = {
            '3': 'e', '1': 'i', '0': 'o', '4': 'a', '5': 's', '7': 't', '@': 'a'
        }
        leet_score = sum(1 for char in password if char in leet_patterns)
        if leet_score > 0:
            if leet_score <= 2:
                score += 5
                details.append("Good use of character substitution")
            else:
                score -= 5
                warnings.append("Excessive l33t speak may be predictable")
        
        # Date patterns
        if re.search(r'(19|20)\d{2}', password):
            score -= 10
            warnings.append("Contains year pattern")
        
        if re.search(r'(0[1-9]|1[0-2])[/\\-](0[1-9]|[12]\d|3[01])', password):
            score -= 15
            warnings.append("Contains date pattern")
        
        # Seasonal/temporal patterns
        temporal_words = ['spring', 'summer', 'fall', 'winter', 'january', 'february', 'march', 
                         'april', 'may', 'june', 'july', 'august', 'september', 'october', 
                         'november', 'december', 'monday', 'tuesday', 'wednesday', 'thursday', 
                         'friday', 'saturday', 'sunday']
        
        for word in temporal_words:
            if word in password.lower():
                score -= 8
                warnings.append(f"Contains temporal word: {word}")
        
        # Character frequency analysis
        char_freq = Counter(password.lower())
        max_freq = max(char_freq.values()) if char_freq else 0
        total_chars = len(password)
        
        if total_chars > 0:
            freq_ratio = max_freq / total_chars
            if freq_ratio > 0.3:  # More than 30% same character
                score -= 20
                warnings.append("High character repetition detected")
            elif freq_ratio > 0.2:  # More than 20% same character
                score -= 10
                warnings.append("Moderate character repetition")
        
        # Palindrome detection
        if password.lower() == password.lower()[::-1] and len(password) > 4:
            score -= 15
            warnings.append("Password is a palindrome")
        
        # Alternating patterns
        if len(password) > 6:
            alternating = all(password[i].isupper() != password[i+1].isupper() 
                            for i in range(len(password)-1) if password[i].isalpha() and password[i+1].isalpha())
            if alternating:
                score += 5
                details.append("Good alternating case pattern")
        
        return {'score': score, 'warnings': warnings, 'details': details}
    
    def _check_dictionary_words(self, password: str) -> Dict:
        """Check for dictionary words and common passwords"""
        score = 0
        warnings = []
        details = []
        
        # Common passwords database
        common_passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty', 'letmein',
            'welcome', 'monkey', '1234567890', 'abc123', 'password1', 'login',
            'master', 'hello', 'guest', 'test', 'root', 'user', 'pass', 'default',
            'secret', 'dragon', 'princess', 'football', 'baseball', 'sunshine',
            'rainbow', 'computer', 'freedom', 'whatever', 'security', 'system'
        ]
        
        password_lower = password.lower()
        for common in common_passwords:
            if common in password_lower:
                penalty = min(30, len(common) * 3)
                score -= penalty
                warnings.append(f"Contains common password element: {common}")
        
        # Dictionary word detection
        common_words = [
            'love', 'life', 'work', 'home', 'time', 'year', 'good', 'great',
            'little', 'world', 'school', 'house', 'family', 'friend', 'money',
            'business', 'internet', 'service', 'phone', 'email', 'account',
            'company', 'website', 'online', 'secure', 'private', 'personal'
        ]
        
        word_count = 0
        for word in common_words:
            if len(word) >= 4 and word in password_lower:
                word_count += 1
                score -= 8
                warnings.append(f"Contains common word: {word}")
        
        if word_count == 0:
            score += 10
            details.append("No common dictionary words detected")
        
        # Personal information patterns
        if re.search(r'(name|user|admin|john|jane|mike|sarah|password|pass)', password_lower):
            score -= 12
            warnings.append("Contains generic personal information")
        
        return {'score': score, 'warnings': warnings, 'details': details}
    
    def _analyze_repetitions(self, password: str) -> Dict:
        """Analyze character repetitions and sequences"""
        score = 0
        warnings = []
        details = []
        
        # Consecutive character repetition
        consecutive_pattern = re.findall(r'(.)\1{2,}', password)
        if consecutive_pattern:
            max_repeat = max(len(match) + 1 for match in consecutive_pattern)
            if max_repeat >= 5:
                score -= 25
                warnings.append(f"Excessive character repetition ({max_repeat} consecutive)")
            elif max_repeat >= 3:
                score -= 15
                warnings.append(f"Character repetition detected ({max_repeat} consecutive)")
        else:
            score += 5
            details.append("No excessive character repetition")
        
        # Sequential patterns (ascending)
        sequential_patterns = [
            '0123', '1234', '2345', '3456', '4567', '5678', '6789',
            'abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij'
        ]
        
        for pattern in sequential_patterns:
            if pattern in password.lower():
                score -= 20
                warnings.append(f"Contains ascending sequence: {pattern}")
        
        # Sequential patterns (descending)
        descending_patterns = [
            '9876', '8765', '7654', '6543', '5432', '4321', '3210',
            'dcba', 'cba', 'zyxw', 'yxwv', 'xwvu', 'wvut', 'vuts'
        ]
        
        for pattern in descending_patterns:
            if pattern in password.lower():
                score -= 20
                warnings.append(f"Contains descending sequence: {pattern}")
        
        # Check for arithmetic sequences
        if len(password) >= 4:
            digits_only = re.sub(r'[^0-9]', '', password)
            if len(digits_only) >= 3:
                for i in range(len(digits_only) - 2):
                    if (int(digits_only[i+1]) - int(digits_only[i]) == 
                        int(digits_only[i+2]) - int(digits_only[i+1])):
                        score -= 10
                        warnings.append("Contains arithmetic sequence in digits")
                        break
        
        return {'score': score, 'warnings': warnings, 'details': details}
    
    def _detect_personal_info(self, password: str) -> Dict:
        """Detect potential personal information in passwords"""
        score = 0
        warnings = []
        details = []
        
        # Phone number patterns
        if re.search(r'\d{3}[\-\.]?\d{3}[\-\.]?\d{4}', password):
            score -= 25
            warnings.append("Contains phone number pattern")
        
        # Social security pattern
        if re.search(r'\d{3}[\-]?\d{2}[\-]?\d{4}', password):
            score -= 30
            warnings.append("Contains SSN-like pattern")
        
        # Address patterns
        if re.search(r'\d{1,5}\s*(st|nd|rd|th|street|ave|avenue|dr|drive|ln|lane)', password.lower()):
            score -= 20
            warnings.append("Contains address-like pattern")
        
        # Birth year patterns (1920-2023)
        current_year = datetime.datetime.now().year
        for year in range(1920, current_year + 1):
            if str(year) in password:
                score -= 15
                warnings.append(f"Contains potential birth year: {year}")
                break
        
        # Vehicle patterns (license plates)
        if re.search(r'[A-Z]{2,3}\d{3,4}', password.upper()):
            score -= 15
            warnings.append("Contains license plate-like pattern")
        
        # Credit card patterns (simplified)
        if re.search(r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}', password):
            score -= 35
            warnings.append("Contains credit card-like pattern")
        
        if not warnings:
            score += 10
            details.append("No personal information patterns detected")
        
        return {'score': score, 'warnings': warnings, 'details': details}
    
    def _estimate_crack_time(self, entropy: float, charset_size: int) -> Dict:
        """Estimate time to crack password using various methods"""
        if entropy <= 0:
            return {'online': 'Instantly', 'offline_fast': 'Instantly', 'offline_slow': 'Instantly'}
        
        # Attempts needed (average)
        attempts = (2 ** entropy) / 2
        
        # Attack speeds (attempts per second)
        online_speed = 1000  # Rate-limited online attacks
        offline_fast_speed = 1e12  # High-end GPU cluster
        offline_slow_speed = 1e6   # Single CPU
        
        def format_time(seconds):
            if seconds < 60:
                return f"{seconds:.0f} seconds"
            elif seconds < 3600:
                return f"{seconds/60:.0f} minutes"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                return f"{seconds/86400:.0f} days"
            elif seconds < 31536000 * 1000:
                return f"{seconds/31536000:.0f} years"
            else:
                return "Billions of years"
        
        return {
            'online': format_time(attempts / online_speed),
            'offline_fast': format_time(attempts / offline_fast_speed),
            'offline_slow': format_time(attempts / offline_slow_speed),
            'entropy_bits': entropy
        }
    
    def _get_security_rating(self, score: int) -> Dict:
        """Get detailed security rating based on score"""
        if score >= 90:
            return {
                'rating': 'Exceptional',
                'color': '#0d7377',
                'description': 'Military-grade password security',
                'recommendation': 'Excellent choice for high-security applications'
            }
        elif score >= 80:
            return {
                'rating': 'Very Strong',
                'color': '#28a745',
                'description': 'Excellent security for most applications',
                'recommendation': 'Perfect for financial and sensitive accounts'
            }
        elif score >= 65:
            return {
                'rating': 'Strong',
                'color': '#20c997',
                'description': 'Good security for general use',
                'recommendation': 'Suitable for most online accounts'
            }
        elif score >= 45:
            return {
                'rating': 'Moderate',
                'color': '#ffc107',
                'description': 'Basic security, consider improvements',
                'recommendation': 'Acceptable for low-risk accounts only'
            }
        elif score >= 25:
            return {
                'rating': 'Weak',
                'color': '#fd7e14',
                'description': 'Poor security, vulnerable to attacks',
                'recommendation': 'Should be improved before use'
            }
        else:
            return {
                'rating': 'Very Weak',
                'color': '#dc3545',
                'description': 'Extremely vulnerable to attacks',
                'recommendation': 'Must be changed immediately'
            }
    
    def _get_improvement_suggestions(self, score: int, char_sets: Dict, length: int) -> List[str]:
        """Generate specific improvement suggestions"""
        suggestions = []
        
        # Length suggestions
        if length < 8:
            suggestions.append("🔢 Use at least 8 characters (12+ recommended)")
        elif length < 12:
            suggestions.append("🔢 Consider extending to 12+ characters for better security")
        elif length < 16:
            suggestions.append("🔢 For maximum security, consider 16+ characters")
        
        # Character type suggestions
        if not char_sets.get('lowercase', False):
            suggestions.append("🔤 Add lowercase letters (a-z)")
        if not char_sets.get('uppercase', False):
            suggestions.append("🔠 Add uppercase letters (A-Z)")
        if not char_sets.get('digits', False):
            suggestions.append("🔢 Include numbers (0-9)")
        if not char_sets.get('symbols', False):
            suggestions.append("🔣 Add special characters (!@#$%^&*)")
        if not char_sets.get('extended', False) and score < 70:
            suggestions.append("🌐 Consider using extended characters (é, ñ, etc.)")
        
        # Security-specific suggestions
        if score < 50:
            suggestions.append("🛡️ Avoid common words and patterns")
            suggestions.append("🔄 Make it unique - don't reuse across accounts")
            suggestions.append("💡 Use a passphrase with random words")
        
        if score < 30:
            suggestions.append("⚠️ Consider using a password manager")
            suggestions.append("🔐 Enable two-factor authentication as backup")
        
        # Advanced suggestions for already strong passwords
        if score >= 70:
            suggestions.append("✨ Your password is strong! Consider these advanced tips:")
            suggestions.append("🔄 Rotate important passwords every 6-12 months")
            suggestions.append("📱 Use different passwords for each account")
            suggestions.append("🔒 Enable 2FA for additional security layers")
        
        return suggestions
    
    def detailed_strength_analysis(self, password: str) -> Dict:
        """Provide detailed analysis of password strength"""
        analysis = self.calculate_strength(password)
        
        # Additional details for backwards compatibility
        analysis['length'] = len(password)
        analysis['has_lowercase'] = analysis['character_analysis']['lowercase']
        analysis['has_uppercase'] = analysis['character_analysis']['uppercase']
        analysis['has_numbers'] = analysis['character_analysis']['digits']
        analysis['has_symbols'] = analysis['character_analysis']['symbols']
        
        # Map new format to old format for compatibility
        analysis['feedback'] = analysis['warnings']
        analysis['strength'] = analysis['level']
        analysis['security_recommendations'] = analysis['improvement_suggestions']
        
        return analysis