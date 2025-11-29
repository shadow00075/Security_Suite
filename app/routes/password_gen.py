from flask import Blueprint, render_template, request, jsonify, session
from security_modules.password_generator import PasswordGenerator
import json

password_bp = Blueprint('password', __name__)

@password_bp.route('/generator')
def password_generator():
    """Password generator page with tiered security approach"""
    # Initialize session for weak password tracking
    if 'weak_password_attempts' not in session:
        session['weak_password_attempts'] = 0
    
    return render_template('password_generator.html', 
                         title="Password Strength Checker")

@password_bp.route('/evaluate-password', methods=['POST'])
def evaluate_password():
    """Evaluate existing password and determine next steps"""
    try:
        data = request.json
        password = data.get('password', '')
        system_sensitivity = data.get('system_sensitivity', 'standard')
        
        if not password:
            return jsonify({
                'success': False,
                'error': 'Password is required'
            }), 400
        
        generator = PasswordGenerator()
        
        # Evaluate password tier
        tier_info = generator.evaluate_password_tier(password)
        strength_info = generator.detailed_strength_analysis(password)
        
        # Handle weak password attempts with friendly negotiation
        if tier_info['tier'] == 'weak':
            session['weak_password_attempts'] = session.get('weak_password_attempts', 0) + 1
            weak_attempt_info = generator.handle_weak_password_attempts(
                session['weak_password_attempts'], 
                system_sensitivity
            )
            tier_info.update(weak_attempt_info)
        else:
            # Reset attempts for non-weak passwords
            session['weak_password_attempts'] = 0
        
        # Get appropriate questions based on tier
        questions = generator.get_security_questions_for_tier(tier_info['tier'])
        
        # Get additional security suggestions
        additional_security = generator.suggest_additional_security(tier_info['tier'])
        
        return jsonify({
            'success': True,
            'tier_info': tier_info,
            'strength_info': strength_info,
            'questions': questions,
            'additional_security': additional_security,
            'attempt_count': session.get('weak_password_attempts', 0)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/generate', methods=['POST'])
def generate_password():
    """Generate password based on user responses and tier"""
    try:
        data = request.json
        answers = data.get('answers', {})
        custom_length = data.get('length', None)
        tier = data.get('tier', 'moderate')
        
        # Initialize password generator
        generator = PasswordGenerator()
        
        # Analyze answers if provided
        if answers:
            recommendations = generator.analyze_security_profile(answers)
        else:
            # Default recommendations based on tier
            if tier == 'weak':
                recommendations = {
                    'recommended_length': 16,
                    'include_symbols': True,
                    'include_numbers': True,
                    'include_uppercase': True,
                    'exclude_ambiguous': False,
                    'reasoning': ['Enhanced security for weak password replacement'],
                    'security_level': 'high'
                }
            elif tier == 'moderate':
                recommendations = {
                    'recommended_length': 14,
                    'include_symbols': True,
                    'include_numbers': True,
                    'include_uppercase': True,
                    'exclude_ambiguous': False,
                    'reasoning': ['Balanced security improvement'],
                    'security_level': 'medium'
                }
            else:
                recommendations = {
                    'recommended_length': 12,
                    'include_symbols': True,
                    'include_numbers': True,
                    'include_uppercase': True,
                    'exclude_ambiguous': False,
                    'reasoning': ['Standard security level'],
                    'security_level': 'medium'
                }
        
        # Generate password based on recommendations
        password = generator.generate_password(
            length=custom_length or recommendations['recommended_length'],
            include_symbols=recommendations['include_symbols'],
            include_numbers=recommendations['include_numbers'],
            include_uppercase=recommendations['include_uppercase'],
            exclude_ambiguous=recommendations['exclude_ambiguous']
        )
        
        # Generate alternatives
        alternatives = [
            generator.generate_password(
                length=recommendations['recommended_length'],
                include_symbols=recommendations['include_symbols'],
                include_numbers=recommendations['include_numbers'],
                include_uppercase=recommendations['include_uppercase'],
                exclude_ambiguous=recommendations['exclude_ambiguous']
            ) for _ in range(3)
        ]
        
        # Get strength analysis
        strength_info = generator.detailed_strength_analysis(password)
        
        # Reset weak password attempts on successful generation
        session['weak_password_attempts'] = 0
        
        return jsonify({
            'success': True,
            'password': password,
            'alternatives': alternatives,
            'recommendations': recommendations,
            'strength_info': strength_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/check-strength', methods=['POST'])
def check_strength():
    """Check password strength without tier evaluation"""
    try:
        data = request.json
        password = data.get('password', '')
        
        if not password:
            return jsonify({
                'success': False,
                'error': 'Password is required'
            }), 400
        
        generator = PasswordGenerator()
        strength_info = generator.detailed_strength_analysis(password)
        
        return jsonify({
            'success': True,
            'strength_info': strength_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/reset-attempts', methods=['POST'])
def reset_attempts():
    """Reset weak password attempts (admin function)"""
    try:
        session['weak_password_attempts'] = 0
        return jsonify({
            'success': True,
            'message': 'Attempts reset successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/generate-passphrase', methods=['POST'])
def generate_passphrase():
    """Generate user-friendly passphrase"""
    try:
        data = request.json
        word_count = data.get('word_count', 4)
        separator = data.get('separator', ' ')
        
        generator = PasswordGenerator()
        passphrase_info = generator.generate_passphrase(word_count, separator)
        
        return jsonify({
            'success': True,
            'passphrase_info': passphrase_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/accept-with-security', methods=['POST'])
def accept_with_enhanced_security():
    """Accept weak password with additional security measures"""
    try:
        data = request.json
        password = data.get('password', '')
        selected_security_options = data.get('security_options', [])
        
        if not password:
            return jsonify({
                'success': False,
                'error': 'Password is required'
            }), 400
        
        generator = PasswordGenerator()
        
        # Create security plan
        security_plan = {
            'password_accepted': True,
            'selected_options': selected_security_options,
            'setup_instructions': [],
            'security_level': 'Enhanced with additional layers'
        }
        
        # Add setup instructions for each selected option
        option_instructions = {
            'two_factor': {
                'title': 'Set up Two-Factor Authentication (2FA)',
                'steps': [
                    'Go to your account security settings',
                    'Find "Two-Factor Authentication" or "2FA"', 
                    'Choose "Text Message" or "Authenticator App"',
                    'Follow the setup wizard',
                    'Save your backup codes in a safe place'
                ],
                'estimated_time': '2-3 minutes'
            },
            'otp': {
                'title': 'Enable One-Time Password (OTP)',
                'steps': [
                    'Navigate to security settings',
                    'Enable "Email OTP" or "SMS OTP"',
                    'Verify your contact information',
                    'Test the system with a practice login'
                ],
                'estimated_time': '1-2 minutes'
            },
            'email_alerts': {
                'title': 'Enable Email Notifications',
                'steps': [
                    'Go to notification settings',
                    'Enable "Login Alerts"',
                    'Verify your email address',
                    'Set alert preferences'
                ],
                'estimated_time': '30 seconds'
            },
            'biometric': {
                'title': 'Set up Biometric Authentication',
                'steps': [
                    'Check if your device supports biometrics',
                    'Go to account security settings',
                    'Enable "Fingerprint" or "Face Recognition"',
                    'Register your biometric data',
                    'Test the authentication'
                ],
                'estimated_time': '1-2 minutes'
            }
        }
        
        for option in selected_security_options:
            if option in option_instructions:
                security_plan['setup_instructions'].append(option_instructions[option])
        
        # Reset attempts since user accepted a security solution
        session['weak_password_attempts'] = 0
        
        return jsonify({
            'success': True,
            'security_plan': security_plan,
            'message': 'Great choice! Your account will be well-protected with these security measures.',
            'next_steps': 'Follow the setup instructions to complete your enhanced security configuration.'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/get-memory-aid', methods=['POST'])
def get_memory_aid():
    """Get memory aids for complex passwords"""
    try:
        data = request.json
        password = data.get('password', '')
        
        if not password:
            return jsonify({
                'success': False,
                'error': 'Password is required'
            }), 400
        
        generator = PasswordGenerator()
        memory_aid = generator.create_memory_aid(password)
        
        return jsonify({
            'success': True,
            'memory_aid': memory_aid
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@password_bp.route('/request-consultation', methods=['POST'])
def request_consultation():
    """Handle consultation requests"""
    try:
        data = request.json
        contact_preference = data.get('contact_preference', 'email')
        message = data.get('message', '')
        
        # In a real application, this would schedule a consultation
        consultation_info = {
            'consultation_requested': True,
            'contact_preference': contact_preference,
            'message': message,
            'estimated_response_time': '1-2 business days',
            'available_slots': [
                'Monday 10:00 AM - 12:00 PM',
                'Wednesday 2:00 PM - 4:00 PM',
                'Friday 9:00 AM - 11:00 AM'
            ],
            'temporary_security_recommendations': [
                'Enable any available two-factor authentication',
                'Set up email alerts for account access',
                'Avoid using the same password on other accounts',
                'Consider using the suggested security measures while waiting'
            ]
        }
        
        return jsonify({
            'success': True,
            'consultation_info': consultation_info,
            'message': 'Thank you for your consultation request! Our security team will contact you soon.'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400