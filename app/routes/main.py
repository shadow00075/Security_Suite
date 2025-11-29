from flask import Blueprint, render_template
from datetime import datetime

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html', 
                         current_time=datetime.now(),
                         title="Capstone Security Suite")

@main_bp.route('/about')
def about():
    """About page with information about the security suite"""
    return render_template('about.html', title="About")

@main_bp.route('/dashboard')
def dashboard():
    """Security dashboard with overview of all tools"""
    tools = [
        {
            'name': 'Password Strength Checker',
            'description': 'Check password strength with intelligent recommendations',
            'url': '/password/generator',
            'icon': '🔑'
        },
        {
            'name': 'System Information Analyzer',
            'description': 'Comprehensive system security and configuration analysis',
            'url': '/tools/system-info',
            'icon': '💻'
        },
        {
            'name': 'Password Breach Checker',
            'description': 'Check if passwords have been compromised in data breaches',
            'url': '/tools/breach-checker',
            'icon': '🔐'
        },
        {
            'name': 'Network Analyzer',
            'description': 'Analyze network traffic and connections',
            'url': '/tools/network-analyzer',
            'icon': '🌐'
        },
        {
            'name': 'Security Headers Checker',
            'description': 'Analyze HTTP security headers for web applications',
            'url': '/tools/security-headers',
            'icon': '🛡️'
        },
        {
            'name': 'QR Code Security Scanner',
            'description': 'Analyze QR codes for security threats and malicious content',
            'url': '/tools/qr-security',
            'icon': '📱'
        }
    ]
    
    return render_template('dashboard.html', 
                         tools=tools,
                         title="Security Dashboard")