from flask import Blueprint, render_template, request, jsonify
from security_modules.breach_checker import BreachChecker
from security_modules.system_info import SystemInfoTool
from security_modules.qr_security_scanner import QRCodeSecurityScanner
from security_modules.url_safety_checker import URLSafetyChecker
from security_modules.network_info import NetworkInfoTool

security_bp = Blueprint('security', __name__)

@security_bp.route('/system-info')
def system_info():
    """System information analyzer tool page"""
    return render_template('system_info.html', title="System Information Analyzer")

@security_bp.route('/analyze-system', methods=['POST'])
def analyze_system():
    """Perform system information analysis"""
    try:
        analyzer = SystemInfoTool()
        result = analyzer.get_comprehensive_info()
        
        return jsonify({'success': True, 'results': result})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@security_bp.route('/url-safety')
def url_safety():
    """URL safety checker tool page"""
    return render_template('url_safety.html', title="URL Safety Checker")

@security_bp.route('/analyze-url-safety', methods=['POST'])
def analyze_url_safety():
    """Check URL safety and security"""
    try:
        data = request.json
        target_url = data.get('url', '')
        
        if not target_url:
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400
        
        checker = URLSafetyChecker()
        result = checker.analyze_url(target_url)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@security_bp.route('/network-info')
def network_info():
    """Network information tool page"""
    return render_template('network_info.html', title="Network Information Tool")

@security_bp.route('/network-info', methods=['POST'])
def analyze_network_info():
    """Perform network information analysis"""
    try:
        data = request.json
        analysis_type = data.get('analysis_type', 'basic_info')
        
        analyzer = NetworkInfoTool()
        
        if analysis_type == 'basic_info':
            results = analyzer.get_basic_info()
        elif analysis_type == 'ping':
            host = data.get('host', '')
            count = data.get('count', 4)
            results = analyzer.ping_host(host, count)
        elif analysis_type == 'port_check':
            host = data.get('host', '')
            port = data.get('port', 80)
            results = analyzer.check_port(host, port)
        elif analysis_type == 'speed_test':
            results = analyzer.speed_test()
        else:
            raise ValueError('Invalid analysis type')
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@security_bp.route('/breach-checker')
def breach_checker():
    """Password breach checker tool page"""
    return render_template('breach_checker.html', title="Password Breach Checker")

@security_bp.route('/check-breach', methods=['POST'])
def check_breach():
    """Check if password has been breached"""
    try:
        data = request.json
        password = data.get('password', '')
        
        checker = BreachChecker()
        result = checker.check_password_breach(password)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@security_bp.route('/qr-security')
def qr_security():
    """QR code security scanner tool page"""
    return render_template('qr_security.html', title="QR Code Security Scanner")

@security_bp.route('/analyze-qr-security', methods=['POST'])
def analyze_qr_security():
    """Perform QR code security analysis"""
    try:
        data = request.json
        qr_content = data.get('qr_content', '')
        analysis_type = data.get('analysis_type', 'text')
        
        if not qr_content:
            return jsonify({'success': False, 'error': 'QR code content is required'}), 400
        
        scanner = QRCodeSecurityScanner()
        
        # For demo purposes, we'll analyze text input rather than actual image processing
        results = scanner.analyze_qr_from_text(qr_content)
        
        # Handle error case
        if not results.get('success', True) and 'error' in results:
            return jsonify({'success': False, 'error': results['error']}), 400
        
        return jsonify({
            'success': True, 
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400