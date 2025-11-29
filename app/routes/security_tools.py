from flask import Blueprint, render_template, request, jsonify
from security_modules.breach_checker import BreachChecker
from security_modules.network_analyzer import NetworkAnalyzer
from security_modules.system_info import SystemInfoTool
from security_modules.security_headers_checker import SecurityHeadersChecker
from security_modules.qr_security_scanner import QRCodeSecurityScanner

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

@security_bp.route('/security-headers')
def security_headers():
    """Security headers checker tool page"""
    return render_template('security_headers.html', title="Security Headers Checker")

@security_bp.route('/check-security-headers', methods=['POST'])
def check_security_headers():
    """Check HTTP security headers"""
    try:
        data = request.json
        target_url = data.get('url', '')
        
        if not target_url:
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400
        
        checker = SecurityHeadersChecker()
        result = checker.analyze_headers(target_url)
        
        # Return the result directly - no nested 'results' key needed for this endpoint
        return jsonify({
            'success': True, 
            'results': result
        })
        
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

@security_bp.route('/network-analyzer')
def network_analyzer():
    """Network analyzer tool page"""
    return render_template('network_analyzer.html', title="Network Analyzer")

@security_bp.route('/analyze-network', methods=['POST'])
def analyze_network():
    """Perform network analysis"""
    try:
        data = request.json
        analysis_type = data.get('type', 'interfaces')
        
        analyzer = NetworkAnalyzer()
        
        if analysis_type == 'interfaces':
            results = analyzer.get_network_interfaces()
        elif analysis_type == 'connections':
            results = analyzer.get_active_connections()
        elif analysis_type == 'statistics':
            results = analyzer.get_network_statistics()
        elif analysis_type == 'ping':
            host = data.get('host', '')
            count = data.get('count', 4)
            results = analyzer.ping_host(host, count)
        elif analysis_type == 'traceroute':
            host = data.get('host', '')
            results = analyzer.traceroute(host)
        elif analysis_type == 'dns':
            domain = data.get('domain', '')
            record_type = data.get('record_type', 'A')
            results = analyzer.dns_lookup(domain, record_type)
        elif analysis_type == 'public_ip':
            results = analyzer.get_public_ip()
        elif analysis_type == 'discovery':
            network = data.get('network', None)
            results = analyzer.network_discovery(network)
        else:
            raise ValueError('Invalid analysis type')
        
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

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