from flask import Blueprint, render_template, request, jsonify, session
from ids_system.anomaly_detector import IntrusionDetectionSystem, generate_sample_network_data, create_sample_alert_handler
import json
import threading
import time

ids_bp = Blueprint('ids', __name__)

# Global IDS instance
ids_system = IntrusionDetectionSystem()
recent_alerts = []
alert_lock = threading.Lock()

def alert_handler(alert):
    """Handle IDS alerts"""
    global recent_alerts
    with alert_lock:
        recent_alerts.append(alert)
        # Keep only last 50 alerts
        if len(recent_alerts) > 50:
            recent_alerts = recent_alerts[-50:]

# Register alert handler
ids_system.add_alert_handler(alert_handler)

@ids_bp.route('/dashboard')
def ids_dashboard():
    """IDS dashboard page"""
    return render_template('ids_dashboard.html', title="Intrusion Detection System")

@ids_bp.route('/status')
def ids_status():
    """Get IDS status and statistics"""
    try:
        stats = ids_system.get_statistics()
        
        global recent_alerts
        with alert_lock:
            current_alerts = recent_alerts.copy()
        
        return jsonify({
            'success': True,
            'status': stats,
            'recent_alerts': current_alerts[-10:],  # Last 10 alerts
            'total_alerts': len(current_alerts)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/train', methods=['POST'])
def train_ids():
    """Train IDS on sample or uploaded data"""
    try:
        data = request.json
        training_method = data.get('method', 'sample')
        
        if training_method == 'sample':
            # Generate sample normal traffic data
            sample_size = data.get('sample_size', 500)
            training_data = generate_sample_network_data(
                count=sample_size, 
                anomaly_rate=0.0  # Only normal data for training
            )
            
        elif training_method == 'upload':
            # Use uploaded training data
            training_data = data.get('training_data', [])
            
        elif training_method == 'current_buffer':
            # Use current buffer data as training data
            training_data = ids_system.get_recent_activity()
            
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid training method'
            }), 400
        
        # Train the system
        result = ids_system.train(training_data)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/start-monitoring', methods=['POST'])
def start_monitoring():
    """Start real-time monitoring"""
    try:
        data = request.json or {}
        
        # Ensure IDS is trained before starting monitoring
        if not hasattr(ids_system, '_is_trained') or not ids_system._is_trained:
            training_data = generate_sample_network_data(
                count=100, 
                anomaly_rate=0.1
            )
            
            # Train the IDS system
            training_result = ids_system.train_system(training_data)
            if not training_result.get('success', False):
                return jsonify({
                    'success': False, 
                    'error': 'Failed to train IDS system'
                }), 500
        
        # Configure monitoring if parameters provided
        config_updates = {}
        if 'detection_threshold' in data:
            config_updates['detection_threshold'] = float(data['detection_threshold'])
        if 'alert_threshold' in data:
            config_updates['alert_threshold'] = float(data['alert_threshold'])
        if 'monitoring_interval' in data:
            config_updates['monitoring_interval'] = float(data['monitoring_interval'])
        
        if config_updates:
            ids_system.load_config(config_updates)
        
        # Create sample data source for demonstration
        def sample_data_source():
            """Generate sample network data for monitoring"""
            import random
            if random.random() < 0.1:  # 10% chance of generating data each interval
                sample_data = generate_sample_network_data(count=1, anomaly_rate=0.3)
                return sample_data[0] if sample_data else None
            return None
        
        # Start monitoring
        result = ids_system.start_monitoring(data_source_callback=sample_data_source)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/stop-monitoring', methods=['POST'])
def stop_monitoring():
    """Stop real-time monitoring"""
    try:
        result = ids_system.stop_monitoring()
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/analyze-data', methods=['POST'])
def analyze_data():
    """Analyze a single data point"""
    try:
        data = request.json
        data_point = data.get('data_point', {})
        
        if not data_point:
            return jsonify({
                'success': False,
                'error': 'No data point provided'
            }), 400
        
        # Analyze the data point
        result = ids_system.analyze_data_point(data_point)
        
        return jsonify({
            'success': True,
            'analysis': result
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/simulate-attack', methods=['POST'])
def simulate_attack():
    """Simulate various attack scenarios for testing"""
    try:
        data = request.json or {}
        attack_type = data.get('attack_type', 'port_scan')
        duration = data.get('duration', 30)  # seconds
        
        # Generate attack simulation data
        attack_data = []
        
        if attack_type == 'port_scan':
            # Simulate port scanning attack
            for i in range(duration):
                attack_point = {
                    'timestamp': time.time() + i,
                    'src_ip': '192.168.1.100',
                    'dst_ip': '192.168.1.50',
                    'port': 22 + (i % 100),  # Scanning sequential ports
                    'protocol': 'tcp',
                    'packet_size': 64,
                    'connection_count': i,  # Increasing connections
                    'bytes_per_second': 1000,
                    'packets_per_second': 10,
                    'payload': f'scan_probe_{i}'
                }
                attack_data.append(attack_point)
                
        elif attack_type == 'ddos':
            # Simulate DDoS attack
            for i in range(duration):
                attack_point = {
                    'timestamp': time.time() + i,
                    'src_ip': f'10.0.{i%256}.{(i*7)%256}',  # Varying source IPs
                    'dst_ip': '192.168.1.50',
                    'port': 80,
                    'protocol': 'tcp',
                    'packet_size': 1500,
                    'connection_count': 1000 + i * 10,  # High connection count
                    'bytes_per_second': 1000000 + i * 50000,  # High bandwidth
                    'packets_per_second': 1000 + i * 50,
                    'payload': f'flood_data_{i}' * 100  # Large payload
                }
                attack_data.append(attack_point)
                
        elif attack_type == 'data_exfiltration':
            # Simulate data exfiltration
            for i in range(duration):
                attack_point = {
                    'timestamp': time.time() + i,
                    'src_ip': '192.168.1.25',
                    'dst_ip': f'203.0.113.{i%256}',  # External IP
                    'port': 443,
                    'protocol': 'https',
                    'packet_size': 8000 + (i * 100),  # Large outgoing packets
                    'connection_count': 1,
                    'bytes_per_second': 500000 + i * 10000,  # High outbound traffic
                    'packets_per_second': 50 + i,
                    'payload': f'encrypted_data_chunk_{i}'
                }
                attack_data.append(attack_point)
        
        # Analyze each attack data point
        analysis_results = []
        for attack_point in attack_data[:10]:  # Limit to first 10 for response
            result = ids_system.analyze_data_point(attack_point)
            analysis_results.append(result)
        
        return jsonify({
            'success': True,
            'attack_type': attack_type,
            'simulated_duration': duration,
            'sample_analyses': analysis_results,
            'total_data_points': len(attack_data)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/get-alerts')
def get_alerts():
    """Get recent alerts"""
    try:
        global recent_alerts
        with alert_lock:
            current_alerts = recent_alerts.copy()
        
        # Paginate if requested
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        paginated_alerts = current_alerts[start_idx:end_idx]
        
        return jsonify({
            'success': True,
            'alerts': paginated_alerts,
            'total': len(current_alerts),
            'page': page,
            'per_page': per_page,
            'has_next': end_idx < len(current_alerts),
            'has_prev': start_idx > 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/clear-alerts', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    try:
        global recent_alerts
        with alert_lock:
            cleared_count = len(recent_alerts)
            recent_alerts.clear()
        
        return jsonify({
            'success': True,
            'cleared_alerts': cleared_count
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/export-data', methods=['POST'])
def export_data():
    """Export IDS data (buffer or alerts)"""
    try:
        data = request.json or {}
        export_type = data.get('type', 'buffer')  # 'buffer' or 'alerts'
        
        if export_type == 'buffer':
            export_data = ids_system.get_recent_activity()
            filename = f'ids_buffer_data_{int(time.time())}.json'
        elif export_type == 'alerts':
            global recent_alerts
            with alert_lock:
                export_data = recent_alerts.copy()
            filename = f'ids_alerts_{int(time.time())}.json'
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid export type'
            }), 400
        
        return jsonify({
            'success': True,
            'data': export_data,
            'filename': filename,
            'count': len(export_data)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/configure', methods=['POST'])
def configure_ids():
    """Update IDS configuration"""
    try:
        data = request.json or {}
        
        # Validate configuration parameters
        valid_params = [
            'detection_threshold', 'alert_threshold', 'buffer_size',
            'training_data_size', 'monitoring_interval', 'max_alerts_per_minute',
            'enabled_detectors'
        ]
        
        config_updates = {}
        for param in valid_params:
            if param in data:
                config_updates[param] = data[param]
        
        if config_updates:
            ids_system.load_config(config_updates)
            
            return jsonify({
                'success': True,
                'updated_config': config_updates,
                'current_config': ids_system.config
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No valid configuration parameters provided'
            }), 400
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@ids_bp.route('/detector-info')
def detector_info():
    """Get information about available detectors"""
    try:
        detector_info = {
            'statistical': {
                'name': 'Statistical Anomaly Detector',
                'description': 'Uses statistical analysis (Z-score, IQR) to detect anomalies',
                'features': ['Z-score analysis', 'Interquartile Range detection', 'Multi-feature analysis'],
                'best_for': ['Numerical anomalies', 'Traffic volume changes', 'Timing anomalies']
            },
            'sequence': {
                'name': 'Sequence Pattern Detector', 
                'description': 'Detects unusual patterns in sequential network events',
                'features': ['Pattern recognition', 'Sequence analysis', 'Behavioral modeling'],
                'best_for': ['Protocol anomalies', 'Attack sequences', 'Behavioral changes']
            }
        }
        
        current_status = ids_system.get_statistics()
        
        return jsonify({
            'success': True,
            'available_detectors': detector_info,
            'current_status': current_status['detector_status'],
            'enabled_detectors': ids_system.config['enabled_detectors']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500