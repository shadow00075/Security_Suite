import numpy as np
import pandas as pd
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import hashlib

class AnomalyDetector:
    """Base class for anomaly detection algorithms"""
    
    def __init__(self):
        self.is_trained = False
        self.baseline_stats = {}
    
    def train(self, normal_data: List[Dict]) -> None:
        """Train the detector on normal traffic data"""
        raise NotImplementedError
    
    def detect(self, data_point: Dict) -> Tuple[bool, float]:
        """Detect if a data point is anomalous. Returns (is_anomaly, confidence)"""
        raise NotImplementedError
    
    def get_feature_vector(self, data_point: Dict) -> List[float]:
        """Convert data point to feature vector"""
        raise NotImplementedError

class StatisticalAnomalyDetector(AnomalyDetector):
    """Statistical anomaly detector using Z-score and IQR methods"""
    
    def __init__(self, threshold: float = 3.0):
        super().__init__()
        self.threshold = threshold
        self.feature_stats = {}
    
    def train(self, normal_data: List[Dict]) -> None:
        """Train statistical models on normal data"""
        if not normal_data:
            return
        
        # Convert to feature vectors
        feature_vectors = [self.get_feature_vector(dp) for dp in normal_data]
        df = pd.DataFrame(feature_vectors)
        
        # Calculate statistics for each feature
        self.feature_stats = {
            'means': df.mean().to_dict(),
            'stds': df.std().to_dict(),
            'q25': df.quantile(0.25).to_dict(),
            'q75': df.quantile(0.75).to_dict(),
            'mins': df.min().to_dict(),
            'maxs': df.max().to_dict()
        }
        
        self.is_trained = True
    
    def detect(self, data_point: Dict) -> Tuple[bool, float]:
        """Detect anomaly using statistical methods"""
        if not self.is_trained:
            return False, 0.0
        
        feature_vector = self.get_feature_vector(data_point)
        anomaly_scores = []
        
        for i, value in enumerate(feature_vector):
            mean = self.feature_stats['means'].get(i, 0)
            std = self.feature_stats['stds'].get(i, 1)
            
            # Z-score based detection
            if std > 0:
                z_score = abs((value - mean) / std)
                anomaly_scores.append(z_score)
            
            # IQR based detection
            q25 = self.feature_stats['q25'].get(i, 0)
            q75 = self.feature_stats['q75'].get(i, 0)
            iqr = q75 - q25
            
            if iqr > 0:
                iqr_score = 0
                if value < q25 - 1.5 * iqr or value > q75 + 1.5 * iqr:
                    iqr_score = min(abs(value - q25) / iqr, abs(value - q75) / iqr)
                anomaly_scores.append(iqr_score)
        
        # Calculate overall anomaly confidence
        max_score = max(anomaly_scores) if anomaly_scores else 0
        avg_score = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0
        
        confidence = min((max_score + avg_score) / 2, 1.0)
        is_anomaly = max_score > self.threshold
        
        return is_anomaly, confidence
    
    def get_feature_vector(self, data_point: Dict) -> List[float]:
        """Extract numerical features from data point"""
        features = []
        
        # Network features
        features.append(data_point.get('packet_size', 0))
        features.append(data_point.get('port', 0))
        features.append(len(data_point.get('payload', '')))
        features.append(data_point.get('connection_count', 0))
        features.append(data_point.get('bytes_per_second', 0))
        features.append(data_point.get('packets_per_second', 0))
        
        # Time-based features
        timestamp = data_point.get('timestamp', time.time())
        hour_of_day = datetime.fromtimestamp(timestamp).hour
        day_of_week = datetime.fromtimestamp(timestamp).weekday()
        features.extend([hour_of_day, day_of_week])
        
        # Protocol features (convert to numerical)
        protocol = data_point.get('protocol', 'tcp').lower()
        protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3, 'http': 4, 'https': 5}
        features.append(protocol_map.get(protocol, 0))
        
        return features

class SequenceAnomalyDetector(AnomalyDetector):
    """Sequence-based anomaly detector for detecting unusual patterns"""
    
    def __init__(self, sequence_length: int = 10, threshold: float = 0.7):
        super().__init__()
        self.sequence_length = sequence_length
        self.threshold = threshold
        self.normal_sequences = set()
        self.sequence_frequencies = defaultdict(int)
    
    def train(self, normal_data: List[Dict]) -> None:
        """Train on sequence patterns"""
        if len(normal_data) < self.sequence_length:
            return
        
        # Extract sequence patterns
        for i in range(len(normal_data) - self.sequence_length + 1):
            sequence = self._extract_sequence_pattern(
                normal_data[i:i + self.sequence_length]
            )
            self.normal_sequences.add(sequence)
            self.sequence_frequencies[sequence] += 1
        
        self.is_trained = True
    
    def detect(self, data_point: Dict, context: List[Dict] = None) -> Tuple[bool, float]:
        """Detect anomaly based on sequence context"""
        if not self.is_trained or not context:
            return False, 0.0
        
        if len(context) < self.sequence_length:
            return False, 0.0
        
        # Check recent sequence
        recent_sequence = self._extract_sequence_pattern(
            context[-self.sequence_length:]
        )
        
        if recent_sequence in self.normal_sequences:
            # Calculate rarity score
            frequency = self.sequence_frequencies[recent_sequence]
            total_sequences = sum(self.sequence_frequencies.values())
            rarity = 1.0 - (frequency / total_sequences)
            
            is_anomaly = rarity > self.threshold
            return is_anomaly, rarity
        else:
            # Completely unknown sequence
            return True, 1.0
    
    def _extract_sequence_pattern(self, sequence: List[Dict]) -> str:
        """Extract a pattern signature from sequence"""
        pattern_elements = []
        
        for data_point in sequence:
            # Create a simple pattern based on key features
            pattern = {
                'protocol': data_point.get('protocol', 'unknown'),
                'port_range': self._get_port_range(data_point.get('port', 0)),
                'size_category': self._get_size_category(data_point.get('packet_size', 0)),
                'time_of_day': self._get_time_category(data_point.get('timestamp', time.time()))
            }
            pattern_elements.append(str(pattern))
        
        # Create hash of the sequence pattern
        sequence_str = '|'.join(pattern_elements)
        return hashlib.md5(sequence_str.encode()).hexdigest()[:16]
    
    def _get_port_range(self, port: int) -> str:
        """Categorize port into ranges"""
        if port < 1024:
            return 'system'
        elif port < 49152:
            return 'user'
        else:
            return 'dynamic'
    
    def _get_size_category(self, size: int) -> str:
        """Categorize packet size"""
        if size < 100:
            return 'small'
        elif size < 1500:
            return 'medium'
        else:
            return 'large'
    
    def _get_time_category(self, timestamp: float) -> str:
        """Categorize time of day"""
        hour = datetime.fromtimestamp(timestamp).hour
        if 6 <= hour < 12:
            return 'morning'
        elif 12 <= hour < 18:
            return 'afternoon'
        elif 18 <= hour < 22:
            return 'evening'
        else:
            return 'night'
    
    def get_feature_vector(self, data_point: Dict) -> List[float]:
        """Not used in sequence detector"""
        return []

class IntrusionDetectionSystem:
    """Main IDS class that coordinates different detection methods"""
    
    def __init__(self):
        self.detectors = {
            'statistical': StatisticalAnomalyDetector(),
            'sequence': SequenceAnomalyDetector()
        }
        self.is_monitoring = False
        self.monitoring_thread = None
        self.data_buffer = deque(maxlen=1000)
        self.alert_handlers = []
        self.config = self._load_default_config()
        self._start_time = time.time()
        
    def _load_default_config(self) -> Dict:
        """Load default IDS configuration"""
        return {
            'detection_threshold': 0.7,
            'alert_threshold': 0.8,
            'buffer_size': 1000,
            'training_data_size': 500,
            'monitoring_interval': 1.0,  # seconds
            'max_alerts_per_minute': 10,
            'enabled_detectors': ['statistical', 'sequence']
        }
    
    def load_config(self, config: Dict) -> None:
        """Load custom configuration"""
        self.config.update(config)
    
    def train(self, training_data: List[Dict]) -> Dict:
        """Train all detectors on normal traffic data"""
        results = {}
        
        if len(training_data) < self.config['training_data_size']:
            return {
                'success': False,
                'error': f'Insufficient training data. Need at least {self.config["training_data_size"]} samples.'
            }
        
        for detector_name in self.config['enabled_detectors']:
            if detector_name in self.detectors:
                try:
                    self.detectors[detector_name].train(training_data)
                    results[detector_name] = {
                        'status': 'trained',
                        'training_samples': len(training_data)
                    }
                except Exception as e:
                    results[detector_name] = {
                        'status': 'failed',
                        'error': str(e)
                    }
        
        return {
            'success': True,
            'results': results,
            'training_completed': datetime.now().isoformat()
        }
    
    def analyze_data_point(self, data_point: Dict) -> Dict:
        """Analyze a single data point for anomalies"""
        analysis_results = {
            'timestamp': data_point.get('timestamp', time.time()),
            'data_point': data_point,
            'detections': {},
            'overall_anomaly': False,
            'max_confidence': 0.0,
            'alert_level': 'none'
        }
        
        # Run enabled detectors
        for detector_name in self.config['enabled_detectors']:
            if detector_name in self.detectors:
                detector = self.detectors[detector_name]
                
                try:
                    if detector_name == 'sequence':
                        # Provide context for sequence detector
                        context = list(self.data_buffer)
                        is_anomaly, confidence = detector.detect(data_point, context)
                    else:
                        is_anomaly, confidence = detector.detect(data_point)
                    
                    analysis_results['detections'][detector_name] = {
                        'is_anomaly': is_anomaly,
                        'confidence': confidence,
                        'detector_type': detector_name
                    }
                    
                    # Update overall results
                    if is_anomaly:
                        analysis_results['overall_anomaly'] = True
                    
                    analysis_results['max_confidence'] = max(
                        analysis_results['max_confidence'], confidence
                    )
                    
                except Exception as e:
                    analysis_results['detections'][detector_name] = {
                        'error': str(e),
                        'detector_type': detector_name
                    }
        
        # Determine alert level
        max_conf = analysis_results['max_confidence']
        if max_conf >= self.config['alert_threshold']:
            analysis_results['alert_level'] = 'high'
        elif max_conf >= self.config['detection_threshold']:
            analysis_results['alert_level'] = 'medium'
        elif analysis_results['overall_anomaly']:
            analysis_results['alert_level'] = 'low'
        
        # Add to buffer
        self.data_buffer.append(data_point)
        
        return analysis_results
    
    def start_monitoring(self, data_source_callback=None) -> Dict:
        """Start real-time monitoring"""
        if self.is_monitoring:
            return {'success': False, 'error': 'Already monitoring'}
        
        self.is_monitoring = True
        
        def monitoring_loop():
            while self.is_monitoring:
                try:
                    # In a real implementation, this would get data from network interface
                    # For now, we'll use the callback if provided
                    if data_source_callback:
                        data_point = data_source_callback()
                        if data_point:
                            result = self.analyze_data_point(data_point)
                            
                            # Handle alerts
                            if result['alert_level'] != 'none':
                                self._handle_alert(result)
                    
                    time.sleep(self.config['monitoring_interval'])
                    
                except Exception as e:
                    print(f"Monitoring error: {e}")
                    time.sleep(1)
        
        self.monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        return {
            'success': True,
            'status': 'monitoring_started',
            'config': self.config
        }
    
    def stop_monitoring(self) -> Dict:
        """Stop real-time monitoring"""
        if not self.is_monitoring:
            return {'success': False, 'error': 'Not currently monitoring'}
        
        self.is_monitoring = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        return {
            'success': True,
            'status': 'monitoring_stopped'
        }
    
    def add_alert_handler(self, handler_func) -> None:
        """Add alert handler function"""
        self.alert_handlers.append(handler_func)
    
    def _handle_alert(self, detection_result: Dict) -> None:
        """Handle detected anomaly alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_level': detection_result['alert_level'],
            'confidence': detection_result['max_confidence'],
            'detections': detection_result['detections'],
            'source_data': detection_result['data_point']
        }
        
        # Call all alert handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")
    
    def get_statistics(self) -> Dict:
        """Get IDS statistics and status"""
        total_processed = len(self.data_buffer)
        
        detector_status = {}
        for name, detector in self.detectors.items():
            detector_status[name] = {
                'trained': detector.is_trained,
                'type': detector.__class__.__name__
            }
        
        return {
            'is_monitoring': self.is_monitoring,
            'total_data_points_processed': total_processed,
            'buffer_size': len(self.data_buffer),
            'detector_status': detector_status,
            'config': self.config,
            'uptime_seconds': self._get_uptime()
        }
    
    def get_status(self) -> Dict:
        """Get current IDS status (alias for get_statistics for compatibility)"""
        stats = self.get_statistics()
        return {
            'status': 'active' if self.is_monitoring else 'inactive',
            'monitoring': self.is_monitoring,
            'detectors_trained': all(d.is_trained for d in self.detectors.values()),
            'total_processed': stats['total_data_points_processed'],
            'buffer_usage': f"{stats['buffer_size']}/{stats['config']['buffer_size']}",
            'enabled_detectors': stats['config']['enabled_detectors'],
            'detection_threshold': stats['config']['detection_threshold'],
            'alert_threshold': stats['config']['alert_threshold']
        }
    
    def get_recent_activity(self, limit: int = 100) -> List[Dict]:
        """Get recent network activity from buffer"""
        return list(self.data_buffer)[-limit:]
    
    def export_training_data(self, file_path: str) -> Dict:
        """Export current buffer data for training"""
        try:
            training_data = list(self.data_buffer)
            
            with open(file_path, 'w') as f:
                json.dump(training_data, f, indent=2)
            
            return {
                'success': True,
                'exported_samples': len(training_data),
                'file_path': file_path
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def import_training_data(self, file_path: str) -> Dict:
        """Import training data from file"""
        try:
            with open(file_path, 'r') as f:
                training_data = json.load(f)
            
            return self.train(training_data)
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_uptime(self) -> float:
        """Get system uptime (placeholder)"""
        return time.time() - getattr(self, '_start_time', time.time())

# Example usage and testing functions
def generate_sample_network_data(count: int = 100, anomaly_rate: float = 0.1) -> List[Dict]:
    """Generate sample network data for testing"""
    import random
    
    data = []
    base_time = time.time() - (count * 60)  # Start from count minutes ago
    
    for i in range(count):
        # Generate normal traffic
        is_anomaly = random.random() < anomaly_rate
        
        if is_anomaly:
            # Generate anomalous data
            data_point = {
                'timestamp': base_time + (i * 60),
                'src_ip': f"192.168.1.{random.randint(1, 255)}",
                'dst_ip': f"10.0.0.{random.randint(1, 255)}",  # Unusual network
                'port': random.choice([1234, 4444, 31337]),  # Suspicious ports
                'protocol': random.choice(['tcp', 'udp']),
                'packet_size': random.randint(1400, 9000),  # Large packets
                'payload': 'suspicious_payload_' + ''.join(random.choices('abcdef0123456789', k=20)),
                'connection_count': random.randint(50, 200),  # High connection count
                'bytes_per_second': random.randint(1000000, 10000000),  # High bandwidth
                'packets_per_second': random.randint(1000, 5000)
            }
        else:
            # Generate normal data
            data_point = {
                'timestamp': base_time + (i * 60),
                'src_ip': f"192.168.1.{random.randint(1, 50)}",
                'dst_ip': f"192.168.1.{random.randint(1, 50)}",
                'port': random.choice([80, 443, 22, 25, 53]),  # Common ports
                'protocol': random.choice(['tcp', 'http', 'https']),
                'packet_size': random.randint(50, 1500),
                'payload': 'normal_payload_' + ''.join(random.choices('abcdef0123456789', k=10)),
                'connection_count': random.randint(1, 10),
                'bytes_per_second': random.randint(1000, 100000),
                'packets_per_second': random.randint(1, 100)
            }
        
        data.append(data_point)
    
    return data

def create_sample_alert_handler():
    """Create a sample alert handler for testing"""
    def alert_handler(alert: Dict):
        print(f"🚨 SECURITY ALERT [{alert['alert_level'].upper()}]")
        print(f"   Time: {alert['timestamp']}")
        print(f"   Confidence: {alert['confidence']:.2f}")
        print(f"   Source IP: {alert['source_data'].get('src_ip', 'unknown')}")
        print(f"   Destination: {alert['source_data'].get('dst_ip', 'unknown')}:{alert['source_data'].get('port', 'unknown')}")
        print(f"   Protocol: {alert['source_data'].get('protocol', 'unknown')}")
        print("   ---")
    
    return alert_handler