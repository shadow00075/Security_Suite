"""
Network Information Tool
Provides basic network information and connectivity checks
"""
import socket
import platform
import subprocess
import requests
from typing import Dict, List
import time
import re

class NetworkInfoTool:
    """Simple network information and connectivity analyzer"""
    
    def __init__(self):
        self.system = platform.system().lower()
    
    def get_basic_info(self) -> Dict:
        """Get basic network information"""
        try:
            info = {
                'hostname': socket.gethostname(),
                'system': platform.system(),
                'local_ip': self._get_local_ip(),
                'public_ip': self._get_public_ip(),
                'dns_servers': self._get_dns_servers(),
                'network_status': 'Connected' if self._check_internet() else 'Disconnected'
            }
            
            return {
                'success': True,
                'data': info
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get network info: {str(e)}'
            }
    
    def ping_host(self, host: str, count: int = 4) -> Dict:
        """Ping a host and return results"""
        try:
            if not host:
                return {'success': False, 'error': 'No host specified'}
            
            # Clean the host input
            host = host.strip()
            if host.startswith(('http://', 'https://')):
                host = host.replace('http://', '').replace('https://', '')
                host = host.split('/')[0]
            
            if self.system == 'windows':
                cmd = ['ping', '-n', str(count), host]
            else:
                cmd = ['ping', '-c', str(count), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            output = result.stdout + result.stderr
            
            # Parse ping results
            success_count = 0
            response_times = []
            
            if self.system == 'windows':
                # Windows ping parsing
                if 'TTL=' in output:
                    lines = output.split('\n')
                    for line in lines:
                        if 'time=' in line:
                            success_count += 1
                            time_match = re.search(r'time=?(\d+)ms', line)
                            if time_match:
                                response_times.append(int(time_match.group(1)))
            else:
                # Linux/Mac ping parsing
                success_count = output.count('time=')
                times = re.findall(r'time=(\d+\.?\d*)\s*ms', output)
                response_times = [float(t) for t in times]
            
            packet_loss = ((count - success_count) / count) * 100
            
            ping_result = {
                'host': host,
                'packets_sent': count,
                'packets_received': success_count,
                'packet_loss_percent': packet_loss,
                'response_times': response_times,
                'avg_response_time': sum(response_times) / len(response_times) if response_times else 0,
                'status': 'Success' if success_count > 0 else 'Failed',
                'raw_output': output
            }
            
            return {
                'success': True,
                'data': ping_result
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Ping request timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Ping failed: {str(e)}'
            }
    
    def check_port(self, host: str, port: int) -> Dict:
        """Check if a specific port is open on a host"""
        try:
            if not host or not port:
                return {'success': False, 'error': 'Host and port required'}
            
            host = host.strip()
            if host.startswith(('http://', 'https://')):
                host = host.replace('http://', '').replace('https://', '')
                host = host.split('/')[0]
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((host, port))
            end_time = time.time()
            
            sock.close()
            
            is_open = result == 0
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            # Identify common services
            service = self._identify_service(port)
            
            port_result = {
                'host': host,
                'port': port,
                'status': 'Open' if is_open else 'Closed/Filtered',
                'response_time_ms': round(response_time, 2),
                'service': service,
                'timestamp': time.time()
            }
            
            return {
                'success': True,
                'data': port_result
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Port check failed: {str(e)}'
            }
    
    def speed_test(self) -> Dict:
        """Simple connection speed test"""
        try:
            test_urls = [
                'https://httpbin.org/bytes/1024',  # 1KB
                'https://httpbin.org/bytes/10240',  # 10KB
            ]
            
            results = []
            
            for url in test_urls:
                try:
                    start_time = time.time()
                    response = requests.get(url, timeout=10)
                    end_time = time.time()
                    
                    if response.status_code == 200:
                        size_kb = len(response.content) / 1024
                        duration = end_time - start_time
                        speed_kbps = size_kb / duration if duration > 0 else 0
                        
                        results.append({
                            'size_kb': round(size_kb, 2),
                            'duration_seconds': round(duration, 3),
                            'speed_kbps': round(speed_kbps, 2)
                        })
                except:
                    continue
            
            if results:
                avg_speed = sum(r['speed_kbps'] for r in results) / len(results)
                
                return {
                    'success': True,
                    'data': {
                        'tests': results,
                        'average_speed_kbps': round(avg_speed, 2),
                        'estimated_speed_mbps': round(avg_speed / 1024, 2),
                        'connection_quality': self._assess_speed(avg_speed)
                    }
                }
            else:
                return {
                    'success': False,
                    'error': 'Unable to perform speed test'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Speed test failed: {str(e)}'
            }
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except:
            return 'Unknown'
    
    def _get_public_ip(self) -> str:
        """Get public IP address"""
        try:
            response = requests.get('https://httpbin.org/ip', timeout=5)
            if response.status_code == 200:
                return response.json().get('origin', 'Unknown')
        except:
            pass
        return 'Unknown'
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers (simplified)"""
        try:
            if self.system == 'windows':
                result = subprocess.run(['nslookup', 'google.com'], 
                                      capture_output=True, text=True, timeout=10)
                output = result.stdout
                servers = re.findall(r'Server:\s+([\d\.]+)', output)
                return servers[:3] if servers else ['8.8.8.8']
            else:
                # For non-Windows systems
                return ['8.8.8.8', '1.1.1.1']
        except:
            return ['8.8.8.8']
    
    def _check_internet(self) -> bool:
        """Check if internet connection is available"""
        try:
            response = requests.get('https://httpbin.org/ip', timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def _identify_service(self, port: int) -> str:
        """Identify common services by port number"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL'
        }
        return common_ports.get(port, f'Unknown (Port {port})')
    
    def _assess_speed(self, speed_kbps: float) -> str:
        """Assess connection speed quality"""
        if speed_kbps > 1000:
            return 'Excellent'
        elif speed_kbps > 500:
            return 'Good'
        elif speed_kbps > 100:
            return 'Fair'
        else:
            return 'Poor'
    
    def get_demo_hosts(self) -> List[Dict]:
        """Get demonstration hosts for testing"""
        return [
            {'name': 'Google DNS', 'host': '8.8.8.8', 'description': 'Google public DNS server'},
            {'name': 'Cloudflare DNS', 'host': '1.1.1.1', 'description': 'Cloudflare public DNS'},
            {'name': 'Google', 'host': 'google.com', 'description': 'Google search engine'},
            {'name': 'GitHub', 'host': 'github.com', 'description': 'GitHub code repository'},
            {'name': 'Your Repository', 'host': 'github.com', 'description': 'Test connectivity to GitHub'}
        ]