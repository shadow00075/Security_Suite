import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

class PortScanner:
    """Network port scanner for security assessment"""
    
    def __init__(self):
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL',
            1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB', 8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT', 5000: 'UPnP', 135: 'RPC', 139: 'NetBIOS',
            445: 'SMB', 514: 'Syslog', 631: 'IPP', 161: 'SNMP', 162: 'SNMP-Trap'
        }
        
    def scan_port(self, target: str, port: int, timeout: float = 3) -> Dict:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            start_time = time.time()
            result = sock.connect_ex((target, port))
            end_time = time.time()
            
            sock.close()
            
            if result == 0:
                service = self.common_ports.get(port, 'Unknown')
                return {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'response_time': round((end_time - start_time) * 1000, 2)
                }
            else:
                return {
                    'port': port,
                    'status': 'closed',
                    'service': None,
                    'response_time': None
                }
                
        except socket.gaierror:
            return {
                'port': port,
                'status': 'error',
                'service': None,
                'response_time': None,
                'error': 'Host resolution failed'
            }
        except Exception as e:
            return {
                'port': port,
                'status': 'error',
                'service': None,
                'response_time': None,
                'error': str(e)
            }
    
    def scan_range(self, target: str, start_port: int, end_port: int, 
                   timeout: float = 3, max_threads: int = 100) -> List[Dict]:
        """Scan a range of ports"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, target, port, timeout): port
                for port in range(start_port, end_port + 1)
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result['status'] == 'open' or result['status'] == 'error':
                    results.append(result)
        
        return sorted(results, key=lambda x: x['port'])
    
    def scan_common_ports(self, target: str, timeout: float = 3) -> List[Dict]:
        """Scan common ports"""
        return self.scan_range(target, min(self.common_ports.keys()), 
                              max(self.common_ports.keys()), timeout)
    
    def quick_scan(self, target: str) -> Dict:
        """Quick scan of most common ports"""
        quick_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432]
        
        results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self.scan_port, target, port, 2): port
                for port in quick_ports
            }
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        open_ports = [r for r in results if r['status'] == 'open']
        closed_ports = [r for r in results if r['status'] == 'closed']
        error_ports = [r for r in results if r['status'] == 'error']
        
        return {
            'target': target,
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'closed_ports': len(closed_ports),
            'errors': error_ports,
            'scan_summary': {
                'total_scanned': len(results),
                'open': len(open_ports),
                'closed': len(closed_ports),
                'errors': len(error_ports)
            }
        }
    
    def get_service_info(self, port: int) -> Dict:
        """Get detailed service information for a port"""
        return {
            'port': port,
            'service': self.common_ports.get(port, 'Unknown'),
            'description': self._get_service_description(port),
            'security_notes': self._get_security_notes(port)
        }
    
    def _get_service_description(self, port: int) -> str:
        """Get service description"""
        descriptions = {
            21: 'File Transfer Protocol - Used for transferring files',
            22: 'Secure Shell - Encrypted remote access protocol',
            23: 'Telnet - Unencrypted remote access (deprecated)',
            25: 'Simple Mail Transfer Protocol - Email sending',
            53: 'Domain Name System - Name resolution service',
            80: 'Hypertext Transfer Protocol - Web traffic',
            135: 'Microsoft RPC - Remote Procedure Call service',
            139: 'NetBIOS Session Service - Windows file sharing',
            443: 'HTTPS - Encrypted web traffic',
            445: 'Server Message Block - Windows file sharing',
            3389: 'Remote Desktop Protocol - Windows remote desktop'
        }
        return descriptions.get(port, 'Service information not available')
    
    def _get_security_notes(self, port: int) -> List[str]:
        """Get security considerations for a port"""
        security_notes = {
            21: ['FTP sends credentials in plaintext', 'Consider SFTP or FTPS'],
            22: ['Generally secure if properly configured', 'Disable root login', 'Use key-based authentication'],
            23: ['Highly insecure - sends everything in plaintext', 'Should be disabled'],
            25: ['Can be exploited for spam relay', 'Ensure proper authentication'],
            53: ['Can be used for DNS amplification attacks', 'Restrict recursive queries'],
            80: ['Unencrypted web traffic', 'Should redirect to HTTPS'],
            135: ['Windows RPC can be exploited', 'Firewall if not needed'],
            139: ['Legacy NetBIOS can leak information', 'Disable if not needed'],
            443: ['Generally secure', 'Ensure strong TLS configuration'],
            445: ['SMB vulnerabilities exist', 'Keep systems updated'],
            3389: ['Target for brute force attacks', 'Use Network Level Authentication']
        }
        return security_notes.get(port, ['No specific security notes available'])