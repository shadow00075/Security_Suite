"""
System Information Tool
Provides comprehensive system and security information for security assessments
"""
import platform
import psutil
import socket
import os
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Optional

class SystemInfoTool:
    """System information analyzer for security assessment"""
    
    def __init__(self):
        self.system = platform.system().lower()
    
    def get_comprehensive_info(self) -> Dict:
        """Get comprehensive system information"""
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'system_info': self._get_system_info(),
                'hardware_info': self._get_hardware_info(),
                'network_info': self._get_network_summary(),
                'security_info': self._get_security_info(),
                'process_info': self._get_process_summary(),
                'disk_info': self._get_disk_info(),
                'recommendations': self._get_security_recommendations()
            }
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_system_info(self) -> Dict:
        """Get basic system information"""
        try:
            return {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'architecture': platform.architecture(),
                'hostname': socket.gethostname(),
                'python_version': platform.python_version(),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'uptime_hours': round((datetime.now().timestamp() - psutil.boot_time()) / 3600, 2)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_hardware_info(self) -> Dict:
        """Get hardware information"""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A',
                'usage_percent': psutil.cpu_percent(interval=1)
            }
            
            memory_info = {
                'total': self._format_bytes(memory.total),
                'available': self._format_bytes(memory.available),
                'used': self._format_bytes(memory.used),
                'percentage': memory.percent
            }
            
            disk_info = {
                'total': self._format_bytes(disk.total),
                'used': self._format_bytes(disk.used),
                'free': self._format_bytes(disk.free),
                'percentage': round((disk.used / disk.total) * 100, 2)
            }
            
            return {
                'cpu': cpu_info,
                'memory': memory_info,
                'disk': disk_info
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_network_summary(self) -> Dict:
        """Get network configuration summary"""
        try:
            # Get active network interfaces
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                if_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        if_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                    elif addr.family == socket.AF_INET6:  # IPv6
                        if_info['addresses'].append({
                            'type': 'IPv6',
                            'address': addr.address
                        })
                if if_info['addresses']:
                    interfaces.append(if_info)
            
            # Get network stats
            net_io = psutil.net_io_counters()
            stats = {
                'bytes_sent': self._format_bytes(net_io.bytes_sent),
                'bytes_recv': self._format_bytes(net_io.bytes_recv),
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
            
            return {
                'interfaces': interfaces[:5],  # Limit to first 5 interfaces
                'network_stats': stats,
                'active_connections': len(psutil.net_connections())
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_security_info(self) -> Dict:
        """Get security-related information"""
        try:
            # Check for common security software processes
            security_processes = []
            security_keywords = ['antivirus', 'firewall', 'defender', 'security', 'protection']
            
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(keyword in proc_name for keyword in security_keywords):
                        security_processes.append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check Windows Defender status (Windows only)
            defender_status = 'Unknown'
            if self.system == 'windows':
                try:
                    result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and 'True' in result.stdout:
                        defender_status = 'Active'
                    else:
                        defender_status = 'Inactive/Unknown'
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    defender_status = 'Cannot determine'
            
            # Check for admin/root privileges
            is_admin = False
            try:
                if self.system == 'windows':
                    is_admin = psutil.Process().as_dict(['username'])['username'].endswith('Administrator') or os.access('C:\\Windows\\System32', os.W_OK)
                else:
                    is_admin = os.geteuid() == 0
            except:
                pass
            
            return {
                'security_processes': list(set(security_processes))[:10],  # Remove duplicates, limit to 10
                'windows_defender_status': defender_status,
                'running_as_admin': is_admin,
                'firewall_status': self._check_firewall_status()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_process_summary(self) -> Dict:
        """Get running process summary"""
        try:
            process_count = len(psutil.pids())
            
            # Get top 5 processes by CPU usage
            processes = []
            for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage and get top 5
            top_cpu = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:5]
            
            return {
                'total_processes': process_count,
                'top_cpu_processes': top_cpu
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_disk_info(self) -> Dict:
        """Get disk usage information"""
        try:
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'filesystem': partition.fstype,
                        'total': self._format_bytes(usage.total),
                        'used': self._format_bytes(usage.used),
                        'free': self._format_bytes(usage.free),
                        'percentage': round((usage.used / usage.total) * 100, 2)
                    })
                except (PermissionError, OSError):
                    continue
            
            return {'disks': disks[:5]}  # Limit to 5 disks
        except Exception as e:
            return {'error': str(e)}
    
    def _check_firewall_status(self) -> str:
        """Check firewall status"""
        try:
            if self.system == 'windows':
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    if 'State                                 ON' in result.stdout:
                        return 'Active'
                    else:
                        return 'Inactive'
            else:
                # Try to check iptables or ufw for Linux/Unix
                result = subprocess.run(['which', 'ufw'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    ufw_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
                    if 'Status: active' in ufw_result.stdout:
                        return 'Active (UFW)'
                    else:
                        return 'Inactive (UFW)'
            return 'Unknown'
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return 'Cannot determine'
    
    def _get_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on system info"""
        recommendations = []
        
        try:
            # Memory usage check
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                recommendations.append("High memory usage detected. Consider closing unnecessary applications.")
            
            # Disk usage check
            disk = psutil.disk_usage('/')
            if (disk.used / disk.total) > 0.90:
                recommendations.append("Low disk space. Clean up unnecessary files for better security.")
            
            # Admin privileges check
            try:
                if self.system == 'windows':
                    is_admin = os.access('C:\\Windows\\System32', os.W_OK)
                else:
                    is_admin = os.geteuid() == 0
                
                if is_admin:
                    recommendations.append("Running with admin privileges. Use standard user account for daily tasks.")
            except:
                pass
            
            # Network connections check
            connections = psutil.net_connections()
            if len(connections) > 100:
                recommendations.append("High number of network connections. Review active connections for suspicious activity.")
            
            # Default recommendations
            recommendations.extend([
                "Regularly update your operating system and software",
                "Use strong, unique passwords for all accounts",
                "Enable firewall protection",
                "Keep antivirus software updated",
                "Regular system backups are recommended"
            ])
            
        except Exception:
            # Fallback recommendations if analysis fails
            recommendations = [
                "Regularly update your operating system and software",
                "Use strong, unique passwords for all accounts",
                "Enable firewall protection",
                "Keep antivirus software updated",
                "Regular system backups are recommended"
            ]
        
        return recommendations
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def get_quick_summary(self) -> Dict:
        """Get a quick system summary for dashboard"""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'system': f"{platform.system()} {platform.release()}",
                'memory_usage': f"{memory.percent}%",
                'disk_usage': f"{round((disk.used / disk.total) * 100, 1)}%",
                'cpu_usage': f"{psutil.cpu_percent(interval=1)}%",
                'uptime': f"{round((datetime.now().timestamp() - psutil.boot_time()) / 3600, 1)} hours",
                'active_processes': len(psutil.pids())
            }
        except Exception as e:
            return {'error': str(e)}