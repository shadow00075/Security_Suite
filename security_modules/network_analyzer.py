import socket
import psutil
import netifaces
import subprocess
import platform
import time
import requests
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

class NetworkAnalyzer:
    """Network analysis and monitoring tools"""
    
    def __init__(self):
        self.system = platform.system().lower()
    
    def get_network_interfaces(self) -> Dict:
        """Get information about all network interfaces"""
        try:
            interfaces = {}
            
            for interface in netifaces.interfaces():
                try:
                    interface_info = {
                        'name': interface,
                        'addresses': {},
                        'status': 'unknown'
                    }
                    
                    # Get address families (IPv4, IPv6, MAC)
                    addrs = netifaces.ifaddresses(interface)
                    
                    # IPv4 addresses
                    if netifaces.AF_INET in addrs:
                        ipv4_info = addrs[netifaces.AF_INET][0]
                        interface_info['addresses']['ipv4'] = {
                            'address': ipv4_info.get('addr', 'N/A'),
                            'netmask': ipv4_info.get('netmask', 'N/A'),
                            'broadcast': ipv4_info.get('broadcast', 'N/A')
                        }
                    
                    # IPv6 addresses  
                    if netifaces.AF_INET6 in addrs:
                        ipv6_info = addrs[netifaces.AF_INET6][0]
                        interface_info['addresses']['ipv6'] = {
                            'address': ipv6_info.get('addr', 'N/A'),
                            'netmask': ipv6_info.get('netmask', 'N/A')
                        }
                    
                    # MAC address
                    if netifaces.AF_LINK in addrs:
                        mac_info = addrs[netifaces.AF_LINK][0]
                        interface_info['addresses']['mac'] = mac_info.get('addr', 'N/A')
                    
                    interfaces[interface] = interface_info
                
                except Exception as interface_error:
                    # Skip problematic interfaces but continue processing
                    interfaces[interface] = {
                        'name': interface,
                        'addresses': {},
                        'status': f'error: {str(interface_error)}'
                    }
                    continue
            
            # Get default gateway safely
            default_gateway = {}
            try:
                gateways = netifaces.gateways()
                if hasattr(gateways, 'get') and 'default' in gateways:
                    default_gateway = gateways.get('default', {})
            except Exception:
                default_gateway = {}
            
            return {
                'interfaces': interfaces,
                'default_gateway': default_gateway,
                'dns_servers': self._get_dns_servers()
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'interfaces': {}
            }
    
    def get_active_connections(self) -> Dict:
        """Get active network connections"""
        try:
            connections = []
            
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                    'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Get process info if PID is available
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        conn_info['process_name'] = process.name()
                        conn_info['process_exe'] = process.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info['process_name'] = 'Access Denied'
                
                connections.append(conn_info)
            
            # Group by protocol
            tcp_connections = [c for c in connections if c['type'] == 'TCP']
            udp_connections = [c for c in connections if c['type'] == 'UDP']
            
            return {
                'total_connections': len(connections),
                'tcp_connections': tcp_connections,
                'udp_connections': udp_connections,
                'summary': {
                    'tcp_count': len(tcp_connections),
                    'udp_count': len(udp_connections),
                    'listening': len([c for c in tcp_connections if c['status'] == 'LISTEN']),
                    'established': len([c for c in tcp_connections if c['status'] == 'ESTABLISHED'])
                }
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'connections': []
            }
    
    def get_network_statistics(self) -> Dict:
        """Get network I/O statistics"""
        try:
            # Get network stats
            net_io = psutil.net_io_counters(pernic=True)
            total_stats = psutil.net_io_counters()
            
            interface_stats = {}
            for interface, stats in net_io.items():
                interface_stats[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errors_in': stats.errin,
                    'errors_out': stats.errout,
                    'drops_in': stats.dropin,
                    'drops_out': stats.dropout
                }
            
            return {
                'total_stats': {
                    'bytes_sent': total_stats.bytes_sent,
                    'bytes_recv': total_stats.bytes_recv,
                    'packets_sent': total_stats.packets_sent,
                    'packets_recv': total_stats.packets_recv,
                    'errors_in': total_stats.errin,
                    'errors_out': total_stats.errout,
                    'drops_in': total_stats.dropin,
                    'drops_out': total_stats.dropout
                },
                'interface_stats': interface_stats
            }
            
        except Exception as e:
            return {
                'error': str(e)
            }
    
    def ping_host(self, host: str, count: int = 4) -> Dict:
        """Ping a host and return statistics"""
        try:
            # Determine ping command based on OS
            if self.system == 'windows':
                cmd = ['ping', '-n', str(count), host]
            else:
                cmd = ['ping', '-c', str(count), host]
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            end_time = time.time()
            
            output = result.stdout
            
            # Parse ping results (simplified)
            if result.returncode == 0:
                lines = output.split('\n')
                
                # Extract basic info (this is simplified parsing)
                packets_sent = count
                packets_received = 0
                min_time = float('inf')
                max_time = 0
                total_time = 0
                times = []
                
                for line in lines:
                    if 'time=' in line.lower() or 'zeit=' in line.lower():
                        packets_received += 1
                        # Simple time extraction (may need adjustment for different locales)
                        time_parts = line.split('time=')
                        if len(time_parts) > 1:
                            try:
                                time_str = time_parts[1].split()[0].rstrip('ms')
                                ping_time = float(time_str)
                                times.append(ping_time)
                                min_time = min(min_time, ping_time)
                                max_time = max(max_time, ping_time)
                                total_time += ping_time
                            except (ValueError, IndexError):
                                pass
                
                packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
                avg_time = total_time / packets_received if packets_received > 0 else 0
                
                return {
                    'host': host,
                    'packets_sent': packets_sent,
                    'packets_received': packets_received,
                    'packet_loss_percent': round(packet_loss, 2),
                    'min_time_ms': min_time if min_time != float('inf') else None,
                    'max_time_ms': max_time,
                    'avg_time_ms': round(avg_time, 2),
                    'total_time_seconds': round(end_time - start_time, 2),
                    'status': 'success',
                    'raw_output': output
                }
            else:
                return {
                    'host': host,
                    'status': 'failed',
                    'error': result.stderr or 'Ping failed',
                    'raw_output': output
                }
                
        except subprocess.TimeoutExpired:
            return {
                'host': host,
                'status': 'timeout',
                'error': 'Ping command timed out'
            }
        except Exception as e:
            return {
                'host': host,
                'status': 'error',
                'error': str(e)
            }
    
    def traceroute(self, host: str, max_hops: int = 30) -> Dict:
        """Perform traceroute to a host"""
        try:
            # Determine traceroute command based on OS
            if self.system == 'windows':
                cmd = ['tracert', '-h', str(max_hops), host]
            else:
                cmd = ['traceroute', '-m', str(max_hops), host]
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            end_time = time.time()
            
            return {
                'host': host,
                'max_hops': max_hops,
                'total_time_seconds': round(end_time - start_time, 2),
                'status': 'success' if result.returncode == 0 else 'failed',
                'raw_output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
            
        except subprocess.TimeoutExpired:
            return {
                'host': host,
                'status': 'timeout',
                'error': 'Traceroute command timed out'
            }
        except Exception as e:
            return {
                'host': host,
                'status': 'error',
                'error': str(e)
            }
    
    def dns_lookup(self, domain: str, record_type: str = 'A') -> Dict:
        """Perform DNS lookup"""
        try:
            import dns.resolver
            
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, record_type)
            
            records = []
            for rdata in answers:
                records.append(str(rdata))
            
            return {
                'domain': domain,
                'record_type': record_type,
                'records': records,
                'ttl': answers.rrset.ttl,
                'status': 'success'
            }
            
        except ImportError:
            # Fallback to basic socket resolution for A records
            if record_type.upper() == 'A':
                try:
                    ip = socket.gethostbyname(domain)
                    return {
                        'domain': domain,
                        'record_type': 'A',
                        'records': [ip],
                        'status': 'success',
                        'note': 'Basic resolution (install dnspython for full DNS features)'
                    }
                except socket.gaierror as e:
                    return {
                        'domain': domain,
                        'record_type': record_type,
                        'status': 'failed',
                        'error': str(e)
                    }
            else:
                return {
                    'domain': domain,
                    'record_type': record_type,
                    'status': 'failed',
                    'error': 'Install dnspython for advanced DNS lookups'
                }
        except Exception as e:
            return {
                'domain': domain,
                'record_type': record_type,
                'status': 'failed',
                'error': str(e)
            }
    
    def get_public_ip(self) -> Dict:
        """Get public IP address"""
        try:
            # Try multiple services
            services = [
                'https://api.ipify.org',
                'https://icanhazip.com',
                'https://ident.me'
            ]
            
            import urllib.request
            
            for service in services:
                try:
                    with urllib.request.urlopen(service, timeout=10) as response:
                        ip = response.read().decode().strip()
                        return {
                            'public_ip': ip,
                            'service_used': service,
                            'status': 'success'
                        }
                except:
                    continue
            
            return {
                'status': 'failed',
                'error': 'Could not determine public IP from any service'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def network_discovery(self, network: str = None) -> Dict:
        """Discover devices on local network"""
        try:
            if not network:
                # Auto-detect local network
                interfaces = self.get_network_interfaces()
                for interface_info in interfaces['interfaces'].values():
                    if 'ipv4' in interface_info['addresses']:
                        ipv4 = interface_info['addresses']['ipv4']
                        if ipv4['address'] and ipv4['address'].startswith('192.168.'):
                            # Simple network discovery for 192.168.x.0/24
                            base_ip = '.'.join(ipv4['address'].split('.')[:-1])
                            network = f"{base_ip}.0/24"
                            break
            
            if not network:
                return {
                    'status': 'failed',
                    'error': 'Could not determine network range'
                }
            
            # Simple ping sweep (for demonstration)
            base_ip = network.split('/')[0].rsplit('.', 1)[0]
            active_hosts = []
            
            def ping_host_simple(ip):
                try:
                    if self.system == 'windows':
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                              capture_output=True, text=True)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                              capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        return ip
                except:
                    pass
                return None
            
            # Scan first 50 IPs for demo (full scan would be too slow)
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(ping_host_simple, f"{base_ip}.{i}") 
                          for i in range(1, 51)]
                
                for future in futures:
                    result = future.result()
                    if result:
                        active_hosts.append(result)
            
            return {
                'network': network,
                'active_hosts': active_hosts,
                'scan_range': f"{base_ip}.1-50",
                'status': 'success',
                'note': 'Limited scan for demonstration (first 50 IPs)'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS server configuration"""
        try:
            dns_servers = []
            
            if self.system == 'windows':
                # Try using PowerShell to get DNS servers
                try:
                    result = subprocess.run([
                        'powershell', '-Command', 
                        'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            if line.strip() and '.' in line.strip():
                                dns_servers.append(line.strip())
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
                
                # Fallback: try ipconfig
                if not dns_servers:
                    try:
                        result = subprocess.run(['ipconfig', '/all'], 
                                              capture_output=True, text=True, timeout=10)
                        lines = result.stdout.split('\n')
                        for i, line in enumerate(lines):
                            if 'DNS Servers' in line and ':' in line:
                                # Get DNS server from same line
                                dns_part = line.split(':')[1].strip()
                                if dns_part and '.' in dns_part:
                                    dns_servers.append(dns_part)
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                        pass
                        
            else:
                # Linux/Unix - read /etc/resolv.conf
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                parts = line.split()
                                if len(parts) > 1:
                                    dns_servers.append(parts[1])
                except FileNotFoundError:
                    pass
            
            # Default fallback DNS servers if none found
            if not dns_servers:
                dns_servers = ['8.8.8.8', '8.8.4.4']  # Google DNS as fallback
            
            return dns_servers[:3]  # Limit to 3 DNS servers
            
        except Exception as e:
            return ['Unable to determine DNS servers']