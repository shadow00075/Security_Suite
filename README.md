# Capstone Security Suite

A comprehensive web-based cybersecurity toolkit built with Python and Flask, featuring intelligent security tools and anomaly-based intrusion detection.

## Features

### 🔐 Smart Password Generator
- **Intelligent Recommendations**: Based on 10 security questions
- **Customizable Parameters**: Length, character sets, complexity
- **Strength Analysis**: Real-time password strength assessment
- **Multiple Algorithms**: Support for various hashing methods

### 🔍 Network Security Tools
- **Port Scanner**: Advanced port scanning with service detection
- **Hash Generator**: Multiple cryptographic hash algorithms (MD5, SHA family, bcrypt, HMAC)
- **Network Analyzer**: Interface monitoring, connection tracking, network discovery
- **Vulnerability Scanner**: Web application and network vulnerability assessment

### 🛡️ Intrusion Detection System (IDS)
- **Anomaly-Based Detection**: Machine learning powered threat detection
- **Multiple Detection Methods**: Statistical analysis and sequence pattern recognition
- **Real-Time Monitoring**: Live network traffic analysis
- **Extensible Architecture**: Easy to add custom detection algorithms
- **Alert Management**: Configurable alerting and notification system

### 📊 Web Dashboard
- **Centralized Control**: Single interface for all security tools
- **Real-Time Updates**: Live status monitoring and alerts
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Export Functionality**: Data export in multiple formats

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Setup Instructions

1. **Clone or download the project**
   ```bash
   cd "MSU 2024-2025/Fall 2025/CS 499D/Capstone Security Suite"
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up configuration (optional)**
   ```bash
   # Create .env file for environment variables
   copy .env.example .env  # Windows
   cp .env.example .env    # macOS/Linux
   
   # Edit .env file with your preferences
   ```

5. **Run the application**
   ```bash
   python run.py
   ```

6. **Access the application**
   - Open your web browser
   - Navigate to `http://127.0.0.1:5000`
   - Start using the security tools!

## Usage Guide

### Password Generator
1. Navigate to **Tools > Password Generator**
2. Complete the 10-question security assessment
3. Optionally set a custom password length
4. Click "Generate Password" to get personalized recommendations
5. Use the strength checker to analyze existing passwords

### Network Tools

#### Port Scanner
1. Go to **Tools > Port Scanner**
2. Enter target IP address or hostname
3. Select scan type (Quick, Common Ports, or Custom Range)
4. Review results with service identification and security notes

#### Hash Generator
1. Access **Tools > Hash Generator**
2. Enter text to hash or verify
3. Select algorithm (MD5, SHA-256, bcrypt, etc.)
4. Generate hashes or verify existing ones
5. Use HMAC for message authentication

#### Network Analyzer
1. Open **Tools > Network Analyzer**
2. Choose analysis type:
   - Network interfaces and configuration
   - Active connections and processes
   - Network statistics and traffic
   - Ping and traceroute utilities
   - DNS lookups and network discovery

#### Vulnerability Scanner
1. Navigate to **Tools > Vulnerability Scanner**
2. Enter target URL or IP address
3. Select scan type (Basic, Web, Network, SSL, or Comprehensive)
4. Review vulnerability report with risk assessment
5. Follow remediation recommendations

### Intrusion Detection System

#### Setup and Training
1. Go to **Intrusion Detection > Dashboard**
2. Train the system using sample data or import your own
3. Configure detection thresholds and parameters
4. Start monitoring for real-time threat detection

#### Monitoring and Alerts
- View real-time alerts and threat levels
- Analyze detection patterns and statistics
- Export data for further analysis
- Simulate attacks for testing

## Architecture

### Project Structure
```
Capstone Security Suite/
├── app/                          # Flask application
│   ├── routes/                   # URL routes and handlers
│   ├── static/                   # CSS, JS, images
│   ├── templates/                # HTML templates
│   └── __init__.py              # App factory
├── security_modules/             # Security tool modules
│   ├── password_generator.py     # Password generation logic
│   ├── port_scanner.py          # Network port scanning
│   ├── hash_generator.py        # Cryptographic functions
│   ├── network_analyzer.py      # Network analysis tools
│   └── vulnerability_scanner.py # Vulnerability assessment
├── ids_system/                   # Intrusion Detection System
│   └── anomaly_detector.py      # ML-based anomaly detection
├── config/                       # Configuration files
├── logs/                        # Application logs
└── requirements.txt             # Python dependencies
```

### Key Components

#### Password Generator
- **Security Questionnaire**: 10 targeted questions to assess user's security context
- **Recommendation Engine**: Analyzes responses to suggest optimal password parameters
- **Strength Calculator**: Multi-factor password strength assessment including entropy analysis
- **Alternative Generation**: Provides multiple password options

#### IDS System
- **Statistical Detector**: Uses Z-score and IQR methods for numerical anomaly detection
- **Sequence Detector**: Pattern recognition for behavioral analysis
- **Training Module**: Machine learning model training on normal traffic data
- **Alert System**: Configurable alerting with multiple severity levels

#### Security Scanners
- **Multi-threaded Scanning**: Efficient concurrent operations
- **Service Detection**: Identifies services running on open ports
- **Vulnerability Database**: Checks for common security issues
- **Risk Assessment**: Automated risk scoring and prioritization

## Configuration

### Environment Variables
Create a `.env` file to customize settings:

```bash
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
HOST=127.0.0.1
PORT=5000

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/security_suite.log

# Security Settings
SESSION_TIMEOUT=7200
MAX_SCAN_TARGETS=1000

# IDS Configuration
IDS_DETECTION_THRESHOLD=0.7
IDS_ALERT_THRESHOLD=0.8
IDS_BUFFER_SIZE=1000
```

### Application Settings
Modify `config/settings.py` for advanced configuration:

- Security thresholds
- Rate limiting
- Database settings (if needed)
- Logging configuration
- Scanner parameters

## Security Considerations

### For Administrators
- **Change Default Keys**: Update SECRET_KEY in production
- **Enable HTTPS**: Use SSL certificates for production deployment
- **Network Access**: Restrict access to authorized users only
- **Regular Updates**: Keep dependencies updated for security patches
- **Audit Logs**: Monitor application logs for suspicious activity

### For Users
- **Responsible Use**: Only scan networks and systems you own or have permission to test
- **Data Privacy**: Be mindful of sensitive information in logs and exports
- **Network Impact**: Use appropriate scan settings to avoid overwhelming targets
- **Legal Compliance**: Ensure all security testing complies with applicable laws

## Development

### Adding New Security Tools
1. Create module in `security_modules/`
2. Add route handler in `app/routes/`
3. Create HTML template in `app/templates/`
4. Update navigation in base template
5. Add tool to dashboard configuration

### Extending IDS System
1. Inherit from `AnomalyDetector` base class
2. Implement `train()` and `detect()` methods
3. Register detector in `IntrusionDetectionSystem`
4. Add configuration options
5. Update web interface

### Contributing
- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include unit tests for new features
- Update documentation
- Test thoroughly before committing

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# If pip install fails, try upgrading pip
python -m pip install --upgrade pip

# For Windows users having issues with bcrypt
pip install --only-binary=all bcrypt

# For missing system dependencies
# Ubuntu/Debian: sudo apt-get install python3-dev libffi-dev
# CentOS/RHEL: sudo yum install python3-devel libffi-devel
```

#### Permission Errors
```bash
# Port scanning requires appropriate permissions
# On Windows: Run as Administrator
# On macOS/Linux: Use sudo for low-numbered ports

# Network interface access
# Ensure user has appropriate network permissions
```

#### Performance Issues
- Reduce scan thread count for slower systems
- Increase timeouts for slow networks
- Limit scan ranges for better performance
- Monitor system resources during intensive operations

### Getting Help
- Check application logs in `logs/security_suite.log`
- Verify network connectivity for network tools
- Ensure target systems are accessible
- Review configuration settings
- Check Python and dependency versions

## License

This project is developed as part of CS 499D Capstone coursework. Please respect all applicable laws and regulations when using these security tools.

## Disclaimer

This software is intended for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning or testing any systems. The developers are not responsible for any misuse of these tools.

---

**Version**: 1.0.0  
**Last Updated**: October 2024  
**Python Requirements**: 3.8+  
**Platform Support**: Windows, macOS, Linux