import os
import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Flask settings
    DEBUG = False
    TESTING = False
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security headers
    SEND_FILE_MAX_AGE_DEFAULT = timedelta(hours=12)
    
    # Database (if needed in future)
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///security_suite.db'
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or 'logs/security_suite.log'
    
    # IDS Configuration
    IDS_CONFIG = {
        'detection_threshold': 0.7,
        'alert_threshold': 0.8,
        'buffer_size': 1000,
        'training_data_size': 500,
        'monitoring_interval': 1.0,
        'max_alerts_per_minute': 10,
        'enabled_detectors': ['statistical', 'sequence']
    }
    
    # Security Scanner Configuration
    SCANNER_CONFIG = {
        'max_threads': 100,
        'default_timeout': 5,
        'user_agent': 'Capstone-Security-Suite/1.0',
        'max_scan_targets': 1000
    }
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    
    # Disable some security features for development
    WTF_CSRF_ENABLED = False
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    # Enhanced security for production
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = 'https'
    
    # Logging
    LOG_LEVEL = 'WARNING'
    
class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}