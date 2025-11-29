#!/usr/bin/env python3
"""
Capstone Security Suite - Main Application Entry Point

A comprehensive web-based cybersecurity toolkit featuring:
- Intelligent password generation with security questionnaire
- Network port scanning and analysis
- Cryptographic hash generation and verification
- Network interface monitoring and analysis
- Vulnerability scanning for web applications and networks
- Anomaly-based intrusion detection system with machine learning

Author: CS 499D Capstone Project
Version: 4.0
"""

import os
import sys
import logging
from app import create_app
from config.settings import config

def setup_logging(app):
    """Set up application logging"""
    log_level = getattr(logging, app.config['LOG_LEVEL'], logging.INFO)
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(app.config['LOG_FILE'])
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(app.config['LOG_FILE']),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set up Flask app logger
    app.logger.setLevel(log_level)
    app.logger.info('Capstone Security Suite starting up...')

def main():
    """Main application entry point"""
    # Get configuration environment
    config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Create Flask application
    app = create_app()
    app.config.from_object(config.get(config_name, config['default']))
    
    # Set up logging
    setup_logging(app)
    
    # Get host and port from environment or use defaults
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    debug = app.config.get('DEBUG', False)
    
    app.logger.info(f'Starting server on {host}:{port}')
    app.logger.info(f'Debug mode: {debug}')
    app.logger.info(f'Configuration: {config_name}')
    
    try:
        # Run the application
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
    except KeyboardInterrupt:
        app.logger.info('Server stopped by user')
    except Exception as e:
        app.logger.error(f'Server error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()