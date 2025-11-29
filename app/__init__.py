from flask import Flask
from config.settings import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Import blueprints
    from app.routes.main import main_bp
    from app.routes.password_gen import password_bp
    from app.routes.security_tools import security_bp
    
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(password_bp, url_prefix='/password')
    app.register_blueprint(security_bp, url_prefix='/tools')
    
    return app