"""
Configuration management for the threat detection system.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration"""
    
    # AWS Configuration
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    AWS_LOG_GROUP_NAME = os.getenv('AWS_LOG_GROUP_NAME', '/aws/security/logs')
    
    # Azure Configuration
    AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
    AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
    AZURE_SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')
    AZURE_WORKSPACE_ID = os.getenv('AZURE_WORKSPACE_ID')
    
    # Application Settings
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # ML Model Settings
    MODEL_PATH = os.getenv('MODEL_PATH', './models/threat_detector.pkl')
    CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', 0.7))
    RETRAIN_INTERVAL = int(os.getenv('RETRAIN_INTERVAL', 86400))
    
    # Alert Settings
    ALERT_EMAIL = os.getenv('ALERT_EMAIL', 'security-team@example.com')
    SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
    HIGH_SEVERITY_THRESHOLD = float(os.getenv('HIGH_SEVERITY_THRESHOLD', 0.85))
    MEDIUM_SEVERITY_THRESHOLD = float(os.getenv('MEDIUM_SEVERITY_THRESHOLD', 0.65))
    
    # Dashboard Settings
    REFRESH_INTERVAL = int(os.getenv('REFRESH_INTERVAL', 5000))
    MAX_EVENTS_DISPLAY = int(os.getenv('MAX_EVENTS_DISPLAY', 100))
