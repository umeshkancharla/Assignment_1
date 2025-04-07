import os
from datetime import timedelta

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///cve.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # NVD API configuration
    NVD_API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    RESULTS_PER_PAGE = 2000  # Maximum allowed by NVD API
    SYNC_INTERVAL = timedelta(hours=24)  # Sync every 24 hours
    
    # Application configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true' 