#!/usr/bin/env python3
"""
SecureMFA - Multi-Factor Authentication System
Cryptography & Network Security Project

Run this file to start the application.
"""

import os
from app import create_app

app = create_app(os.environ.get('FLASK_ENV', 'development'))

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=app.config.get('DEBUG', False)
    )
