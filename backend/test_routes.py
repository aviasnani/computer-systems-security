#!/usr/bin/env python3
"""
Quick test script to verify routes are working
"""

import requests
import json

# Test if server is running
try:
    response = requests.get('http://localhost:5000/')
    print(f"✅ Server is running: {response.json()}")
except Exception as e:
    print(f"❌ Server not running: {e}")
    exit(1)

# Test user routes
try:
    response = requests.get('http://localhost:5000/api/test')
    print(f"✅ User routes working: {response.json()}")
except Exception as e:
    print(f"❌ User routes not working: {e}")

# Test auth routes
try:
    response = requests.get('http://localhost:5000/api/auth/me')
    print(f"Auth route response: {response.status_code}")
except Exception as e:
    print(f"❌ Auth routes error: {e}")