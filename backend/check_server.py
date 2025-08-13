#!/usr/bin/env python3
"""
Simple script to check if the backend server is running and accessible
"""
import requests
import socket
from contextlib import closing

def check_port(host, port):
    """Check if a port is open"""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        return result == 0

def check_server():
    """Check server status"""
    ports_to_check = [5000, 5001, 5002, 5003, 8000]
    
    print("Checking backend server status...")
    print("-" * 40)
    
    for port in ports_to_check:
        print(f"Checking port {port}...", end=" ")
        
        if check_port('localhost', port):
            print("✓ OPEN")
            
            # Try to make HTTP request
            try:
                response = requests.get(f'http://localhost:{port}/', timeout=5)
                if response.status_code == 200:
                    print(f"  HTTP response: ✓ {response.json()}")
                else:
                    print(f"  HTTP response: ✗ Status {response.status_code}")
            except Exception as e:
                print(f"  HTTP request failed: {e}")
        else:
            print("✗ CLOSED")
    
    print("\nTo start the backend server:")
    print("cd /Users/aviasnani/Desktop/computer demo/cs-demo/repo/backend")
    print("python run.py")

if __name__ == "__main__":
    check_server()