"""
Start both servers: Auth Server (8000) and Client App (8001)
Usage: python run.py
"""
import subprocess
import sys
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))

server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "server.main:app", "--port", "8000", "--reload"],
    cwd=HERE,
)

time.sleep(1)

client = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "client.main:app", "--port", "8001", "--reload"],
    cwd=HERE,
)

print("\nOAuth2 Playground running:")
print("  Auth Server:  http://localhost:8000")
print("  Client App:   http://localhost:8001  <-- open this")
print("  Discovery:    http://localhost:8000/.well-known/openid-configuration")
print("\nCtrl+C to stop both servers\n")

try:
    server.wait()
except KeyboardInterrupt:
    server.terminate()
    client.terminate()
    print("\nStopped.")
