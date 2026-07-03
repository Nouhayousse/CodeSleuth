"""
Diagnostic réseau : vérifie si Python peut résoudre et joindre l'API Gemini,
indépendamment d'ADK. Aide à isoler si le problème est DNS, proxy, ou firewall.

Usage: python test_network.py
"""

import socket
import httpx

def test_dns():
    try:
        ip = socket.gethostbyname("generativelanguage.googleapis.com")
        print(f"[OK] DNS OK : generativelanguage.googleapis.com -> {ip}")
        return True
    except socket.gaierror as e:
        print(f"[ERROR] DNS FAILED : {e}")
        return False

def test_dns_general():
    try:
        ip = socket.gethostbyname("google.com")
        print(f"[OK] DNS general OK : google.com -> {ip}")
        return True
    except socket.gaierror as e:
        print(f"[ERROR] DNS general FAILED ALSO : {e}")
        print("   -> The problem is not specific to Google, it is your system/network DNS.")
        return False

def test_https_connection():
    try:
        r = httpx.get("https://generativelanguage.googleapis.com", timeout=10)
        print(f"[OK] HTTPS connection OK, status : {r.status_code}")
    except Exception as e:
        print(f"[ERROR] HTTPS connection FAILED : {e}")

if __name__ == "__main__":
    print("--- Test 1 : General DNS (google.com) ---")
    general_ok = test_dns_general()

    print("\n--- Test 2 : Specific Gemini API DNS ---")
    dns_ok = test_dns()

    if dns_ok:
        print("\n--- Test 3 : HTTPS Connection ---")
        test_https_connection()

    if not general_ok:
        print("\n>>> DIAGNOSTIC : Windows system DNS issue. Try changing your DNS")
        print(">>> (e.g. 8.8.8.8 / 1.1.1.1 in network settings) or disable VPN.")
    elif not dns_ok:
        print("\n>>> DIAGNOSTIC : Google works but not this subdomain.")
        print(">>> Check antivirus/firewall/proxy blocking this domain.")