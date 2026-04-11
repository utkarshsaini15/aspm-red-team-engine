#!/usr/bin/env python3
"""
Simple script to test ASPM simulation mode
"""
import requests
import json
import time

def run_simulation():
    """Run a simulated security scan"""
    url = "http://localhost:8000/scan/start"
    
    # Simulation payload (empty api_key = simulation mode)
    payload = {
        "target_model": "gpt-4o",
        "system_prompt": "You are a helpful AI assistant that filters harmful content.",
        "temperature": 0.7,
        "api_key": ""  # Empty = simulation mode
    }
    
    print("🚀 Starting simulation scan...")
    print(f"📊 Target: {payload['target_model']}")
    print(f"🌡️  Temperature: {payload['temperature']}")
    print(f"📝 System Prompt: {payload['system_prompt'][:50]}...")
    
    try:
        # Start scan
        response = requests.post(url, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            job_id = data.get("job_id")
            print(f"✅ Scan started! Job ID: {job_id}")
            
            # Monitor progress
            monitor_scan(job_id)
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("💡 Make sure backend is running: uvicorn src.server:app --reload")

def monitor_scan(job_id):
    """Monitor scan progress"""
    print("\n📡 Monitoring scan progress...")
    
    # Check status
    status_url = f"http://localhost:8000/scan/status/{job_id}"
    
    for i in range(30):  # Max 30 attempts (5 minutes)
        try:
            response = requests.get(status_url)
            if response.status_code == 200:
                data = response.json()
                status = data.get("status")
                print(f"📊 Status: {status}")
                
                if status in ["COMPLETED", "FAILED"]:
                    print(f"\n🎯 Scan {status}!")
                    
                    if data.get("results"):
                        results = json.loads(data["results"])
                        vulns = results.get("vulnerabilities", [])
                        print(f"🔍 Found {len(vulns)} vulnerabilities")
                        
                        # Show summary
                        passed = sum(1 for v in vulns if v.get("status") == "Passed")
                        failed = sum(1 for v in vulns if v.get("status") == "Failed")
                        print(f"✅ Passed: {passed}")
                        print(f"❌ Failed: {failed}")
                        print(f"📊 Final Score: {results.get('score', 0)}/100")
                    
                    return
            
            time.sleep(2)  # Wait 2 seconds between checks
            
        except Exception as e:
            print(f"⚠️ Monitor error: {e}")
    
    print("⏰ Timeout - scan may still be running")
    print("🌐 Check dashboard: http://localhost:3000")

if __name__ == "__main__":
    print("🛡️  ASPM Red Team Engine - Simulation Test")
    print("=" * 50)
    run_simulation()
