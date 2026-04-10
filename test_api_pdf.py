import requests

r = requests.get('http://localhost:8000/scans/history')
h = r.json()
print(f"{len(h)} scans in history")

if not h:
    print("No scans found!")
    exit()

job_id = h[0]['job_id']
print(f"Testing job: {job_id}")

r2 = requests.get(f'http://localhost:8000/scan/report/{job_id}')
print(f"Status: {r2.status_code}")
ct = r2.headers.get("content-type", "unknown")
print(f"Content-Type: {ct}")
print(f"Size: {len(r2.content)} bytes")
print(f"First 20 bytes: {r2.content[:20]}")

with open("test_from_api.pdf", "wb") as f:
    f.write(r2.content)
print("Saved to test_from_api.pdf")
