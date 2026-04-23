import requests

urls = [
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://www.amazon.com/dp/B09V3KXJPB',
    'http://win-free-iphone15.xyz/claim?user=123456',
    'https://www.nsbm.ac.lk/students/portal'
]

for url in urls:
    r = requests.post('http://127.0.0.1:8000/scan-url', json={'url': url})
    d = r.json()
    status = d['overall_status']
    print(f'{status} | {url[:60]}')