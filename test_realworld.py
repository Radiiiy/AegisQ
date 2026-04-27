import requests

urls = [
    'https://www.facebook.com/login',
    'https://accounts.google.com/signin/verify',
    'https://www.paypal.com/signin',
    'https://www.dialog.lk/secure-payment',
    'http://free-gift-winner.xyz/claim/reward/12345',
    'https://www.ndbbank.com/account/update'
]

for url in urls:
    r = requests.post('http://127.0.0.1:8000/scan-url', json={'url': url})
    d = r.json()
    status = d['overall_status']
    print(f'{status} | {url[:65]}')