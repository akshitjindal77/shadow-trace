import httpx
from bs4 import BeautifulSoup

url = 'https://html.duckduckgo.com/html/?q=test%40example.com+site%3Apastebin.com'
with httpx.Client(headers={'User-Agent': 'Mozilla/5.0'}, timeout=20.0) as client:
    response = client.get(url)
    print('status', response.status_code)
    soup = BeautifulSoup(response.text, 'html.parser')
    print('a.result__a count', len(soup.select('a.result__a')))
    for a in soup.select('a.result__a')[:5]:
        print('TITLE', a.get_text(strip=True))
        print('HREF', a.get('href'))
    print('FALLBACK anchors', len(soup.find_all('a', href=True)))
    print('first anchor', soup.find('a', href=True))
