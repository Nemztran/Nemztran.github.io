from html.parser import HTMLParser
from pathlib import Path
import json
import re
import sys
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parent.parent
site = root / '_site'
baseurl = sys.argv[1] if len(sys.argv) > 1 else ''

class Page(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.tags = []
        self.feed(path.read_text(encoding='utf-8'))

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

checks = 0
for page_path in site.rglob('*.html'):
    page = Page(page_path)
    english = page_path.relative_to(site).parts[0] == 'en'
    language = 'en' if english else 'vi'
    content_language = next(attrs['lang'] for tag, attrs in page.tags if tag == 'html')
    # An untranslated post may legitimately use Vietnamese as the fallback.
    assert content_language in ({'vi', 'en'} if english else {'vi'}), page_path
    switch = [attrs for tag, attrs in page.tags if tag == 'a' and 'data-language' in attrs]
    assert len(switch) == 2, page_path
    assert [item['data-language'] for item in switch if item.get('aria-current') == 'true'] == [language], page_path
    for tag, attrs in page.tags:
        for attribute in ('href', 'src'):
            url = attrs.get(attribute, '')
            if not url.startswith('/') or url.startswith('//'):
                continue
            pathname = unquote(urlsplit(url).path)
            assert not baseurl or pathname.startswith(baseurl + '/'), (page_path, url)
            target = site / pathname.removeprefix(baseurl).lstrip('/')
            assert target.is_file() or (target / 'index.html').is_file(), (page_path, url)
    checks += 1

entry_count = None
for language, prefix in [('vi', ''), ('en', '/en')]:
    entries = json.loads((site / prefix.lstrip('/') / 'assets/js/data/search.json').read_text(encoding='utf-8'))
    if entry_count is None:
        entry_count = len(entries)
    assert len(entries) == entry_count
    assert all(entry['url'].startswith(baseurl + prefix + '/posts/') for entry in entries)
    homepage = (site / prefix.lstrip('/') / 'index.html').read_text(encoding='utf-8')
    assert f"json: '{baseurl}{prefix}/assets/js/data/search.json'" in homepage
    assert all(entry['title'] in homepage for entry in entries)

for original in (root / '_posts').glob('*.md'):
    translated = root / '_posts/en' / original.name
    if not translated.exists():
        continue
    before = original.read_text(encoding='utf-8')
    after = translated.read_text(encoding='utf-8')
    fences = r'^```[^\n]*\n.*?^```[^\n]*$'
    assert re.findall(fences, before, re.M | re.S) == re.findall(fences, after, re.M | re.S), original
    assert re.findall(r'!\[[^\]]*\]\(([^)]+)\)', before) == re.findall(r'!\[[^\]]*\]\(([^)]+)\)', after), original
    assert len(re.findall(r'^#{2,6} ', before, re.M)) == len(re.findall(r'^#{2,6} ', after, re.M)), original

assert not (site / 'vendor').exists(), 'Build tools should not be published'
print(f'PASS: {checks} localized HTML pages, search indexes, navigation, images, code blocks, and heading counts')
