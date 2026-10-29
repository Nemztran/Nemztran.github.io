const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../assets/js/language.js'), 'utf8');

function load({ language = 'vi', saved = null, baseurl = '', pathname = '/posts/oauth-authentication/', search = '', hash = '', storageBlocked = false } = {}) {
  const storage = new Map(saved ? [['site-language', saved]] : []);
  const links = ['vi', 'en'].map((language) => ({
    dataset: { language },
    search: '',
    addEventListener(event, handler) { this[event] = handler; }
  }));
  let redirect;
  vm.runInNewContext(source, {
    URL,
    document: {
      currentScript: { dataset: { baseurl, language, defaultLanguage: 'vi' } },
      querySelectorAll: () => links
    },
    localStorage: {
      getItem(key) {
        if (storageBlocked) throw new Error('Storage blocked');
        return storage.get(key) ?? null;
      },
      setItem(key, value) {
        if (storageBlocked) throw new Error('Storage blocked');
        storage.set(key, value);
      }
    },
    window: { location: {
      href: `https://example.com${baseurl}${pathname}${search}${hash}`,
      search,
      replace(url) { redirect = url; }
    } }
  });
  return { links, storage, redirect };
}

test('Vietnamese remains the default for a new visitor', () => {
  assert.equal(load().redirect, undefined);
});

test('saved English opens the same article and keeps the query', () => {
  assert.equal(load({ saved: 'en', search: '?q=oauth', hash: '#old-heading' }).redirect,
    'https://example.com/en/posts/oauth-authentication/?q=oauth');
});

test('an explicit English URL takes precedence and remembers English', () => {
  const result = load({ language: 'en', saved: 'vi', pathname: '/en/about/' });
  assert.equal(result.redirect, undefined);
  assert.equal(result.storage.get('site-language'), 'en');
});

test('switching back to Vietnamese saves the new choice', () => {
  const result = load({ language: 'en', saved: 'en', search: '?q=oauth' });
  result.links[0].click();
  assert.equal(result.storage.get('site-language'), 'vi');
  assert.equal(result.links[0].search, '?q=oauth');
  assert.equal(load({ saved: 'vi' }).redirect, undefined);
});

test('redirects work under a project baseurl', () => {
  assert.equal(load({ saved: 'en', baseurl: '/blog' }).redirect,
    'https://example.com/blog/en/posts/oauth-authentication/');
});

test('invalid preferences are ignored', () => {
  assert.equal(load({ saved: 'fr' }).redirect, undefined);
});

test('a missing English URL cannot create a redirect loop through the root 404 page', () => {
  const result = load({ pathname: '/en/missing/', saved: 'en' });
  assert.equal(result.redirect, undefined);
  assert.equal(result.storage.get('site-language'), 'en');
});

test('language links keep working when storage is blocked', () => {
  const result = load({ storageBlocked: true });
  assert.equal(result.redirect, undefined);
  assert.doesNotThrow(() => result.links[1].click());
});
