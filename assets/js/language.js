(() => {
  'use strict';

  const script = document.currentScript;
  const baseurl = script.dataset.baseurl;
  const currentLanguage = script.dataset.language;
  const defaultLanguage = script.dataset.defaultLanguage;
  const storageKey = 'site-language';
  const links = document.querySelectorAll('.language-switch [data-language]');
  const languages = Array.from(links, (link) => link.dataset.language);

  function remember(language) {
    try {
      localStorage.setItem(storageKey, language);
    } catch (_) {
      // Language links still work when browser storage is unavailable.
    }
  }

  links.forEach((link) => {
    // Heading IDs change with the translation; keep the reader on the same article.
    link.search = window.location.search;
    link.addEventListener('click', () => remember(link.dataset.language));
  });

  const target = new URL(window.location.href);
  const pathLanguage = target.pathname.slice(baseurl.length).split('/')[1];
  // GitHub Pages may serve the root 404 page for a missing translated URL.
  // Recognize its prefix so a saved choice cannot add /en/ repeatedly.
  if (languages.includes(pathLanguage) && pathLanguage !== defaultLanguage) {
    remember(pathLanguage);
    return;
  }

  // An explicit translated URL takes precedence over a previously saved choice.
  if (currentLanguage !== defaultLanguage) {
    remember(currentLanguage);
    return;
  }

  let preferredLanguage;
  try {
    preferredLanguage = localStorage.getItem(storageKey);
  } catch (_) {
    return;
  }

  if (!languages.includes(preferredLanguage) || preferredLanguage === currentLanguage) return;

  target.pathname = `${baseurl}/${preferredLanguage}${target.pathname.slice(baseurl.length)}`;
  target.hash = '';
  window.location.replace(target.href);
})();
