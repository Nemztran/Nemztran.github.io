# Keep theme metadata in the same language as the localized content.
Jekyll::Hooks.register :site, :post_read do |site|
  language = site.config['active_lang'] || site.config['lang']
  strings = site.data.dig('i18n', language)
  next unless strings

  %w[tagline description].each do |key|
    site.config[key] = strings[key]
  end
end
