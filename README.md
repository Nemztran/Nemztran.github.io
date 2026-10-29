# Chirpy Starter

[![Gem Version](https://img.shields.io/gem/v/jekyll-theme-chirpy)][gem]&nbsp;
[![GitHub license](https://img.shields.io/github/license/cotes2020/chirpy-starter.svg?color=blue)][mit]

A minimal, ready-to-use template for creating a blog with the [**Chirpy**][chirpy] Jekyll theme. Get up and running in minutes with all critical files pre-configured.

## Why This Starter Exists

When installing Chirpy through [RubyGems.org][gem], Jekyll can only read a subset of theme files (`_data`, `_layouts`, `_includes`, `_sass`, `assets`) and limited `_config.yml` options from the gem. As a result, users cannot enjoy the full out-of-the-box experience that Chirpy offers.

To unlock all features, the following files must be present in your Jekyll site:

```shell
.
├── _config.yml
├── _plugins
├── _tabs
└── index.html
```

This starter bundles those files from the latest **Chirpy** release along with a [CD][CD] workflow, so you can start writing immediately.

## Usage

### English / Tiếng Việt

Blog hỗ trợ hai ngôn ngữ qua Jekyll Polyglot. Tiếng Việt dùng đường dẫn gốc,
tiếng Anh dùng tiền tố `/en/`. Nút **VI / EN** trong thanh bên chuyển sang cùng
trang ở ngôn ngữ còn lại và ghi nhớ lựa chọn trên trình duyệt.

- Bài gốc: `_posts/YYYY-MM-DD-slug.md`, đặt `lang: vi` trong front matter.
- Bản tiếng Anh: `_posts/en/YYYY-MM-DD-slug.md`, đặt `lang: en`. Giữ nguyên
  tên file, ngày đăng và permalink (nếu khai báo) để hai bản ghép đúng với nhau.
- Trang giới thiệu: `_tabs/about.md` và `_tabs/en/about.md`, cùng permalink `/about/`.
- Các nhãn giao diện dùng locale có sẵn của Chirpy; tagline và mô tả SEO nằm ở `_data/i18n.yml`.
- Nếu một bài mới chưa có bản dịch, Polyglot hiển thị bản tiếng Việt dự phòng.
  Nội dung bài viết được dịch và lưu trong repo, không dùng dịch vụ dịch tự động khi đọc.

Chạy `bundle install`, sau đó `bundle exec jekyll serve` để xem thử.
Build production bằng `JEKYLL_ENV=production bundle exec jekyll build`.

Check out the [theme's docs](https://github.com/cotes2020/jekyll-theme-chirpy/wiki).

## Contributing

This repository is automatically updated with new releases from the theme repository. If you encounter any issues or want to contribute to its improvement, please visit the [theme repository][chirpy] to provide feedback.

## License

This work is published under [MIT][mit] License.

[gem]: https://rubygems.org/gems/jekyll-theme-chirpy
[chirpy]: https://github.com/cotes2020/jekyll-theme-chirpy/
[CD]: https://en.wikipedia.org/wiki/Continuous_deployment
[mit]: https://github.com/cotes2020/chirpy-starter/blob/master/LICENSE
