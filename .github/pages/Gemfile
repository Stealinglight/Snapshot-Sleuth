source "https://rubygems.org"

# Jekyll core
gem "jekyll", "~> 4.3"

# Theme
gem "minima", "~> 2.5"

# Plugins - these are also listed in _config.yml
group :jekyll_plugins do
  gem "jekyll-feed", "~> 0.12"
  gem "jekyll-seo-tag", "~> 2.8"
  gem "jekyll-sitemap", "~> 1.4"
  gem "jekyll-relative-links", "~> 0.7"
end

# GitHub Pages compatibility (optional - use for deployment)
# Uncomment the following line if deploying to GitHub Pages
# gem "github-pages", group: :jekyll_plugins

# Windows and JRuby does not include zoneinfo files
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# Performance-booster for watching directories on Windows
gem "wdm", "~> 0.1.1", :platforms => [:mingw, :x64_mingw, :mswin]

# Lock http_parser.rb gem to v0.6.x on JRuby
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]

# For webrick (required for Ruby 3.0+)
gem "webrick", "~> 1.8"
