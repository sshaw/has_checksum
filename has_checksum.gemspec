lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "has_checksum/version"

Gem::Specification.new do |spec|
  spec.name          = "has_checksum"
  spec.version       = HasChecksum::VERSION
  spec.authors       = ["Skye Shaw"]
  spec.email         = ["skye.shaw@gmail.com"]

  spec.summary       = %q{Automatically calculate checksums and signatures from the values of your class' attributes/methods}
   spec.description  = %q{Automatically calculate checksums and signatures from the values of your ActiveRecord or POROs classes' attributes/methods}
  spec.homepage      = "https://github.com/sshaw/has_checksum"
  spec.license       = "MIT"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sshaw/has_checksum"
  spec.metadata["changelog_uri"] = "https://github.com/sshaw/has_checksum/Changes"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "appraisal"
  spec.add_development_dependency "activerecord"
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "~> 3.0"
end
