# HasChecksum

[![Build Status](https://travis-ci.org/sshaw/has_checksum.svg?branch=master)](https://travis-ci.org/sshaw/has_checksum)

Automatically calculate checksums and signatures from the values of your class' attributes/methods

Works with POROs and ActiveRecord.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "has_checksum"
```

And then execute:

    bundle

Or install it yourself as:

    gem install has_checksum

## Usage

Use the [`has_checksum`](#has_checksum) and/or [`has_signature`](#has_signature) class methods to calculate checksums or signatures of your class' columns and/or methods' return values.

### `has_checksum`

```rb
class User
  include HasChecksum

  attr_accessor :username

  has_checksum :username
end

user = User.new
user.username = "sshaw"
user.username_checksum # 5b891e901f3c8859115dcdfe323944ec7b4abbde9f7b680430fca7d2c7af89e5
```

By default SHA256 is used.

Multiple attributes can be specified:

```rb
class User
  include HasChecksum

  attr_accessor :username
  attr_accessor :updated_at

  has_checksum :username, :updated_at
end

user = User.new
user.username = "sshaw"
user.updated_at = Time.now
user.username_updated_at_checksum # bf6bfb33a4927184eae61195afcff0b033b13da15d79629d513639717c06e15f
```

Use the`:method` and `:algorithm` arguments to change the method name and algorithm. Here we use an ActiveRecord subclass:

```rb
class User < ActiveRecord::Base
  include HasChecksum

  has_checksum :settings, :updated_at, :method => "settings_signature", :algorithm => "md5"
end

user.settings[:timezone] = "America/Los_Angeles"
user.save!
user.settings_signature # 4a390b8df412ab4168b9856291437bba
```

With ActiveRecord, if the generated method is a database column, the checksum will be persisted:

```
rails g migration add_settings_signature_to_users settings_signature:string  # should use char(N), really
```

`:algorithm` can also be a block:

```rb
class User < ActiveRecord::Base
  include HasChecksum

  has_checksum :settings, :updated_at, :algorithm => ->(value) { whirlpool(value) }
end
```

By default the checksum will be hex encoded but you can change this via `:encode`:

```rb
class User < ActiveRecord::Base
  include HasChecksum

  has_checksum :settings, :updated_at, :encode => "base64"  # or "binary" or "bubblebabble"
end
```

### `has_signature`

Calculates a hash-based message authentication code (HMAC).
This (mostly) works the same as [`has_checksum`](#has_checksum) but requires a `:key` argument that will be used as the HMAC's key:

```rb
class User < ActiveRecord::Base
  include HasChecksum

  has_signature :id, :created_at, :last_login_at, :key => :some_salt_column, :method => "session_id"
end
```

If `:key` is a `Symbol` it will treated as a method name. If it's a `String` is will be used literally, as the key.
It can also be a `Proc` that returns the key.

## See Also

[rspec-checksum-matchers](https://gist.github.com/sshaw/df14f6f89860b2dbcfd2)

## Author

Skye Shaw (skye.shaw -AT- gmail)

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
