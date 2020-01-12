require "spec_helper"
require "digest"

User = Struct.new(:username, :created_at, :age) do
  include HasChecksum

  has_checksum :username
  has_checksum :username, :created_at
  has_checksum :age, :method => "get_age_checksum"
  has_checksum :age, :username, :algorithm => "md5"
  has_checksum :created_at, :algorithm => "md5", :format => "base64"
  has_checksum :username, :method => "custom_checksum", :algorithm => -> (v) { v.chop }

  has_signature :username, :key => "xxx"
  has_signature :username, :created_at, :key => "xxx"
  has_signature :age, :key => "xxx", :method => "get_age_signature"
  has_signature :username, :key => :key_method, :method => "with_custom_key"

  def key_method
    "__key__"
  end
end

RSpec.describe HasChecksum do
  describe ".has_checksum" do
    context "given no configuration" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_checksum }
        }.to raise_error(ArgumentError, "config required")
      end
    end

    context "given an unknown algorithm" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_checksum :age, :algorithm => "x" }
        }.to raise_error(ArgumentError, "unknown algorithm 'x'")
      end
    end

    context "given an unknown attribute" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_checksum :username, :foo }
        }.to raise_error(ArgumentError, "cannot calculate using unknown method/attribute 'foo'")
      end
    end

    it "performs a SHA256 checksum on a single attribute" do
      expect(User.new).to respond_to(:username_checksum)
      expect(User.new("sshaw").username_checksum).to eq Digest::SHA256.hexdigest("sshaw")
    end

    it "performs a SHA256 checksum on multiple attributes" do
      t = Time.now
      expect(User.new).to respond_to(:username_created_at_checksum)
      expect(User.new("sshaw", t).username_created_at_checksum).to eq Digest::SHA256.hexdigest(["sshaw", t].join(""))
    end

    it "recalculates the checksum when the targeted attribute(s) change" do
      t = Time.now
      u = User.new("sshaw", t)
      expect(u.username_checksum).to eq Digest::SHA256.hexdigest("sshaw")

      u.username = "Foo"
      expect(u.username_checksum).to eq Digest::SHA256.hexdigest("Foo")

      expect(u.username_created_at_checksum).to eq Digest::SHA256.hexdigest(["Foo", t].join(""))

      u.created_at = nil
      expect(u.username_created_at_checksum).to eq Digest::SHA256.hexdigest(["Foo", nil].join(""))
    end

    it "allows the caller to define the checksum method" do
      expect(User.new).to respond_to(:get_age_checksum)
      expect(User.new(nil, nil, 10).get_age_checksum).to eq Digest::SHA256.hexdigest("10")
    end

    it "allows the caller to define the checksum algorithm" do
      expect(User.new("sshaw", nil, 10).age_username_checksum).to eq Digest::MD5.hexdigest([10, "sshaw"].join(""))
    end

    it "allows the caller to define the checksum format" do
      t = Time.now
      expect(User.new(nil, t).created_at_checksum).to eq Digest::MD5.base64digest(t.to_s)
    end

    it "allows the caller to provide a custom calculation via a proc" do
      expect(User.new("sshaw").custom_checksum).to eq "ssha"
    end
  end

  describe ".has_signature" do
    context "given no configuration" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_signature }
        }.to raise_error(ArgumentError, "config required")
      end
    end

    context "given no key" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_signature :age }
        }.to raise_error(ArgumentError, "key option required to calculate a signature")
      end
    end

    context "given an unknown algorithm" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_signature :age, :key => "x", :algorithm => "y" }
        }.to raise_error(ArgumentError, "unknown algorithm 'y'")
      end
    end

    context "given an unknown attribute" do
      it "raise an ArgumentError" do
        expect {
          Class.new(User) { has_signature :username, :foo, :key => "x" }
        }.to raise_error(ArgumentError, "cannot calculate using unknown method/attribute 'foo'")
      end
    end

    it "performs a SHA256 HMAC on a single attribute" do
      expect(User.new).to respond_to(:username_signature)

      hmac = OpenSSL::HMAC.new("xxx", "sha256")
      hmac << "sshaw"

      expect(User.new("sshaw").username_signature).to eq hmac.hexdigest
    end

    it "performs a SHA256 HMAC on a multiple attributes" do
      expect(User.new).to respond_to(:username_created_at_signature)

      hmac = OpenSSL::HMAC.new("xxx", "sha256")
      hmac << "sshaw"

      t = Time.now
      hmac << t.to_s

      expect(User.new("sshaw", t).username_created_at_signature).to eq hmac.hexdigest
    end

    it "allows the caller to define the signature method" do
      expect(User.new).to respond_to(:get_age_signature)

      hmac = OpenSSL::HMAC.new("xxx", "sha256")
      hmac << "10"

      expect(User.new(nil, nil, 10).get_age_signature).to eq hmac.hexdigest
    end

    it "allows the caller to define a method to return the HMAC key" do
      hmac = OpenSSL::HMAC.new("__key__", "sha256")
      hmac << "sshaw"

      expect(User.new("sshaw").with_custom_key).to eq hmac.hexdigest
    end

  end
end
