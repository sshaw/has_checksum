require "spec_helper"
require "active_record"

ActiveRecord::Base.establish_connection(
  :adapter => "sqlite3",
  :database  => ":memory:"
)

ActiveRecord::Base.connection.create_table(:users, :force => true) do |t|
  t.string :username
  t.string :username_checksum
  t.string :a_checksum
  t.string :username_signature
  t.integer :age
  t.timestamps
end

ARUser = Class.new ActiveRecord::Base do
  self.table_name = "users"
  include HasChecksum

  has_checksum :username
  has_checksum :username, :created_at
  has_checksum :foo
  has_checksum :username, :method => :a_checksum, :algorithm => -> (v) { v.chop }

  has_signature :username, :key => :updated_at

  def foo
    "123"
  end
end

POROUser = Struct.new(:username, :created_at, :age) do
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
  has_signature :created_at, :key => "xxx", :algorithm => "md5"
  has_signature :username, :method => "custom_signature", :key => "xxx", :algorithm => -> (v) { v += "X" }

  def key_method
    "__key__"
  end
end


RSpec.describe HasChecksum do
  context "given a PORO" do
    describe ".has_checksum" do
      context "given no configuration" do
        it "raise an ArgumentError" do
          expect {
            Class.new(POROUser) { has_checksum }
          }.to raise_error(ArgumentError, "config required")
        end
      end

      context "given an unknown algorithm" do
        it "raise an ArgumentError" do
          expect {
            Class.new(POROUser) { has_checksum :age, :algorithm => "x" }
          }.to raise_error(ArgumentError, "unknown algorithm 'x'")
        end
      end

      it "performs a SHA256 checksum on a single attribute" do
        expect(POROUser.new).to respond_to(:username_checksum)
        expect(POROUser.new("sshaw").username_checksum).to eq Digest::SHA256.hexdigest("sshaw")
      end

      it "performs a SHA256 checksum on multiple attributes" do
        t = Time.now
        expect(POROUser.new).to respond_to(:username_created_at_checksum)
        expect(POROUser.new("sshaw", t).username_created_at_checksum).to eq Digest::SHA256.hexdigest(["sshaw", t].join(""))
      end

      it "recalculates the checksum when the targeted attribute(s) change" do
        t = Time.now
        u = POROUser.new("sshaw", t)
        expect(u.username_checksum).to eq Digest::SHA256.hexdigest("sshaw")

        u.username = "Foo"
        expect(u.username_checksum).to eq Digest::SHA256.hexdigest("Foo")

        expect(u.username_created_at_checksum).to eq Digest::SHA256.hexdigest(["Foo", t].join(""))

        u.created_at = nil
        expect(u.username_created_at_checksum).to eq Digest::SHA256.hexdigest(["Foo", nil].join(""))
      end

      it "allows the caller to define the checksum method" do
        expect(POROUser.new).to respond_to(:get_age_checksum)
        expect(POROUser.new(nil, nil, 10).get_age_checksum).to eq Digest::SHA256.hexdigest("10")
      end

      it "allows the caller to define the checksum algorithm" do
        expect(POROUser.new("sshaw", nil, 10).age_username_checksum).to eq Digest::MD5.hexdigest([10, "sshaw"].join(""))
      end

      it "allows the caller to define the checksum format" do
        t = Time.now
        expect(POROUser.new(nil, t).created_at_checksum).to eq Digest::MD5.base64digest(t.to_s)
      end

      it "allows the caller to provide a custom calculation via a proc" do
        expect(POROUser.new("sshaw").custom_checksum).to eq "ssha"
      end
    end

    describe ".has_signature" do
      context "given no configuration" do
        it "raise an ArgumentError" do
          expect {
            Class.new(POROUser) { has_signature }
          }.to raise_error(ArgumentError, "config required")
        end
      end

      context "given no key" do
        it "raise an ArgumentError" do
          expect {
            Class.new(POROUser) { has_signature :age }
          }.to raise_error(ArgumentError, "key option required to calculate a signature")
        end
      end

      context "given an unknown algorithm" do
        it "raise an ArgumentError" do
          expect {
            Class.new(POROUser) { has_signature :age, :key => "x", :algorithm => "y" }
          }.to raise_error(ArgumentError, "unknown algorithm 'y'")
        end
      end

      it "performs a SHA256 HMAC on a single attribute" do
        expect(POROUser.new).to respond_to(:username_signature)

        hmac = OpenSSL::HMAC.new("xxx", "sha256")
        hmac << "sshaw"

        expect(POROUser.new("sshaw").username_signature).to eq hmac.hexdigest
      end

      it "performs a SHA256 HMAC on a multiple attributes" do
        expect(POROUser.new).to respond_to(:username_created_at_signature)

        hmac = OpenSSL::HMAC.new("xxx", "sha256")
        hmac << "sshaw"

        t = Time.now
        hmac << t.to_s

        expect(POROUser.new("sshaw", t).username_created_at_signature).to eq hmac.hexdigest
      end

      it "allows the caller to define the signature method" do
        expect(POROUser.new).to respond_to(:get_age_signature)

        hmac = OpenSSL::HMAC.new("xxx", "sha256")
        hmac << "10"

        expect(POROUser.new(nil, nil, 10).get_age_signature).to eq hmac.hexdigest
      end

      it "allows the caller to define a method to return the HMAC key" do
        hmac = OpenSSL::HMAC.new("__key__", "sha256")
        hmac << "sshaw"

        expect(POROUser.new("sshaw").with_custom_key).to eq hmac.hexdigest
      end

      it "allows the caller to define the signature algorithm" do
        t = Time.now
        hmac = OpenSSL::HMAC.new("xxx", "md5")
        hmac << t.to_s

        expect(POROUser.new(nil, t).created_at_signature).to eq hmac.hexdigest
      end

      it "allows the caller to provide a custom calculation via a proc" do
        expect(POROUser.new("sshaw").custom_signature).to eq "sshawX"
      end
    end
  end

  context "given an ActiveRecord::Base subclass" do
    describe ".has_checksum" do
      it "performs a SHA256 checksum on a single attribute" do
        expect(ARUser.new).to respond_to(:username_checksum)
        expect(ARUser.new(:username => "sshaw").username_checksum).to eq Digest::SHA256.hexdigest("sshaw")
      end

      it "performs a SHA256 checksum on multiple attributes" do
        t = Time.now
        expect(ARUser.new).to respond_to(:username_created_at_checksum)
        expect(ARUser.new(:username => "sshaw", :created_at => t).username_created_at_checksum).to eq Digest::SHA256.hexdigest(["sshaw", t].join(""))
      end

      context "when the checksum method is not a database column" do
        it "does not attempt to insert the checksum into the database" do
          user = ARUser.new
          expect(user.foo_checksum).to eq Digest::SHA256.hexdigest("123")
          expect(user.save).to eq true
        end
      end

      context "when the checksum method is a database column" do
        it "inserts the checksum to the database when the record is saved" do
          user = ARUser.create!(:username => "sshaw")
          value = ARUser.connection.select_value("select username_checksum from users where id = #{user.id}")
          expect(value).to eq Digest::SHA256.hexdigest("sshaw")
        end

        it "updates the checksum in the database when the record is updated" do
          user = ARUser.create!(:username => "sshaw")
          user.update!(:username => "fofinha")

          value = ARUser.connection.select_value("select username_checksum from users where id = #{user.id}")
          expect(value).to eq Digest::SHA256.hexdigest("fofinha")
        end

        context "and :algorithm is provided via a Proc" do
          it "inserts the checksum to the database when the record is saved" do
            user = ARUser.create!(:username => "sshaw")
            value = ARUser.connection.select_value("select a_checksum from users where id = #{user.id}")
            expect(value).to eq "ssha"
          end

          it "updates the checksum in the database when the record is updated" do
            user = ARUser.create!(:username => "sshaw")
            user.update!(:username => "fofinha")

            value = ARUser.connection.select_value("select a_checksum from users where id = #{user.id}")
            expect(value).to eq "fofinh"
          end
        end
      end
    end

    describe ".has_signature" do
      context "when the key is the updated_at column" do
        it "recalculates the checksum when the record is updated" do
          user = ARUser.create!(:username => "sshaw")

          hmac = OpenSSL::HMAC.new(user.updated_at.to_s, "sha256")
          hmac << "sshaw"

          value = ARUser.connection.select_value("select username_signature from users where id = #{user.id}")
          expect(value).to eq hmac.hexdigest

          user.update!(:age => 99)

          hmac = OpenSSL::HMAC.new(user.updated_at.to_s, "sha256")
          hmac << "sshaw"

          value = ARUser.connection.select_value("select username_signature from users where id = #{user.id}")
          expect(value).to eq hmac.hexdigest
        end
      end
    end
  end
end
