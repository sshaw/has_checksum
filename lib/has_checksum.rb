require "has_checksum/version"

require "openssl"
require "digest"

module HasChecksum
  def self.included(klass)
    klass.extend ClassMethods
    klass.class_eval do

      private

      def digest_string(methods)
        methods.map { |name| public_send(name) }.join("")
      end

      def calculate_signature(digest, value, options = {})
        key = case options[:key]
              when Symbol
                raise "key option refers to an unknown method '#{options[:key]}'" unless respond_to?(options[:key])
                send(options[:key])
              when Proc
                options[:key][]
              else
                options[:key]
              end

        hmac = OpenSSL::HMAC.new(key.to_s, digest)
        hmac << value

        case options[:format]
        when :binary, "binary"
          hmac.digest
        else
          hmac.hexdigest
        end
      end

      def calculate_checksum(klass, value, options = {})
        case options[:format]
        when :binary, "binary"
          klass.digest(value)
        when :base64, "base64"
          klass.base64digest(value)
        when :bubblebabble, "bubblebabble"
          klass.bubblebabble(value)
        else
          klass.hexdigest(value)
        end
      end
    end
  end

  module ClassMethods
    def has_signature(*config)
      source, options = has_checksum_configure(config)
      raise ArgumentError, "key option required to calculate a signature" unless options[:key]

      if !options[:algorithm].respond_to?(:call)
        begin
          options[:algorithm] = OpenSSL::Digest.new(options[:algorithm])
        rescue RuntimeError
          raise ArgumentError, "unknown algorithm '#{options[:algorithm]}'"
        end
      end

      options[:method] ||= "%s_signature" % source.join("_")
      define_methods(:calculate_signature, source, options)
    end

    def has_checksum(*config)
      source, options = has_checksum_configure(config)

      if !options[:algorithm].respond_to?(:call)
        # TODO: use OpenSSL here too?
        begin
          options[:algorithm] = Digest.const_get(options[:algorithm].upcase)
        # Digest seems to only raise LoadError here but we add NameError for good measure
        rescue LoadError, NameError
          raise ArgumentError, "unknown algorithm '#{options[:algorithm]}'"
        end
      end

      options[:method] ||= "%s_checksum" % source.join("_")
      define_methods(:calculate_checksum, source, options)
    end

    private

    def has_checksum_configure(config)
      config.flatten!
      raise ArgumentError, "config required" if config.empty?

      options = config[-1].is_a?(Hash) ? config.pop : {}
      raise ArgumentError, "no column(s) specified" if config.empty?

      options[:algorithm] ||= "sha256"

      if self < ::ActiveRecord::Base
        extend ActiveRecord
      else
        extend PORO
      end

      [ Array(config), options ]
    end
  end

  module PORO
    private

    def define_methods(calculator, source, options)
      klass = options[:algorithm]
      if klass.respond_to?(:call)
        define_method(options[:method]) { klass[digest_string(source)] }
      else
        define_method(options[:method]) { send(calculator, klass, digest_string(source), options) }
      end
    end
  end

  module ActiveRecord
    private

    def define_methods(calculator, source, options)
      klass = options[:algorithm]
      if klass.respond_to?(:call)
        define_method(options[:method]) { klass[digest_string(source)] }
      else
        define_method(options[:method]) { send(calculator, klass, digest_string(source), options) }
      end

      # Check if we a column to write to or if we only recalculate
      return unless columns_hash.include?(options[:method].to_s)

      watching = source.map(&:to_s)
      if options[:key].is_a?(Symbol)
        key = options[:key].to_s
        # if the key is a column it could change too and we must recalculate, e.g., updated_at
        watching += [key] if columns_hash.include?(key)
      end

      if klass.respond_to?(:call)
        after_create { update_column(options[:method], klass[digest_string(source)]) }
        around_update do |_, block|
          changed = (watching & changed_attributes.keys).any?
          block[]
          update_column(options[:method], klass[digest_string(source)]) if changed
        end
      else
        after_create { update_column(options[:method], public_send(options[:method])) }
        around_update do |_, block|
          changed = (watching & changed_attributes.keys).any?
          block[]
          update_column(options[:method], public_send(options[:method])) if changed
        end
      end
    end
  end
end
