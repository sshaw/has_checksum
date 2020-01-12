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
                send(options[:key])
              when Proc
                options[:key][]
              else
                key
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
      if options[:key].is_a?(Symbol) && !method_exists?(options[:key])
        raise "key option refers to an unknown method '#{options[:key]}'"
      end

      if !options[:algorithm].respond_to?(:call)
        begin
          options[:algorithm] = OpenSSL::Digest.new(options[:algorithm])
        rescue RuntimeError
          raise ArgumentError, "unknown algorithm #{options[:algorithm]}"
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
          raise ArgumentError, "unknown algorithm #{options[:algorithm]}"
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

      if defined?(::ActiveRecord)
        extend ActiveRecord
      else
        extend PORO
      end

      sources = Array(config)
      sources.each do |name|
        raise "cannot calculate using unknown method/attribute '#{name}'" unless method_exists?(name)
      end

      [ sources, options ]
    end
  end

  module PORO
    private

    def method_exists?(name)
      respond_to?(name) || instance_methods.include?(name.to_sym)
    end

    def define_methods(calculator, source, options)
      klass = options[:algorithm]
      if !method_exists?(options[:method])
        if klass.respond_to?(:call)
          define_method(options[:method]) { klass[digest_string(source)] }
        else
          define_method(options[:method]) { send(calculator, klass, digest_string(source), options) }
        end
      end
    end
  end

  module ActiveRecord
    private

    def method_exists?(name)
      columns_hash.include?(name.to_s) || respond_to?(name)
    end

    def define_methods(calculator, source, options)
      klass = options[:algorithm]
      if !method_exists?(options[:method])
        if klass.respond_to?(:call)
          define_method(options[:method]) { klass[digest_string(source)] }
        else
          define_method(options[:method]) { send(calculator, klass, digest_string(source), options) }
        end

        return
      end

      setter = "#{options[:method]}="
      raise "#{setter} does not exist" unless respond_to?(setter) || method_exists?(options[:method])

      if klass.respond_to?(:call)
        before_save { klass[value] }
      else
        before_save do
          public_send(setter, send(calculator, klass, digest_string(source), options))
        end
      end
    end
  end
end
