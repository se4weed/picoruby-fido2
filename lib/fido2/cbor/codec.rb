# frozen_string_literal: true

module FIDO2
  def self.byte_slice(data, offset, length)
    return nil if offset < 0 || length < 0 || offset + length > data.bytesize

    result = ""
    index = 0
    while index < length
      result << data.getbyte(offset + index).chr
      index += 1
    end
    result
  end

  module CBOR
    class DecodeError < StandardError; end

    class Text
      attr_reader :value

      def initialize(value)
        @value = value.to_s
      end
    end

    def self.text(value)
      Text.new(value)
    end

    def self.encode(value)
      case value
      when Integer
        value >= 0 ? encode_head(0, value) : encode_head(1, -1 - value)
      when String
        encode_head(2, value.bytesize) + value
      when Text
        encoded = value.value
        encode_head(3, encoded.bytesize) + encoded
      when Array
        result = encode_head(4, value.length)
        index = 0
        while index < value.length
          result << encode(value[index])
          index += 1
        end
        result
      when Hash
        result = encode_head(5, value.length)
        keys = value.keys
        index = 0
        while index < keys.length
          key = keys[index]
          result << encode(key) << encode(value[key])
          index += 1
        end
        result
      when true then "\xF5"
      when false then "\xF4"
      when nil then "\xF6"
      else
        raise ArgumentError, "unsupported CBOR type: #{value.class}"
      end
    end

    def self.decode(data)
      decoder = Decoder.new(data)
      value = decoder.read
      raise DecodeError, "trailing CBOR data" unless decoder.eof?

      value
    end

    def self.encode_head(major, value)
      raise ArgumentError, "negative CBOR length" if value < 0

      prefix = major << 5
      case value
      when 0..23 then [prefix | value].pack("C")
      when 24..0xFF then [prefix | 24, value].pack("CC")
      when 0x100..0xFFFF then [prefix | 25, value].pack("Cn")
      when 0x1_0000..0x7FFF_FFFF then [prefix | 26, value].pack("CN")
      else
        raise RangeError, "CBOR integer is outside PicoRuby's 32-bit range"
      end
    end
    class Decoder
      def initialize(data)
        @data = data
        @offset = 0
      end

      def eof?
        @offset == @data.bytesize
      end

      def read
        initial = read_bytes(1).unpack("C").first
        major = initial >> 5
        additional = initial & 0x1F

        case major
        when 0 then read_length(additional)
        when 1 then -1 - read_length(additional)
        when 2, 3 then read_bytes(read_length(additional))
        when 4 then read_array(additional)
        when 5 then read_map(additional)
        when 7 then read_simple(additional)
        else raise DecodeError, "unsupported CBOR major type: #{major}"
        end
      end

      private

      def read_array(additional)
        length = read_length(additional)
        array = []
        index = 0
        while index < length
          array << read
          index += 1
        end
        array
      end

      def read_map(additional)
        length = read_length(additional)
        map = {}
        index = 0
        while index < length
          key = read
          map[key] = read
          index += 1
        end
        map
      end

      def read_length(additional)
        case additional
        when 0..23 then additional
        when 24 then read_bytes(1).unpack("C").first
        when 25 then read_bytes(2).unpack("n").first
        when 26 then read_bytes(4).unpack("N").first
        when 27 then read_bytes(8).unpack("Q>").first
        else raise DecodeError, "indefinite lengths are not supported"
        end
      end

      def read_simple(additional)
        return false if additional == 20
        return true if additional == 21
        return nil if additional == 22

        raise DecodeError, "unsupported CBOR simple value: #{additional}"
      end

      def read_bytes(length)
        finish = @offset + length
        raise DecodeError, "truncated CBOR data" if finish > @data.bytesize

        bytes = FIDO2.byte_slice(@data, @offset, length)
        @offset = finish
        bytes
      end
    end
  end
end
