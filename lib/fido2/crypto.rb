# frozen_string_literal: true

module FIDO2
  module Crypto
    class Key
      attr_reader :private_bytes, :public_bytes

      def initialize(private_bytes, public_bytes)
        @private_bytes = private_bytes
        @public_bytes = public_bytes
      end

      def public_key
        Key.new(nil, @public_bytes)
      end
    end

    PRIVATE_KEY_MAGIC = "F2K1"
    PRIVATE_KEY_SIZE = 32
    PUBLIC_KEY_SIZE = 64

    class << self
      def random_bytes(length)
        RNG.random_string(length)
      end

      def sha256(data)
        Native.sha256(data)
      end

      def generate_key_pair
        pair = Native.generate_key_pair
        Key.new(pair[0], pair[1])
      end

      def sign(private_key, data)
        raise ArgumentError, "private key is required" unless private_key.private_bytes

        encode_der_signature(Native.sign(private_key.private_bytes, sha256(data)))
      end

      def verify(key, signature, data)
        raw_signature = decode_der_signature(signature)
        return false unless raw_signature

        Native.verify(key.public_bytes, raw_signature, sha256(data))
      rescue StandardError
        false
      end

      def shared_secret(private_key, peer_cose_key)
        x = peer_cose_key[-2]
        y = peer_cose_key[-3]
        unless x.is_a?(String) && x.bytesize == 32 && y.is_a?(String) && y.bytesize == 32
          raise ArgumentError, "invalid peer P-256 public key"
        end

        sha256(Native.ecdh(private_key.private_bytes, x + y))
      end

      def hmac_sha256(key, data)
        Native.hmac_sha256(key, data)
      end

      def aes256_cbc_encrypt(key, data)
        Native.aes256_cbc_encrypt(key, data)
      end

      def aes256_cbc_decrypt(key, data)
        Native.aes256_cbc_decrypt(key, data)
      end

      def public_key_to_cose(key)
        point = key.public_bytes
        raise ArgumentError, "invalid P-256 public key" unless point && point.bytesize == PUBLIC_KEY_SIZE

        {
          1 => 2,
          3 => -7,
          -1 => 1,
          -2 => FIDO2.byte_slice(point, 0, 32),
          -3 => FIDO2.byte_slice(point, 32, 32)
        }
      end

      def export_private_key(key)
        private_bytes = key.private_bytes
        raise ArgumentError, "private key is required" unless private_bytes && private_bytes.bytesize == PRIVATE_KEY_SIZE

        PRIVATE_KEY_MAGIC + private_bytes + key.public_bytes
      end

      def import_private_key(serialized)
        expected_size = PRIVATE_KEY_MAGIC.bytesize + PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE
        unless serialized && serialized.bytesize == expected_size &&
               FIDO2.byte_slice(serialized, 0, PRIVATE_KEY_MAGIC.bytesize) == PRIVATE_KEY_MAGIC
          raise ArgumentError, "invalid serialized P-256 private key"
        end

        private_bytes = FIDO2.byte_slice(serialized, PRIVATE_KEY_MAGIC.bytesize, PRIVATE_KEY_SIZE)
        public_bytes = Native.public_from_private(private_bytes)
        stored_public = FIDO2.byte_slice(serialized, PRIVATE_KEY_MAGIC.bytesize + PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE)
        raise ArgumentError, "P-256 public key does not match private key" unless public_bytes == stored_public

        Key.new(private_bytes, public_bytes)
      end

      private

      def encode_der_signature(raw_signature)
        raise ArgumentError, "invalid raw P-256 signature" unless raw_signature.bytesize == 64

        r = encode_der_integer(FIDO2.byte_slice(raw_signature, 0, 32))
        s = encode_der_integer(FIDO2.byte_slice(raw_signature, 32, 32))
        body = "\x02" + r.bytesize.chr + r + "\x02" + s.bytesize.chr + s
        "\x30" + body.bytesize.chr + body
      end

      def encode_der_integer(integer)
        offset = 0
        offset += 1 while offset < integer.bytesize - 1 && integer.getbyte(offset) == 0
        encoded = FIDO2.byte_slice(integer, offset, integer.bytesize - offset)
        encoded = "\x00" + encoded if (encoded.getbyte(0) & 0x80) != 0
        encoded
      end

      def decode_der_signature(signature)
        return nil unless signature && signature.bytesize >= 8
        return nil unless signature.getbyte(0) == 0x30 && signature.getbyte(1) == signature.bytesize - 2

        offset = 2
        r, offset = decode_der_integer(signature, offset)
        return nil unless r

        s, offset = decode_der_integer(signature, offset)
        return nil unless s && offset == signature.bytesize

        r + s
      end

      def decode_der_integer(signature, offset)
        return [nil, offset] unless signature.getbyte(offset) == 0x02

        length = signature.getbyte(offset + 1)
        offset += 2
        return [nil, offset] unless length && length > 0 && offset + length <= signature.bytesize

        integer = FIDO2.byte_slice(signature, offset, length)
        return [nil, offset] if (integer.getbyte(0) & 0x80) != 0
        return [nil, offset] if length > 33 || (length == 33 && integer.getbyte(0) != 0)
        return [nil, offset] if length > 1 && integer.getbyte(0) == 0 && (integer.getbyte(1) & 0x80) == 0

        integer = FIDO2.byte_slice(integer, 1, 32) if length == 33
        padded = "\x00" * (32 - integer.bytesize) + integer
        [padded, offset + length]
      end
    end
  end
end
