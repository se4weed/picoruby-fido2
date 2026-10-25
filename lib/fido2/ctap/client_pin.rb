# frozen_string_literal: true

module FIDO2
  module CTAP
    class PinFileStore
      MAGIC = "F2P1"
      FILENAME = "pin-state.f2p"

      def initialize(directory, crypto:)
        @path = "#{directory}/#{FILENAME}"
        @crypto = crypto
      end

      def load
        return nil unless File.file?(@path)

        file = File.open(@path, "r")
        contents = file.read
        file.close
        return nil unless contents && contents.bytesize == 53

        payload = FIDO2.byte_slice(contents, 0, 21)
        checksum = FIDO2.byte_slice(contents, 21, 32)
        return nil unless secure_equal(checksum, @crypto.sha256(payload))
        return nil unless FIDO2.byte_slice(payload, 0, 4) == MAGIC

        { pin_hash: FIDO2.byte_slice(payload, 4, 16), retries: payload.getbyte(20) }
      rescue StandardError
        file.close if file
        nil
      end

      def save(pin_hash, retries)
        payload = MAGIC + pin_hash + [retries].pack("C")
        contents = payload + @crypto.sha256(payload)
        temporary = "#{@path}.tmp"
        file = File.open(temporary, "w")
        file.write(contents)
        file.close
        File.unlink(@path) if File.file?(@path)
        File.rename(temporary, @path)
        true
      ensure
        file.close if file
        File.unlink(temporary) if temporary && File.file?(temporary)
      end

      private

      def secure_equal(left, right)
        return false unless left && right && left.bytesize == right.bytesize

        difference = 0
        index = 0
        while index < left.bytesize
          difference |= left.getbyte(index) ^ right.getbyte(index)
          index += 1
        end
        difference == 0
      end
    end

    class MemoryPinStore
      def load
        return nil unless @pin_hash

        { pin_hash: @pin_hash, retries: @retries }
      end

      def save(pin_hash, retries)
        @pin_hash = pin_hash.dup
        @retries = retries
        true
      end
    end

    class ClientPIN
      PROTOCOL = 1
      MAX_RETRIES = 8
      TEMPORARY_BLOCK_THRESHOLD = 3

      GET_RETRIES = 0x01
      GET_KEY_AGREEMENT = 0x02
      SET_PIN = 0x03
      CHANGE_PIN = 0x04
      GET_PIN_TOKEN = 0x05

      def initialize(store:, crypto:)
        @store = store
        @crypto = crypto
        @key_agreement = crypto.generate_key_pair
        @pin_uv_auth_token = crypto.random_bytes(32)
        @consecutive_failures = 0
        state = store.load
        @pin_hash = state && state[:pin_hash]
        @retries = state ? state[:retries] : MAX_RETRIES
      end

      def pin_set?
        !@pin_hash.nil?
      end

      def call(request)
        protocol = request[1]
        subcommand = request[2]
        raise Error.new(ERR_MISSING_PARAMETER, "pinUvAuthProtocol is required") unless protocol
        raise Error.new(ERR_INVALID_PARAMETER, "unsupported PIN protocol") unless protocol == PROTOCOL

        case subcommand
        when GET_RETRIES then { 3 => @retries }
        when GET_KEY_AGREEMENT then { 1 => key_agreement_cose }
        when SET_PIN then set_pin(request)
        when CHANGE_PIN then change_pin(request)
        when GET_PIN_TOKEN then get_pin_token(request)
        else raise Error.new(ERR_INVALID_PARAMETER, "unsupported ClientPIN subcommand")
        end
      end

      def verify_pin_uv_auth_param(client_data_hash, parameter, protocol)
        raise Error.new(ERR_PIN_AUTH_INVALID, "unsupported PIN protocol") unless protocol == PROTOCOL
        expected = left16(@crypto.hmac_sha256(@pin_uv_auth_token, client_data_hash))
        raise Error.new(ERR_PIN_AUTH_INVALID, "invalid pinUvAuthParam") unless secure_equal(expected, parameter)

        true
      end

      private

      def key_agreement_cose
        cose = @crypto.public_key_to_cose(@key_agreement)
        cose[3] = -25
        cose
      end

      def shared_secret(request)
        peer_key = request[3]
        raise Error.new(ERR_MISSING_PARAMETER, "keyAgreement is required") unless peer_key.is_a?(Hash)

        @crypto.shared_secret(@key_agreement, peer_key)
      rescue ArgumentError
        raise Error.new(ERR_INVALID_PARAMETER, "invalid keyAgreement")
      end

      def set_pin(request)
        raise Error.new(ERR_PIN_AUTH_INVALID, "PIN is already set") if pin_set?

        secret = shared_secret(request)
        encrypted = required_binary(request, 5, "newPinEnc")
        authenticate!(secret, encrypted, required_binary(request, 4, "pinUvAuthParam"))
        pin = decode_new_pin(secret, encrypted)
        @pin_hash = left16(@crypto.sha256(pin))
        @retries = MAX_RETRIES
        @store.save(@pin_hash, @retries)
        clear_string(pin)
        {}
      end

      def change_pin(request)
        require_pin!
        secret = shared_secret(request)
        encrypted = required_binary(request, 5, "newPinEnc")
        old_hash_encrypted = required_binary(request, 6, "pinHashEnc")
        authenticate!(secret, encrypted + old_hash_encrypted, required_binary(request, 4, "pinUvAuthParam"))
        verify_pin_hash!(secret, old_hash_encrypted)
        pin = decode_new_pin(secret, encrypted)
        @pin_hash = left16(@crypto.sha256(pin))
        reset_retries
        clear_string(pin)
        {}
      end

      def get_pin_token(request)
        require_pin!
        secret = shared_secret(request)
        verify_pin_hash!(secret, required_binary(request, 6, "pinHashEnc"))
        { 2 => @crypto.aes256_cbc_encrypt(secret, @pin_uv_auth_token) }
      end

      def authenticate!(secret, message, parameter)
        expected = left16(@crypto.hmac_sha256(secret, message))
        raise Error.new(ERR_PIN_AUTH_INVALID, "invalid pinUvAuthParam") unless secure_equal(expected, parameter)
      end

      def verify_pin_hash!(secret, encrypted)
        blocked_checks!
        decrypted = @crypto.aes256_cbc_decrypt(secret, encrypted)
        candidate = FIDO2.byte_slice(decrypted, 0, 16)
        if secure_equal(candidate, @pin_hash)
          @consecutive_failures = 0
          reset_retries
          clear_string(decrypted)
          return true
        end

        clear_string(decrypted)
        @retries -= 1
        @consecutive_failures += 1
        @store.save(@pin_hash, @retries)
        raise Error.new(ERR_PIN_BLOCKED, "PIN is blocked") if @retries <= 0
        if @consecutive_failures >= TEMPORARY_BLOCK_THRESHOLD
          raise Error.new(ERR_PIN_AUTH_BLOCKED, "PIN authentication is temporarily blocked")
        end
        raise Error.new(ERR_PIN_INVALID, "invalid PIN")
      end

      def blocked_checks!
        raise Error.new(ERR_PIN_BLOCKED, "PIN is blocked") if @retries <= 0
        if @consecutive_failures >= TEMPORARY_BLOCK_THRESHOLD
          raise Error.new(ERR_PIN_AUTH_BLOCKED, "PIN authentication is temporarily blocked")
        end
      end

      def decode_new_pin(secret, encrypted)
        unless encrypted.bytesize >= 64 && encrypted.bytesize % 16 == 0
          raise Error.new(ERR_PIN_POLICY_VIOLATION, "newPinEnc has an invalid length")
        end
        padded = @crypto.aes256_cbc_decrypt(secret, encrypted)
        length = padded.bytesize
        length -= 1 while length > 0 && padded.getbyte(length - 1) == 0
        pin = FIDO2.byte_slice(padded, 0, length)
        clear_string(padded)
        count = utf8_codepoint_count(pin)
        unless pin.bytesize <= 63 && count && count >= 4
          clear_string(pin)
          raise Error.new(ERR_PIN_POLICY_VIOLATION, "PIN must contain at least four characters")
        end
        pin
      end

      def utf8_codepoint_count(value)
        count = 0
        index = 0
        size = value.bytesize
        while index < size
          byte = value.getbyte(index)
          continuation = if byte < 0x80
                           0
                         elsif byte >= 0xC2 && byte <= 0xDF
                           1
                         elsif byte >= 0xE0 && byte <= 0xEF
                           2
                         elsif byte >= 0xF0 && byte <= 0xF4
                           3
                         else
                           return nil
                         end
          return nil if index + continuation >= size
          offset = 1
          while offset <= continuation
            next_byte = value.getbyte(index + offset)
            return nil unless next_byte >= 0x80 && next_byte <= 0xBF
            offset += 1
          end
          index += continuation + 1
          count += 1
        end
        count
      end

      def required_binary(request, key, name)
        value = request[key]
        raise Error.new(ERR_MISSING_PARAMETER, "#{name} is required") unless value.is_a?(String)

        value
      end

      def require_pin!
        raise Error.new(ERR_PIN_NOT_SET, "PIN is not set") unless pin_set?
      end

      def reset_retries
        @retries = MAX_RETRIES
        @store.save(@pin_hash, @retries)
      end

      def left16(value)
        FIDO2.byte_slice(value, 0, 16)
      end

      def secure_equal(left, right)
        return false unless left && right && left.bytesize == right.bytesize

        difference = 0
        index = 0
        while index < left.bytesize
          difference |= left.getbyte(index) ^ right.getbyte(index)
          index += 1
        end
        difference == 0
      end

      def clear_string(value)
        return unless value

        index = 0
        while index < value.bytesize
          value.setbyte(index, 0)
          index += 1
        end
      end
    end
  end
end
