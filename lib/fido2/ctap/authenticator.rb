# frozen_string_literal: true

module FIDO2
  module CTAP
    class Authenticator
      DEFAULT_AAGUID = "\0" * 16
      USER_PRESENCE_TIMEOUT = 30

      def initialize(store:, crypto:, user_presence:, client_pin: nil, aaguid: DEFAULT_AAGUID)
        raise ArgumentError, "AAGUID must be 16 bytes" unless aaguid.bytesize == 16

        @store = store
        @crypto = crypto
        @user_presence = user_presence
        @client_pin = client_pin
        @aaguid = aaguid
      end

      def get_info
        {
          1 => [CBOR.text("FIDO_2_0")],
          2 => [],
          3 => @aaguid,
          4 => {
            CBOR.text("rk") => true,
            CBOR.text("up") => true,
            CBOR.text("uv") => false,
            CBOR.text("clientPin") => @client_pin ? @client_pin.pin_set? : false
          },
          5 => 1_200,
          6 => @client_pin ? [ClientPIN::PROTOCOL] : []
        }
      end

      def make_credential(request)
        client_data_hash = required_binary(request, 1, length: 32)
        rp = required_hash(request, 2)
        user = required_hash(request, 3)
        parameters = required_array(request, 4)
        rp_id = required_text(rp, "id")
        user_id = required_binary(user, "id")
        options = request[7]
        reject_user_verification!(options)
        user_verified = verify_pin_uv_auth(request, client_data_hash, 8, 9)
        discoverable = options.is_a?(Hash) && options["rk"] == true
        validate_algorithm!(parameters)
        reject_excluded_credentials!(request[5], rp_id)
        confirm_user_presence!

        key = @crypto.generate_key_pair
        credential = Credential::Record.new(
          id: @crypto.random_bytes(32),
          rp_id_hash: @crypto.sha256(rp_id),
          user_id: user_id,
          private_key: key,
          public_key: key,
          sign_count: 0,
          discoverable: discoverable
        )
        @store.save(credential)

        credential_public_key = CBOR.encode(@crypto.public_key_to_cose(key))
        attested_data = @aaguid + [credential.id.bytesize].pack("n") + credential.id + credential_public_key
        flags = 0x41 | (user_verified ? 0x04 : 0)
        auth_data = credential.rp_id_hash + [flags].pack("C") + [0].pack("N") + attested_data

        { 1 => CBOR.text("none"), 2 => auth_data, 3 => {} }
      rescue UserPresence::Timeout
        raise Error.new(ERR_OPERATION_DENIED, "user presence timed out")
      end

      def get_assertion(request)
        rp_id = required_text(request, 1)
        client_data_hash = required_binary(request, 2, length: 32)
        allow_list = request[3]
        unless allow_list.nil? || allow_list.is_a?(Array)
          raise Error.new(ERR_INVALID_PARAMETER, "allowList must be an array")
        end
        options = request[5]
        reject_user_verification!(options)
        user_verified = verify_pin_uv_auth(request, client_data_hash, 6, 7)
        credential = if allow_list && !allow_list.empty?
                       find_allowed_credential(allow_list, rp_id)
                     else
                       @store.find_by_rp_id_hash(@crypto.sha256(rp_id))
                     end
        raise Error.new(ERR_NO_CREDENTIALS, "no matching credential") unless credential

        confirm_user_presence!
        credential = @store.increment_sign_count(credential.id)
        flags = 0x01 | (user_verified ? 0x04 : 0)
        auth_data = credential.rp_id_hash + [flags].pack("C") + [credential.sign_count].pack("N")
        signature = @crypto.sign(credential.private_key, auth_data + client_data_hash)

        {
          1 => { CBOR.text("id") => credential.id, CBOR.text("type") => CBOR.text("public-key") },
          2 => auth_data,
          3 => signature,
          4 => { CBOR.text("id") => credential.user_id }
        }
      rescue UserPresence::Timeout
        raise Error.new(ERR_OPERATION_DENIED, "user presence timed out")
      end

      private

      def required_hash(container, key)
        value = container[key]
        raise Error.new(ERR_MISSING_PARAMETER, "missing parameter #{key}") unless value.is_a?(Hash)

        value
      end

      def required_array(container, key)
        value = container[key]
        raise Error.new(ERR_MISSING_PARAMETER, "missing parameter #{key}") unless value.is_a?(Array)

        value
      end

      def required_text(container, key)
        value = container[key]
        unless value.is_a?(String) && !value.empty?
          raise Error.new(ERR_MISSING_PARAMETER, "missing text parameter #{key}")
        end

        value
      end

      def required_binary(container, key, length: nil)
        value = container[key]
        unless value.is_a?(String)
          raise Error.new(ERR_MISSING_PARAMETER, "missing byte string parameter #{key}")
        end
        if length && value.bytesize != length
          raise Error.new(ERR_INVALID_PARAMETER, "parameter #{key} must be #{length} bytes")
        end

        value
      end

      def validate_algorithm!(parameters)
        supported = false
        index = 0
        while index < parameters.length
          item = parameters[index]
          if item.is_a?(Hash) && item["type"] == "public-key" && item["alg"] == -7
            supported = true
            break
          end
          index += 1
        end
        raise Error.new(ERR_UNSUPPORTED_ALGORITHM, "ES256 is required") unless supported
      end

      def reject_user_verification!(options)
        if options.is_a?(Hash) && options["uv"] == true
          raise Error.new(ERR_UNSUPPORTED_OPTION, "user verification is not supported")
        end
      end

      def verify_pin_uv_auth(request, client_data_hash, parameter_key, protocol_key)
        parameter = request[parameter_key]
        protocol = request[protocol_key]
        return false unless parameter
        raise Error.new(ERR_PIN_AUTH_INVALID, "ClientPIN is unavailable") unless @client_pin
        unless parameter.is_a?(String) && parameter.bytesize == 16
          raise Error.new(ERR_PIN_AUTH_INVALID, "pinUvAuthParam must be 16 bytes")
        end

        @client_pin.verify_pin_uv_auth_param(client_data_hash, parameter, protocol)
      end

      def reject_excluded_credentials!(exclude_list, rp_id)
        return unless exclude_list.is_a?(Array)

        rp_id_hash = @crypto.sha256(rp_id)
        excluded = false
        index = 0
        while index < exclude_list.length
          descriptor = exclude_list[index]
          id = descriptor.is_a?(Hash) && descriptor["id"]
          credential = id.is_a?(String) && @store.find(id)
          if credential && credential.rp_id_hash == rp_id_hash
            excluded = true
            break
          end
          index += 1
        end
        raise Error.new(ERR_CREDENTIAL_EXCLUDED, "credential is excluded") if excluded
      end

      def find_allowed_credential(allow_list, rp_id)
        rp_id_hash = @crypto.sha256(rp_id)
        index = 0
        while index < allow_list.length
          descriptor = allow_list[index]
          if descriptor.is_a?(Hash) && descriptor["type"] == "public-key"
            id = descriptor["id"]
            if id.is_a?(String)
              credential = @store.find(id)
              return credential if credential && credential.rp_id_hash == rp_id_hash
            end
          end
          index += 1
        end
        nil
      end

      def confirm_user_presence!
        @user_presence.confirm(timeout: USER_PRESENCE_TIMEOUT)
      end
    end
  end
end
