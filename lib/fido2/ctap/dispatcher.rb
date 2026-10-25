# frozen_string_literal: true

module FIDO2
  module CTAP
    class Dispatcher
      MAKE_CREDENTIAL = 0x01
      GET_ASSERTION = 0x02
      GET_INFO = 0x04
      CLIENT_PIN = 0x06

      def initialize(authenticator, client_pin: nil)
        @authenticator = authenticator
        @client_pin = client_pin
      end

      def call(command, payload = "")
        request = payload.empty? ? {} : CBOR.decode(payload)
        raise Error.new(ERR_INVALID_CBOR, "CBOR request must be a map") unless request.is_a?(Hash)

        response = case command
                   when MAKE_CREDENTIAL then @authenticator.make_credential(request)
                   when GET_ASSERTION then @authenticator.get_assertion(request)
                   when GET_INFO then @authenticator.get_info
                   when CLIENT_PIN
                     raise Error.new(ERR_INVALID_COMMAND, "ClientPIN is unavailable") unless @client_pin
                     @client_pin.call(request)
                   else raise Error.new(ERR_INVALID_COMMAND, "unknown CTAP command")
                   end
        [SUCCESS].pack("C") + CBOR.encode(response)
      rescue CBOR::DecodeError
        [ERR_INVALID_CBOR].pack("C")
      rescue Error => error
        [error.code].pack("C")
      rescue StandardError
        [ERR_OTHER].pack("C")
      end
    end
  end
end
