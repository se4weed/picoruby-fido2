# frozen_string_literal: true

module FIDO2
  module CTAP
    SUCCESS = 0x00
    ERR_INVALID_COMMAND = 0x01
    ERR_INVALID_PARAMETER = 0x02
    ERR_INVALID_CBOR = 0x12
    ERR_MISSING_PARAMETER = 0x14
    ERR_CREDENTIAL_EXCLUDED = 0x19
    ERR_UNSUPPORTED_ALGORITHM = 0x26
    ERR_OPERATION_DENIED = 0x27
    ERR_UNSUPPORTED_OPTION = 0x2B
    ERR_NO_CREDENTIALS = 0x2E
    ERR_PIN_INVALID = 0x31
    ERR_PIN_BLOCKED = 0x32
    ERR_PIN_AUTH_INVALID = 0x33
    ERR_PIN_AUTH_BLOCKED = 0x34
    ERR_PIN_NOT_SET = 0x35
    ERR_PIN_REQUIRED = 0x36
    ERR_PIN_POLICY_VIOLATION = 0x37
    ERR_KEEPALIVE_CANCEL = 0x2D
    ERR_OTHER = 0x7F

    class Error < StandardError
      attr_reader :code

      def initialize(code, message = nil)
        @code = code
        super(message)
      end
    end
  end
end
