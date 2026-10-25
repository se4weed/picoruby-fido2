# frozen_string_literal: true

require_relative "fido2/cbor/codec"
require_relative "fido2/crypto"
require_relative "fido2/credential/credential"
require_relative "fido2/credential/file_store"
require_relative "fido2/user_presence/provider"
require_relative "fido2/ctap/errors"
require_relative "fido2/ctap/client_pin"
require_relative "fido2/ctap/authenticator"
require_relative "fido2/ctap/dispatcher"
require_relative "fido2/ctaphid/transport"
require_relative "fido2/usb"

module FIDO2
  VERSION = "0.1.0"
end
