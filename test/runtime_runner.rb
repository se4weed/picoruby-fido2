# frozen_string_literal: true

require "fido2"

class RuntimeTest
  def initialize
    @count = 0
  end

  def assert(value, message)
    raise message unless value

    @count += 1
  end

  def assert_equal(expected, actual, message)
    assert(expected == actual, "#{message}: expected #{expected.inspect}, got #{actual.inspect}")
  end

  def run
    crypto = FIDO2::Crypto
    assert_equal(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      hex(crypto.sha256("abc")),
      "SHA-256 vector"
    )

    key = crypto.generate_key_pair
    signed = "authenticator data"
    signature = crypto.sign(key, signed)
    assert(crypto.verify(key.public_key, signature, signed), "ES256 signature")
    assert(!crypto.verify(key.public_key, signature, signed + "!"), "reject invalid ES256 signature")
    restored_key = crypto.import_private_key(crypto.export_private_key(key))
    assert(crypto.verify(restored_key.public_key, crypto.sign(restored_key, signed), signed), "serialized P-256 key")
    cose = crypto.public_key_to_cose(key)
    assert_equal(2, cose[1], "COSE key type")
    assert_equal(-7, cose[3], "COSE algorithm")
    assert_equal(32, cose[-2].bytesize, "COSE x coordinate")
    assert_equal(32, cose[-3].bytesize, "COSE y coordinate")
    assert_equal(
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
      hex(crypto.hmac_sha256("key", "The quick brown fox jumps over the lazy dog")),
      "HMAC-SHA-256 vector"
    )
    aes_key = (0...32).to_a.pack("C*")
    aes_plaintext = [
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    ].pack("C*")
    assert_equal(
      "e0a8f50ec76a04d5a96a175aa870ef63",
      hex(crypto.aes256_cbc_encrypt(aes_key, aes_plaintext)),
      "AES-256-CBC vector"
    )

    cbor_value = { 1 => -7, FIDO2::CBOR.text("text") => [true, false, nil, "bytes"], 3 => 0x1_0000 }
    decoded = FIDO2::CBOR.decode(FIDO2::CBOR.encode(cbor_value))
    assert_equal(-7, decoded[1], "CBOR integer")
    assert_equal([true, false, nil, "bytes"], decoded["text"], "CBOR array")
    assert_equal(0x1_0000, decoded[3], "CBOR 32-bit integer")

    info_dispatcher = FIDO2::CTAP::Dispatcher.new(FIDO2::CTAP::Authenticator.new(
      store: FIDO2::Credential::MemoryStore.new,
      crypto: crypto,
      user_presence: FIDO2::UserPresence::AlwaysPresent.new
    ))
    info = decode_success(info_dispatcher.call(FIDO2::CTAP::Dispatcher::GET_INFO))
    assert_equal(true, info[4]["rk"], "discoverable credential capability")

    test_ctap(crypto)
    test_client_pin(crypto)
    test_ctaphid
    puts "#{@count} assertions passed on PicoRuby"
  end

  private

  def test_ctap(crypto)
    store = FIDO2::Credential::MemoryStore.new
    authenticator = FIDO2::CTAP::Authenticator.new(
      store: store,
      crypto: crypto,
      user_presence: FIDO2::UserPresence::AlwaysPresent.new
    )
    dispatcher = FIDO2::CTAP::Dispatcher.new(authenticator)
    client_data_hash = crypto.sha256("client data")
    make_request = {
      1 => client_data_hash,
      2 => { FIDO2::CBOR.text("id") => FIDO2::CBOR.text("example.com") },
      3 => { FIDO2::CBOR.text("id") => "user-1" },
      4 => [{ FIDO2::CBOR.text("type") => FIDO2::CBOR.text("public-key"), FIDO2::CBOR.text("alg") => -7 }],
      7 => { FIDO2::CBOR.text("rk") => true }
    }
    attestation = decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::MAKE_CREDENTIAL,
      FIDO2::CBOR.encode(make_request)
    ))
    assert_equal("none", attestation[1], "attestation format")

    auth_data = attestation[2]
    credential_id_length = FIDO2.byte_slice(auth_data, 53, 2).unpack("n").first
    credential_id = FIDO2.byte_slice(auth_data, 55, credential_id_length)
    assertion_request = {
      1 => FIDO2::CBOR.text("example.com"),
      2 => client_data_hash
    }
    assertion = decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::GET_ASSERTION,
      FIDO2::CBOR.encode(assertion_request)
    ))
    assert_equal(credential_id, assertion[1]["id"], "assertion credential")
    assert_equal(1, FIDO2.byte_slice(assertion[2], 33, 4).unpack("N").first, "signature counter")
    credential = store.find(credential_id)
    assert_equal(true, credential.discoverable, "discoverable credential")
    assert(crypto.verify(credential.public_key, assertion[3], assertion[2] + client_data_hash), "assertion signature")
  end

  def test_ctaphid
    payload = [0xc3, 0xa9].pack("C*") * 90
    message = FIDO2::CTAPHID::Message.new(channel_id: 0x0102_0304, command: 0x10, payload: payload)
    reports = FIDO2::CTAPHID::Packetizer.call(message)
    report_index = 0
    while report_index < reports.length
      assert_equal(64, reports[report_index].bytesize, "CTAPHID report bytesize")
      report_index += 1
    end
    reassembler = FIDO2::CTAPHID::Reassembler.new
    rebuilt = nil
    index = 0
    while index < reports.length
      candidate = reassembler.feed(reports[index])
      rebuilt = candidate if candidate
      index += 1
    end
    assert_equal(message.channel_id, rebuilt.channel_id, "CTAPHID channel")
    assert_equal(message.command, rebuilt.command, "CTAPHID command")
    assert_equal(message.payload, rebuilt.payload, "CTAPHID payload")

    init = FIDO2::CTAPHID::Message.new(
      channel_id: FIDO2::CTAPHID::BROADCAST_CHANNEL,
      command: FIDO2::CTAPHID::COMMAND_INIT,
      payload: "12345678"
    )
    transport = FIDO2::CTAPHID::Transport.new(nil, random_bytes: ->(_length) { [0x0102_0304].pack("N") })
    init_report = transport.receive(FIDO2::CTAPHID::Packetizer.call(init).first).first
    init_response = FIDO2::CTAPHID::Reassembler.new.feed(init_report)
    assert_equal(17, init_response.payload.bytesize, "CTAPHID INIT payload length")
    assert_equal(0x04, init_response.payload.getbyte(16), "CTAPHID CBOR capability")
  end

  def test_client_pin(crypto)
    pin_store = FIDO2::CTAP::MemoryPinStore.new
    client_pin = FIDO2::CTAP::ClientPIN.new(store: pin_store, crypto: crypto)
    store = FIDO2::Credential::MemoryStore.new
    authenticator = FIDO2::CTAP::Authenticator.new(
      store: store,
      crypto: crypto,
      user_presence: FIDO2::UserPresence::AlwaysPresent.new,
      client_pin: client_pin
    )
    dispatcher = FIDO2::CTAP::Dispatcher.new(authenticator, client_pin: client_pin)
    platform_key = crypto.generate_key_pair

    agreement = decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::CLIENT_PIN,
      FIDO2::CBOR.encode({ 1 => 1, 2 => FIDO2::CTAP::ClientPIN::GET_KEY_AGREEMENT })
    ))[1]
    shared_secret = crypto.shared_secret(platform_key, agreement)
    platform_cose = crypto.public_key_to_cose(platform_key)
    platform_cose[3] = -25
    padded_pin = "1234" + "\0" * 60
    new_pin_enc = crypto.aes256_cbc_encrypt(shared_secret, padded_pin)
    pin_auth = FIDO2.byte_slice(crypto.hmac_sha256(shared_secret, new_pin_enc), 0, 16)
    decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::CLIENT_PIN,
      FIDO2::CBOR.encode({
        1 => 1,
        2 => FIDO2::CTAP::ClientPIN::SET_PIN,
        3 => platform_cose,
        4 => pin_auth,
        5 => new_pin_enc
      })
    ))
    assert_equal(true, decode_success(dispatcher.call(FIDO2::CTAP::Dispatcher::GET_INFO))[4]["clientPin"], "PIN state")

    wrong_pin_hash = FIDO2.byte_slice(crypto.sha256("9999"), 0, 16)
    wrong_pin_response = dispatcher.call(
      FIDO2::CTAP::Dispatcher::CLIENT_PIN,
      FIDO2::CBOR.encode({
        1 => 1,
        2 => FIDO2::CTAP::ClientPIN::GET_PIN_TOKEN,
        3 => platform_cose,
        6 => crypto.aes256_cbc_encrypt(shared_secret, wrong_pin_hash)
      })
    )
    assert_equal(FIDO2::CTAP::ERR_PIN_INVALID, wrong_pin_response.getbyte(0), "reject wrong PIN")
    retries = decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::CLIENT_PIN,
      FIDO2::CBOR.encode({ 1 => 1, 2 => FIDO2::CTAP::ClientPIN::GET_RETRIES })
    ))
    assert_equal(FIDO2::CTAP::ClientPIN::MAX_RETRIES - 1, retries[3], "decrement PIN retries")

    pin_hash = FIDO2.byte_slice(crypto.sha256("1234"), 0, 16)
    token_response = decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::CLIENT_PIN,
      FIDO2::CBOR.encode({
        1 => 1,
        2 => FIDO2::CTAP::ClientPIN::GET_PIN_TOKEN,
        3 => platform_cose,
        6 => crypto.aes256_cbc_encrypt(shared_secret, pin_hash)
      })
    ))
    token = crypto.aes256_cbc_decrypt(shared_secret, token_response[2])
    client_data_hash = crypto.sha256("client PIN data")
    uv_auth = FIDO2.byte_slice(crypto.hmac_sha256(token, client_data_hash), 0, 16)
    response = decode_success(dispatcher.call(
      FIDO2::CTAP::Dispatcher::MAKE_CREDENTIAL,
      FIDO2::CBOR.encode({
        1 => client_data_hash,
        2 => { FIDO2::CBOR.text("id") => FIDO2::CBOR.text("pin.example") },
        3 => { FIDO2::CBOR.text("id") => "pin-user" },
        4 => [{ FIDO2::CBOR.text("type") => FIDO2::CBOR.text("public-key"), FIDO2::CBOR.text("alg") => -7 }],
        8 => uv_auth,
        9 => 1
      })
    ))
    assert_equal(0x45, response[2].getbyte(32), "UP and UV flags")
  end

  def decode_success(response)
    assert_equal(FIDO2::CTAP::SUCCESS, response.getbyte(0), "CTAP status")
    FIDO2::CBOR.decode(FIDO2.byte_slice(response, 1, response.bytesize - 1))
  end

  def hex(value)
    result = ""
    index = 0
    while index < value.bytesize
      result << value.getbyte(index).to_s(16).rjust(2, "0")
      index += 1
    end
    result
  end
end

RuntimeTest.new.run
