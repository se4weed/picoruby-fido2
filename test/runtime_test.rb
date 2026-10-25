# frozen_string_literal: true

class FIDO2RuntimeTest < Picotest::Test
  def setup
    @crypto = FIDO2::Crypto
    @store = FIDO2::Credential::MemoryStore.new
    authenticator = FIDO2::CTAP::Authenticator.new(
      store: @store,
      crypto: @crypto,
      user_presence: FIDO2::UserPresence::AlwaysPresent.new
    )
    @dispatcher = FIDO2::CTAP::Dispatcher.new(authenticator)
  end

  def test_sha256
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert_equal(expected, hex(@crypto.sha256("abc")))
  end

  def test_es256_and_cose_key
    key = @crypto.generate_key_pair
    data = "authenticator data"
    signature = @crypto.sign(key, data)
    assert(@crypto.verify(key.public_key, signature, data))
    refute(@crypto.verify(key.public_key, signature, data + "!"))

    restored_key = @crypto.import_private_key(@crypto.export_private_key(key))
    assert(@crypto.verify(restored_key.public_key, @crypto.sign(restored_key, data), data))

    cose = @crypto.public_key_to_cose(key)
    assert_equal(2, cose[1])
    assert_equal(-7, cose[3])
    assert_equal(32, cose[-2].bytesize)
    assert_equal(32, cose[-3].bytesize)
  end

  def test_cbor_supported_types
    value = {
      1 => -7,
      FIDO2::CBOR.text("text") => [true, false, nil, "bytes"],
      3 => 0x1_0000
    }
    decoded = FIDO2::CBOR.decode(FIDO2::CBOR.encode(value))
    assert_equal(-7, decoded[1])
    assert_equal([true, false, nil, "bytes"], decoded["text"])
    assert_equal(0x1_0000, decoded[3])
  end

  def test_make_credential_and_get_assertion
    info = decode_success(@dispatcher.call(FIDO2::CTAP::Dispatcher::GET_INFO, ""))
    assert_equal(true, info[4]["rk"])
    client_data_hash = @crypto.sha256("client data")
    make_request = {
      1 => client_data_hash,
      2 => { FIDO2::CBOR.text("id") => FIDO2::CBOR.text("example.com") },
      3 => { FIDO2::CBOR.text("id") => "user-1" },
      4 => [{ FIDO2::CBOR.text("type") => FIDO2::CBOR.text("public-key"), FIDO2::CBOR.text("alg") => -7 }],
      7 => { FIDO2::CBOR.text("rk") => true }
    }
    attestation = decode_success(@dispatcher.call(
      FIDO2::CTAP::Dispatcher::MAKE_CREDENTIAL,
      FIDO2::CBOR.encode(make_request)
    ))
    assert_equal("none", attestation[1])

    auth_data = attestation[2]
    credential_id_length = auth_data[53, 2].unpack("n").first
    credential_id = auth_data[55, credential_id_length]
    assertion_request = {
      1 => FIDO2::CBOR.text("example.com"),
      2 => client_data_hash
    }
    assertion = decode_success(@dispatcher.call(
      FIDO2::CTAP::Dispatcher::GET_ASSERTION,
      FIDO2::CBOR.encode(assertion_request)
    ))

    assert_equal(credential_id, assertion[1]["id"])
    assert_equal(1, assertion[2][33, 4].unpack("N").first)
    credential = @store.find(credential_id)
    assert_equal(true, credential.discoverable)
    assert(@crypto.verify(credential.public_key, assertion[3], assertion[2] + client_data_hash))
  end

  def test_ctaphid_fragmentation
    payload = [0xc3, 0xa9].pack("C*") * 90
    message = FIDO2::CTAPHID::Message.new(channel_id: 0x0102_0304, command: 0x10, payload: payload)
    reports = FIDO2::CTAPHID::Packetizer.call(message)
    report_index = 0
    while report_index < reports.length
      assert_equal(64, reports[report_index].bytesize)
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
    assert_equal(message.channel_id, rebuilt.channel_id)
    assert_equal(message.command, rebuilt.command)
    assert_equal(message.payload, rebuilt.payload)

    init = FIDO2::CTAPHID::Message.new(
      channel_id: FIDO2::CTAPHID::BROADCAST_CHANNEL,
      command: FIDO2::CTAPHID::COMMAND_INIT,
      payload: "12345678"
    )
    transport = FIDO2::CTAPHID::Transport.new(nil, random_bytes: ->(_length) { [0x0102_0304].pack("N") })
    init_report = transport.receive(FIDO2::CTAPHID::Packetizer.call(init).first).first
    init_response = FIDO2::CTAPHID::Reassembler.new.feed(init_report)
    assert_equal(17, init_response.payload.bytesize)
    assert_equal(0x04, init_response.payload.getbyte(16))
  end

  private

  def decode_success(response)
    assert_equal(FIDO2::CTAP::SUCCESS, response.getbyte(0))
    FIDO2::CBOR.decode(response[1, response.bytesize - 1])
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
