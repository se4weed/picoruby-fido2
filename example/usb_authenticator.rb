require "fido2"

module FIDO2
  module USB
    def self.hex_bytes(data, offset, length)
      result = ""
      index = 0
      while index < length
        result << data.getbyte(offset + index).to_s(16).rjust(2, "0")
        index += 1
      end
      result
    end

    def self.process(transport)
      report = receive
      return false unless report

      responses = transport.receive(report)
      index = 0
      while index < responses.length
        response = responses[index]
        if response.getbyte(4) == (CTAPHID::COMMAND_INIT | 0x80)
          puts "[CTAPHID_TX_INIT] nonce=#{hex_bytes(response, 7, 8)} " \
               "cid=#{hex_bytes(response, 15, 4)} caps=0x#{response.getbyte(23).to_s(16).rjust(2, "0")}"
        end
        raise RuntimeError, "FIDO HID transmit queue is full" unless send(response)

        index += 1
      end
      true
    end
  end
end

class PersistentLoggingStore < FIDO2::Credential::FileStore
  def save(credential)
    result = super
    unless @incrementing
      puts "[MAKE_CREDENTIAL]"
      puts "credential_id: #{hex(credential.id)}"
      puts "rp_id_hash: #{hex(credential.rp_id_hash)}"
      puts "user_id_length: #{credential.user_id.bytesize}"
      puts "discoverable: #{credential.discoverable}"
      puts "sign_count: #{credential.sign_count}"
    end
    result
  end

  def increment_sign_count(id)
    @incrementing = true
    credential = super
    @incrementing = false
    if credential
      puts "[GET_ASSERTION]"
      puts "credential_id: #{hex(credential.id)}"
      puts "sign_count: #{credential.sign_count}"
    else
      puts "[GET_ASSERTION] credential_not_found"
    end
    credential
  ensure
    @incrementing = false
  end

  def find_by_rp_id_hash(rp_id_hash)
    credential = super
    if credential
      puts "[CREDENTIAL_LOOKUP] found #{hex(credential.id)}"
    else
      puts "[CREDENTIAL_LOOKUP] not_found rp_id_hash=#{hex(rp_id_hash)}"
    end
    credential
  end

  private

  def hex(data)
    encoded = ""
    index = 0
    while index < data.bytesize
      encoded << data.getbyte(index).to_s(16).rjust(2, "0")
      index += 1
    end
    encoded
  end
end

class CTAPLoggingDispatcher
  def initialize(dispatcher)
    @dispatcher = dispatcher
  end

  def call(command, payload)
    name = case command
           when 0x01 then "MAKE_CREDENTIAL"
           when 0x02 then "GET_ASSERTION"
           when 0x04 then "GET_INFO"
           when 0x06 then "CLIENT_PIN"
           else "UNKNOWN_0x#{command.to_s(16)}"
           end
    puts "[CTAP_REQUEST] #{name} payload=#{payload.bytesize} bytes"
    response = @dispatcher.call(command, payload)
    status = response.getbyte(0)
    puts "[CTAP_RESPONSE] #{name} status=0x#{status.to_s(16).rjust(2, "0")} payload=#{response.bytesize - 1} bytes"
    response
  rescue StandardError => error
    puts "[CTAP_EXCEPTION] #{name}: #{error.class}: #{error.message}"
    raise
  end
end

diagnostic_transport = FIDO2::CTAPHID::Transport.new(
  nil,
  random_bytes: ->(_length) { [0x0102_0304].pack("N") }
)
diagnostic_init = FIDO2::CTAPHID::Message.new(
  channel_id: FIDO2::CTAPHID::BROADCAST_CHANNEL,
  command: FIDO2::CTAPHID::COMMAND_INIT,
  payload: "12345678"
)
diagnostic_report = diagnostic_transport.receive(
  FIDO2::CTAPHID::Packetizer.call(diagnostic_init).first
).first
puts "[CTAPHID_SELF_TEST] length=#{diagnostic_report.getbyte(6)} caps=0x#{diagnostic_report.getbyte(23).to_s(16).rjust(2, "0")}"
diagnostic_transport = nil
diagnostic_init = nil
diagnostic_report = nil
GC.start

credential_directory = "/home/fido2-credentials"
Dir.mkdir(credential_directory) unless Dir.exist?(credential_directory)
store = PersistentLoggingStore.new(credential_directory, crypto: FIDO2::Crypto)
user_presence = FIDO2::UserPresence::GPIOButton.new(15)
pin_store = FIDO2::CTAP::PinFileStore.new(credential_directory, crypto: FIDO2::Crypto)
client_pin = FIDO2::CTAP::ClientPIN.new(store: pin_store, crypto: FIDO2::Crypto)
authenticator = FIDO2::CTAP::Authenticator.new(
  store: store,
  crypto: FIDO2::Crypto,
  user_presence: user_presence,
  client_pin: client_pin
)
dispatcher = CTAPLoggingDispatcher.new(FIDO2::CTAP::Dispatcher.new(authenticator, client_pin: client_pin))
transport = FIDO2::CTAPHID::Transport.new(dispatcher)

puts "FIDO2 USB authenticator started (user-presence button: GPIO 15)"
while true
  if FIDO2::USB.process(transport)
    GC.start
  else
    sleep_ms(1)
  end
end
