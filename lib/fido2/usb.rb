# frozen_string_literal: true

module FIDO2
  module USB
    def self.receive
      Crypto::Native.usb_receive
    end

    def self.send(report)
      raise ArgumentError, "FIDO HID report must be 64 bytes" unless report.bytesize == CTAPHID::REPORT_SIZE

      Crypto::Native.usb_send(report)
    end

    def self.process(transport)
      report = receive
      return false unless report

      responses = transport.receive(report)
      index = 0
      while index < responses.length
        raise RuntimeError, "FIDO HID transmit queue is full" unless send(responses[index])

        index += 1
      end
      true
    end
  end
end
