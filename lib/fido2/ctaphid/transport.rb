# frozen_string_literal: true

module FIDO2
  module CTAPHID
    REPORT_SIZE = 64
    BROADCAST_CHANNEL = 0xFFFF_FFFF
    COMMAND_PING = 0x01
    COMMAND_INIT = 0x06
    COMMAND_CBOR = 0x10
    COMMAND_CANCEL = 0x11
    COMMAND_ERROR = 0x3F
    ERROR_INVALID_COMMAND = 0x01
    ERROR_INVALID_LENGTH = 0x03
    ERROR_INVALID_SEQUENCE = 0x04
    MAX_CHANNELS = 8

    class Message
      attr_reader :channel_id, :command, :payload

      def initialize(channel_id:, command:, payload:)
        @channel_id = channel_id
        @command = command
        @payload = payload
      end
    end

    class Packetizer
      def self.call(message)
        payload = message.payload
        first_data = FIDO2.byte_slice(payload, 0, payload.bytesize < 57 ? payload.bytesize : 57) || ""
        packets = [[message.channel_id, message.command | 0x80, payload.bytesize].pack("NCn") + first_data]
        offset = first_data.bytesize
        sequence = 0
        while offset < payload.bytesize
          chunk_length = payload.bytesize - offset
          chunk = FIDO2.byte_slice(payload, offset, chunk_length < 59 ? chunk_length : 59)
          packets << [message.channel_id, sequence].pack("NC") + chunk
          offset += chunk.bytesize
          sequence += 1
        end
        index = 0
        while index < packets.length
          packet = packets[index]
          packet << "\0" * (REPORT_SIZE - packet.bytesize)
          packets[index] = packet
          index += 1
        end
        packets
      end
    end

    class Reassembler
      def initialize
        @pending = {}
      end

      def feed(report)
        raise ArgumentError, "HID report must be 64 bytes" unless report.bytesize == REPORT_SIZE

        channel = report.unpack("N").first
        marker = report.getbyte(4)
        marker & 0x80 == 0x80 ? start_message(channel, marker, report) : continue_message(channel, marker, report)
      end

      private

      def start_message(channel, marker, report)
        command = marker & 0x7F
        length = FIDO2.byte_slice(report, 5, 2).unpack("n").first
        payload = FIDO2.byte_slice(report, 7, length < 57 ? length : 57)
        return Message.new(channel_id: channel, command: command, payload: payload) if payload.bytesize == length

        @pending[channel] = { command: command, length: length, payload: payload, sequence: 0 }
        nil
      end

      def continue_message(channel, sequence, report)
        state = @pending[channel]
        raise ArgumentError, "continuation without initial packet" unless state
        raise ArgumentError, "invalid continuation sequence" unless sequence == state[:sequence]

        remaining = state[:length] - state[:payload].bytesize
        state[:payload] += FIDO2.byte_slice(report, 5, remaining < 59 ? remaining : 59)
        state[:sequence] += 1
        return nil if state[:payload].bytesize < state[:length]

        @pending.delete(channel)
        Message.new(channel_id: channel, command: state[:command], payload: state[:payload])
      end
    end

    class Transport
      def initialize(dispatcher, random_bytes: nil)
        @dispatcher = dispatcher
        @reassembler = Reassembler.new
        @random_bytes = random_bytes || ->(length) { RNG.random_string(length) }
        @channels = {}
        @channel_order = []
      end

      def receive(report)
        message = @reassembler.feed(report)
        return [] unless message

        Packetizer.call(handle(message))
      rescue ArgumentError
        Packetizer.call(Message.new(channel_id: report.unpack("N").first, command: COMMAND_ERROR, payload: [ERROR_INVALID_SEQUENCE].pack("C")))
      end

      private

      def handle(message)
        case message.command
        when COMMAND_INIT then initialize_channel(message)
        when COMMAND_PING then reply(message, message.payload)
        when COMMAND_CBOR
          return error(message.channel_id, ERROR_INVALID_COMMAND) unless @channels[message.channel_id]

          command = message.payload.getbyte(0)
          return error(message.channel_id, ERROR_INVALID_LENGTH) unless command

          reply(message, @dispatcher.call(command, FIDO2.byte_slice(message.payload, 1, message.payload.bytesize - 1) || ""))
        when COMMAND_CANCEL then reply(message, "")
        else error(message.channel_id, ERROR_INVALID_COMMAND)
        end
      end

      def initialize_channel(message)
        return error(message.channel_id, ERROR_INVALID_LENGTH) unless message.payload.bytesize == 8

        channel = allocate_channel
        @channels[channel] = true
        @channel_order << channel
        if @channel_order.length > MAX_CHANNELS
          expired_channel = @channel_order.shift
          @channels.delete(expired_channel)
        end
        version_and_capabilities = "\x02\x00\x01\x00\x04"
        payload = message.payload + [channel].pack("N") + version_and_capabilities
        Message.new(channel_id: message.channel_id, command: COMMAND_INIT, payload: payload)
      end

      def allocate_channel
        loop do
          channel = @random_bytes.call(4).unpack("N").first
          return channel unless channel.zero? || channel == BROADCAST_CHANNEL || @channels[channel]
        end
      end

      def reply(message, payload)
        Message.new(channel_id: message.channel_id, command: message.command, payload: payload)
      end

      def error(channel, code)
        Message.new(channel_id: channel, command: COMMAND_ERROR, payload: [code].pack("C"))
      end
    end
  end
end
