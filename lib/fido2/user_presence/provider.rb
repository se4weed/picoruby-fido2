# frozen_string_literal: true

module FIDO2
  module UserPresence
    class Timeout < StandardError; end

    class AlwaysPresent
      def confirm(timeout: nil)
        true
      end
    end

    class GPIOButton
      DEFAULT_DEBOUNCE_MS = 30
      DEFAULT_POLL_INTERVAL_MS = 5

      def initialize(pin, debounce_ms: DEFAULT_DEBOUNCE_MS, poll_interval_ms: DEFAULT_POLL_INTERVAL_MS)
        @button = GPIO.new(pin, GPIO::IN | GPIO::PULL_UP)
        @debounce_ms = debounce_ms
        @poll_interval_ms = poll_interval_ms
      end

      def confirm(timeout: nil)
        deadline = timeout && Machine.board_millis + timeout * 1_000

        # A press that began before this request must not authorize it.
        while @button.low?
          raise Timeout, "user presence timed out" if deadline && Machine.board_millis >= deadline

          sleep_ms @poll_interval_ms
        end

        while @button.high?
          raise Timeout, "user presence timed out" if deadline && Machine.board_millis >= deadline

          sleep_ms @poll_interval_ms
        end

        sleep_ms @debounce_ms
        raise Timeout, "user presence timed out" if @button.high?

        true
      end
    end

    class Callback
      def initialize(&callback)
        @callback = callback
      end

      def confirm(timeout: nil)
        raise Timeout, "user presence timed out" unless @callback.call(timeout)

        true
      end
    end
  end
end
