# frozen_string_literal: true

module FIDO2
  module Credential
    class FileStore
      MAGIC = "F2C2"

      def initialize(directory, crypto:)
        @directory = directory
        @crypto = crypto
      end

      def save(credential)
        private_key = @crypto.export_private_key(credential.private_key)
        payload = MAGIC +
          [credential.id.bytesize].pack("n") + credential.id +
          credential.rp_id_hash +
          [credential.user_id.bytesize].pack("n") + credential.user_id +
          [credential.discoverable ? 1 : 0].pack("C") +
          [private_key.bytesize].pack("n") + private_key +
          [credential.sign_count].pack("N")
        contents = payload + @crypto.sha256(payload)
        atomic_write(path_for(credential.id), contents)
        atomic_write(rp_index_path(credential.rp_id_hash), credential.id) if credential.discoverable
        credential
      end

      def find(id)
        path = path_for(id)
        return nil unless File.file?(path)

        contents = read_file(path)
        return nil unless contents && contents.bytesize >= 76

        payload = FIDO2.byte_slice(contents, 0, contents.bytesize - 32)
        checksum = FIDO2.byte_slice(contents, contents.bytesize - 32, 32)
        return nil unless secure_equal(checksum, @crypto.sha256(payload))

        decode(payload, id)
      rescue StandardError
        nil
      end

      def delete(id)
        path = path_for(id)
        File.unlink(path) if File.file?(path)
      end

      def increment_sign_count(id)
        credential = find(id)
        return nil unless credential

        credential.sign_count += 1
        save(credential)
      end

      def find_by_rp_id_hash(rp_id_hash)
        index_path = rp_index_path(rp_id_hash)
        if File.file?(index_path)
          id = read_file(index_path)
          credential = id && find(id)
          return credential if credential && credential.discoverable && credential.rp_id_hash == rp_id_hash
        end

        directory = Dir.open(@directory)
        while entry = directory.read
          if entry.end_with?(".f2c")
            id = decode_hex(FIDO2.byte_slice(entry, 0, entry.bytesize - 4))
            credential = id && find(id)
            if credential && credential.discoverable && credential.rp_id_hash == rp_id_hash
              atomic_write(index_path, credential.id)
              return credential
            end
          end
        end
        nil
      rescue StandardError
        nil
      ensure
        directory.close if directory
      end

      private

      def decode(payload, expected_id)
        magic = FIDO2.byte_slice(payload, 0, 4)
        legacy = magic == "F2C1"
        return nil unless legacy || magic == MAGIC

        offset = 4
        id_length = read_u16(payload, offset)
        offset += 2
        id = FIDO2.byte_slice(payload, offset, id_length)
        offset += id_length
        return nil unless id == expected_id

        rp_id_hash = FIDO2.byte_slice(payload, offset, 32)
        offset += 32
        user_length = read_u16(payload, offset)
        offset += 2
        user_id = FIDO2.byte_slice(payload, offset, user_length)
        offset += user_length
        if legacy
          discoverable_byte = 0
        else
          discoverable_byte = payload.getbyte(offset)
          offset += 1
        end
        key_length = read_u16(payload, offset)
        offset += 2
        private_key_pem = FIDO2.byte_slice(payload, offset, key_length)
        offset += key_length
        counter_bytes = FIDO2.byte_slice(payload, offset, 4)
        return nil unless rp_id_hash && rp_id_hash.bytesize == 32 && user_id && private_key_pem
        return nil unless counter_bytes && counter_bytes.bytesize == 4 && offset + 4 == payload.bytesize

        sign_count = counter_bytes.unpack("N").first
        private_key = @crypto.import_private_key(private_key_pem)
        Record.new(
          id: id,
          rp_id_hash: rp_id_hash,
          user_id: user_id,
          private_key: private_key,
          public_key: private_key.public_key,
          sign_count: sign_count,
          discoverable: discoverable_byte == 1
        )
      end

      def decode_hex(value)
        return nil unless value && value.bytesize.even?

        decoded = ""
        index = 0
        while index < value.bytesize
          byte = value[index, 2].to_i(16)
          decoded << byte
          index += 2
        end
        decoded
      end

      def read_u16(data, offset)
        bytes = FIDO2.byte_slice(data, offset, 2)
        raise ArgumentError, "truncated credential" unless bytes && bytes.bytesize == 2

        bytes.unpack("n").first
      end

      def path_for(id)
        hex = ""
        index = 0
        while index < id.bytesize
          hex << id.getbyte(index).to_s(16).rjust(2, "0")
          index += 1
        end
        "#{@directory}/#{hex}.f2c"
      end

      def rp_index_path(rp_id_hash)
        hex = ""
        index = 0
        while index < rp_id_hash.bytesize
          hex << rp_id_hash.getbyte(index).to_s(16).rjust(2, "0")
          index += 1
        end
        "#{@directory}/rp-#{hex}.idx"
      end

      def read_file(path)
        File.open(path, "r") { |file| file.read }
      end

      def atomic_write(path, contents)
        temporary = "#{path}.tmp"
        File.open(temporary, "w") { |file| file.write(contents) }
        File.unlink(path) if File.file?(path)
        File.rename(temporary, path)
      ensure
        File.unlink(temporary) if temporary && File.file?(temporary)
      end

      def secure_equal(left, right)
        return false unless left && right && left.bytesize == right.bytesize

        difference = 0
        index = 0
        while index < left.bytesize
          difference |= left.getbyte(index) ^ right.getbyte(index)
          index += 1
        end
        difference == 0
      end
    end

    class MemoryStore
      def initialize
        @records = {}
      end

      def save(credential)
        @records[credential.id] = credential
      end

      def find(id)
        @records[id]
      end

      def delete(id)
        @records.delete(id)
      end

      def increment_sign_count(id)
        credential = find(id)
        credential.sign_count += 1 if credential
        credential
      end

      def find_by_rp_id_hash(rp_id_hash)
        ids = @records.keys
        index = 0
        while index < ids.length
          credential = @records[ids[index]]
          if credential.discoverable && credential.rp_id_hash == rp_id_hash
            return credential
          end
          index += 1
        end
        nil
      end
    end
  end
end
