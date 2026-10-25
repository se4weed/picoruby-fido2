# frozen_string_literal: true

module FIDO2
  module Credential
    class Record
      attr_accessor :id, :rp_id_hash, :user_id, :private_key, :public_key, :sign_count, :discoverable

      def initialize(id:, rp_id_hash:, user_id:, private_key:, public_key:, sign_count:, discoverable: false)
        @id = id
        @rp_id_hash = rp_id_hash
        @user_id = user_id
        @private_key = private_key
        @public_key = public_key
        @sign_count = sign_count
        @discoverable = discoverable
      end
    end
  end
end
