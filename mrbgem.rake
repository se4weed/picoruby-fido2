MRuby::Gem::Specification.new("picoruby-fido2") do |spec|
  spec.license = "MIT"
  spec.author = "nori"
  spec.summary = "Minimal FIDO2 authenticator for PicoRuby"

  spec.add_dependency "picoruby-rng"
  spec.add_dependency "picoruby-vfs"
  spec.add_dependency "picoruby-gpio"
  spec.add_dependency "picoruby-machine"
  spec.add_dependency "picoruby-mbedtls"
  spec.cc.include_paths << "#{dir}/vendor/p256-m"
  spec.cc.include_paths << "#{MRUBY_ROOT}/mrbgems/picoruby-rng/include"
  spec.cc.include_paths << "#{MRUBY_ROOT}/mrbgems/picoruby-mbedtls/lib/mbedtls/include"
  spec.objs << "#{build_dir}/vendor/p256-m/p256-m.o"
  source_files = [
    "#{dir}/lib/fido2/cbor/codec.rb",
    "#{dir}/lib/fido2/crypto.rb",
    "#{dir}/lib/fido2/credential/credential.rb",
    "#{dir}/lib/fido2/credential/file_store.rb",
    "#{dir}/lib/fido2/user_presence/provider.rb",
    "#{dir}/lib/fido2/ctap/errors.rb",
    "#{dir}/lib/fido2/ctap/client_pin.rb",
    "#{dir}/lib/fido2/ctap/authenticator.rb",
    "#{dir}/lib/fido2/ctap/dispatcher.rb",
    "#{dir}/lib/fido2/ctaphid/transport.rb",
    "#{dir}/lib/fido2/usb.rb"
  ]
  generated = "#{build_dir}/fido2.rb"
  FileUtils.mkdir_p(File.dirname(generated))
  contents = source_files.map { |path| File.read(path) }.join("\n") + <<~RUBY
    module FIDO2
      VERSION = "0.1.0"
    end
  RUBY
  File.write(generated, contents) unless File.exist?(generated) && File.read(generated) == contents
  spec.rbfiles = [generated]
end
