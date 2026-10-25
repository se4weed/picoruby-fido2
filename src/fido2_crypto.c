#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/string.h>

#include <mbedtls/aes.h>

#include "rng.h"
#include "p256-m.h"

#if defined(PICORB_PLATFORM_RP2)
bool fido2_usb_pop_report(uint8_t report[64]);
bool fido2_usb_push_report(const uint8_t report[64]);
#endif

typedef struct {
  uint32_t state[8];
  uint64_t bit_length;
  uint8_t block[64];
  size_t block_length;
} fido2_sha256_context;

static const uint32_t sha256_constants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void secure_zeroize(void *buffer, size_t length)
{
  volatile uint8_t *bytes = (volatile uint8_t *)buffer;
  while (length-- > 0) *bytes++ = 0;
}

static uint32_t rotate_right(uint32_t value, unsigned bits)
{
  return (value >> bits) | (value << (32 - bits));
}

static void sha256_transform(fido2_sha256_context *context)
{
  uint32_t words[64];
  for (size_t i = 0; i < 16; i++) {
    size_t offset = i * 4;
    words[i] = ((uint32_t)context->block[offset] << 24) |
               ((uint32_t)context->block[offset + 1] << 16) |
               ((uint32_t)context->block[offset + 2] << 8) |
               context->block[offset + 3];
  }
  for (size_t i = 16; i < 64; i++) {
    uint32_t s0 = rotate_right(words[i - 15], 7) ^ rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3);
    uint32_t s1 = rotate_right(words[i - 2], 17) ^ rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10);
    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  uint32_t a = context->state[0], b = context->state[1], c = context->state[2], d = context->state[3];
  uint32_t e = context->state[4], f = context->state[5], g = context->state[6], h = context->state[7];
  for (size_t i = 0; i < 64; i++) {
    uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    uint32_t choose = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + sum1 + choose + sha256_constants[i] + words[i];
    uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = sum0 + majority;
    h = g; g = f; f = e; e = d + temp1;
    d = c; c = b; b = a; a = temp1 + temp2;
  }
  context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
  context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

static void sha256(const uint8_t *data, size_t length, uint8_t output[32])
{
  fido2_sha256_context context = {
    { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 },
    0, { 0 }, 0
  };
  for (size_t i = 0; i < length; i++) {
    context.block[context.block_length++] = data[i];
    if (context.block_length == 64) {
      sha256_transform(&context);
      context.bit_length += 512;
      context.block_length = 0;
    }
  }
  context.bit_length += (uint64_t)context.block_length * 8;
  context.block[context.block_length++] = 0x80;
  if (context.block_length > 56) {
    while (context.block_length < 64) context.block[context.block_length++] = 0;
    sha256_transform(&context);
    context.block_length = 0;
  }
  while (context.block_length < 56) context.block[context.block_length++] = 0;
  for (size_t i = 0; i < 8; i++)
    context.block[63 - i] = (uint8_t)(context.bit_length >> (i * 8));
  sha256_transform(&context);
  for (size_t i = 0; i < 8; i++) {
    output[i * 4] = (uint8_t)(context.state[i] >> 24);
    output[i * 4 + 1] = (uint8_t)(context.state[i] >> 16);
    output[i * 4 + 2] = (uint8_t)(context.state[i] >> 8);
    output[i * 4 + 3] = (uint8_t)context.state[i];
  }
}

int p256_generate_random(uint8_t *output, unsigned output_size)
{
  for (unsigned i = 0; i < output_size; i++) output[i] = rng_random_byte_impl();
  return P256_SUCCESS;
}

static mrb_value native_sha256(mrb_state *mrb, mrb_value self)
{
  char *data;
  mrb_int length;
  uint8_t digest[32];
  mrb_get_args(mrb, "s", &data, &length);
  sha256((const uint8_t *)data, (size_t)length, digest);
  return mrb_str_new(mrb, (const char *)digest, sizeof(digest));
}

static mrb_value native_generate_key_pair(mrb_state *mrb, mrb_value self)
{
  uint8_t private_key[32], public_key[64];
  if (p256_gen_keypair(private_key, public_key) != P256_SUCCESS)
    mrb_raise(mrb, E_RUNTIME_ERROR, "P-256 key generation failed");
  mrb_value pair[2] = {
    mrb_str_new(mrb, (const char *)private_key, sizeof(private_key)),
    mrb_str_new(mrb, (const char *)public_key, sizeof(public_key))
  };
  secure_zeroize(private_key, sizeof(private_key));
  return mrb_ary_new_from_values(mrb, 2, pair);
}

static mrb_value native_public_from_private(mrb_state *mrb, mrb_value self)
{
  char *private_key;
  mrb_int length;
  uint8_t public_key[64];
  mrb_get_args(mrb, "s", &private_key, &length);
  if (length != 32 || p256_public_from_private(public_key, (const uint8_t *)private_key) != P256_SUCCESS)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid P-256 private key");
  return mrb_str_new(mrb, (const char *)public_key, sizeof(public_key));
}

static mrb_value native_sign(mrb_state *mrb, mrb_value self)
{
  char *private_key, *digest;
  mrb_int private_length, digest_length;
  uint8_t signature[64];
  mrb_get_args(mrb, "ss", &private_key, &private_length, &digest, &digest_length);
  if (private_length != 32 || digest_length != 32 ||
      p256_ecdsa_sign(signature, (const uint8_t *)private_key, (const uint8_t *)digest, 32) != P256_SUCCESS)
    mrb_raise(mrb, E_RUNTIME_ERROR, "P-256 signing failed");
  return mrb_str_new(mrb, (const char *)signature, sizeof(signature));
}

static mrb_value native_verify(mrb_state *mrb, mrb_value self)
{
  char *public_key, *signature, *digest;
  mrb_int public_length, signature_length, digest_length;
  mrb_get_args(mrb, "sss", &public_key, &public_length, &signature, &signature_length, &digest, &digest_length);
  if (public_length != 64 || signature_length != 64 || digest_length != 32) return mrb_false_value();
  return mrb_bool_value(p256_ecdsa_verify((const uint8_t *)signature, (const uint8_t *)public_key,
                                          (const uint8_t *)digest, 32) == P256_SUCCESS);
}

static mrb_value native_ecdh(mrb_state *mrb, mrb_value self)
{
  char *private_key, *peer_public_key;
  mrb_int private_length, public_length;
  uint8_t secret[32];
  mrb_get_args(mrb, "ss", &private_key, &private_length, &peer_public_key, &public_length);
  if (private_length != 32 || public_length != 64 ||
      p256_ecdh_shared_secret(secret, (const uint8_t *)private_key,
                              (const uint8_t *)peer_public_key) != P256_SUCCESS)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid P-256 ECDH key");
  mrb_value result = mrb_str_new(mrb, (const char *)secret, sizeof(secret));
  secure_zeroize(secret, sizeof(secret));
  return result;
}

static mrb_value native_hmac_sha256(mrb_state *mrb, mrb_value self)
{
  char *key, *data;
  mrb_int key_length, data_length;
  uint8_t key_block[64] = {0}, inner_pad[64], outer_pad[64];
  uint8_t key_hash[32], inner_hash[32], digest[32];
  mrb_get_args(mrb, "ss", &key, &key_length, &data, &data_length);

  if (key_length > 64) {
    sha256((const uint8_t *)key, (size_t)key_length, key_hash);
    memcpy(key_block, key_hash, sizeof(key_hash));
  } else {
    memcpy(key_block, key, (size_t)key_length);
  }
  for (size_t i = 0; i < sizeof(key_block); i++) {
    inner_pad[i] = key_block[i] ^ 0x36;
    outer_pad[i] = key_block[i] ^ 0x5c;
  }

  size_t inner_length = sizeof(inner_pad) + (size_t)data_length;
  uint8_t *inner = mrb_malloc(mrb, inner_length);
  memcpy(inner, inner_pad, sizeof(inner_pad));
  memcpy(inner + sizeof(inner_pad), data, (size_t)data_length);
  sha256(inner, inner_length, inner_hash);
  secure_zeroize(inner, inner_length);
  mrb_free(mrb, inner);

  uint8_t outer[96];
  memcpy(outer, outer_pad, sizeof(outer_pad));
  memcpy(outer + sizeof(outer_pad), inner_hash, sizeof(inner_hash));
  sha256(outer, sizeof(outer), digest);
  mrb_value result = mrb_str_new(mrb, (const char *)digest, sizeof(digest));
  secure_zeroize(key_block, sizeof(key_block));
  secure_zeroize(key_hash, sizeof(key_hash));
  secure_zeroize(inner_hash, sizeof(inner_hash));
  secure_zeroize(inner_pad, sizeof(inner_pad));
  secure_zeroize(outer_pad, sizeof(outer_pad));
  secure_zeroize(outer, sizeof(outer));
  secure_zeroize(digest, sizeof(digest));
  return result;
}

static mrb_value native_aes256_cbc(mrb_state *mrb, bool encrypt)
{
  char *key, *input;
  mrb_int key_length, input_length;
  uint8_t iv[16] = {0};
  mrb_get_args(mrb, "ss", &key, &key_length, &input, &input_length);
  if (key_length != 32 || input_length < 0 || input_length % 16 != 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "AES-256-CBC requires a 32-byte key and block-aligned input");

  uint8_t *output = mrb_malloc(mrb, (size_t)input_length);
  mbedtls_aes_context context;
  mbedtls_aes_init(&context);
  int result = encrypt ? mbedtls_aes_setkey_enc(&context, (const uint8_t *)key, 256)
                       : mbedtls_aes_setkey_dec(&context, (const uint8_t *)key, 256);
  if (result == 0) {
    result = mbedtls_aes_crypt_cbc(&context,
                                  encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                  (size_t)input_length, iv, (const uint8_t *)input, output);
  }
  mbedtls_aes_free(&context);
  secure_zeroize(iv, sizeof(iv));
  if (result != 0) {
    secure_zeroize(output, (size_t)input_length);
    mrb_free(mrb, output);
    mrb_raise(mrb, E_RUNTIME_ERROR, "AES-256-CBC operation failed");
  }
  mrb_value value = mrb_str_new(mrb, (const char *)output, input_length);
  secure_zeroize(output, (size_t)input_length);
  mrb_free(mrb, output);
  return value;
}

static mrb_value native_aes256_cbc_encrypt(mrb_state *mrb, mrb_value self)
{
  return native_aes256_cbc(mrb, true);
}

static mrb_value native_aes256_cbc_decrypt(mrb_state *mrb, mrb_value self)
{
  return native_aes256_cbc(mrb, false);
}

static mrb_value native_usb_receive(mrb_state *mrb, mrb_value self)
{
#if defined(PICORB_PLATFORM_RP2)
  uint8_t report[64];
  if (!fido2_usb_pop_report(report)) return mrb_nil_value();
  return mrb_str_new(mrb, (const char *)report, sizeof(report));
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "FIDO HID is only available on RP2");
  return mrb_nil_value();
#endif
}

static mrb_value native_usb_send(mrb_state *mrb, mrb_value self)
{
  char *report;
  mrb_int length;
  mrb_get_args(mrb, "s", &report, &length);
  if (length != 64) mrb_raise(mrb, E_ARGUMENT_ERROR, "FIDO HID report must be 64 bytes");
#if defined(PICORB_PLATFORM_RP2)
  return mrb_bool_value(fido2_usb_push_report((const uint8_t *)report));
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "FIDO HID is only available on RP2");
  return mrb_false_value();
#endif
}

void mrb_picoruby_fido2_gem_init(mrb_state *mrb)
{
  struct RClass *fido2 = mrb_define_module(mrb, "FIDO2");
  struct RClass *crypto = mrb_define_module_under(mrb, fido2, "Crypto");
  struct RClass *native = mrb_define_module_under(mrb, crypto, "Native");
  mrb_define_module_function(mrb, native, "sha256", native_sha256, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, native, "generate_key_pair", native_generate_key_pair, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, native, "public_from_private", native_public_from_private, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, native, "sign", native_sign, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, native, "verify", native_verify, MRB_ARGS_REQ(3));
  mrb_define_module_function(mrb, native, "ecdh", native_ecdh, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, native, "hmac_sha256", native_hmac_sha256, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, native, "aes256_cbc_encrypt", native_aes256_cbc_encrypt, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, native, "aes256_cbc_decrypt", native_aes256_cbc_decrypt, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, native, "usb_receive", native_usb_receive, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, native, "usb_send", native_usb_send, MRB_ARGS_REQ(1));
}

void mrb_picoruby_fido2_gem_final(mrb_state *mrb)
{
  (void)mrb;
}
