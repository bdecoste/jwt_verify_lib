// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <iostream>
#include <fstream>

#include "absl/strings/escaping.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"
#include "jwt_verify_lib/cbs.h"
#include "jwt_verify_lib/jwks.h"
#include "src/struct_utils.h"

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

namespace google {
namespace jwt_verify {

namespace {

// A convinence inline cast function.
inline const uint8_t* castToUChar(const std::string& str) {
  return reinterpret_cast<const uint8_t*>(str.c_str());
}

inline const char* castToChar(const std::string& str) {
  return reinterpret_cast<const char*>(str.c_str());
}

/** Class to create EVP_PKEY object from string of public key, formatted in PEM
 * or JWKs.
 * If it failed, status_ holds the failure reason.
 *
 * Usage example:
 * EvpPkeyGetter e;
 * bssl::UniquePtr<EVP_PKEY> pkey =
 * e.createEvpPkeyFromStr(pem_formatted_public_key);
 * (You can use createEvpPkeyFromJwkRSA() or createEcKeyFromJwkEC() for JWKs)
 */
class EvpPkeyGetter : public WithStatus {
 public:
  // Create EVP_PKEY from PEM string
  bssl::UniquePtr<EVP_PKEY> createEvpPkeyFromStr(const std::string& pkey_pem) {
	  std::cerr << "!!!!!!!!!!!!!!!! createEvpPkeyFromStr \n";
    // Header "-----BEGIN CERTIFICATE ---"and tailer "-----END CERTIFICATE ---"
    // should have been removed.

	std::string pkey_der;
	if (!absl::Base64Unescape(pkey_pem, &pkey_der) || pkey_der.empty()) {
	  updateStatus(Status::JwksPemBadBase64);
	  return nullptr;
	}

    auto rsa = bssl::UniquePtr<RSA>(
        public_key_from_bytes(castToUChar(pkey_der), pkey_der.length()));


    if (!rsa) {
	  updateStatus(Status::JwksPemParseError);
	  return nullptr;
	}
    return createEvpPkeyFromRsa(rsa.get());
  }

  bssl::UniquePtr<EVP_PKEY> createEvpPkeyFromJwkRSA(const std::string& n,
                                                    const std::string& e) {
	  std::cerr << "!!!!!!!!!!!!!!!! createEvpPkeyFromJwkRSA \n";
    return createEvpPkeyFromRsa(createRsaFromJwk(n, e).get());
  }

  bssl::UniquePtr<EC_KEY> createEcKeyFromJwkEC(const std::string& x,
                                               const std::string& y) {
	  std::cerr << "!!!!!!!!!!!!!!!! createEcKeyFromJwkEC \n";
    bssl::UniquePtr<EC_KEY> ec_key(
        EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!ec_key) {
      updateStatus(Status::JwksEcCreateKeyFail);
      return nullptr;
    }
    bssl::UniquePtr<BIGNUM> bn_x = createBigNumFromBase64UrlString(x);
    bssl::UniquePtr<BIGNUM> bn_y = createBigNumFromBase64UrlString(y);
    if (!bn_x || !bn_y) {
      // EC public key field is missing or has parse error.
      updateStatus(Status::JwksEcParseError);
      return nullptr;
    }

    if (EC_KEY_set_public_key_affine_coordinates(ec_key.get(), bn_x.get(),
                                                 bn_y.get()) == 0) {
      updateStatus(Status::JwksEcParseError);
      return nullptr;
    }
    return ec_key;
  }

 private:
  bssl::UniquePtr<EVP_PKEY> createEvpPkeyFromRsa(RSA* rsa) {
	  std::cerr << "!!!!!!!!!!!!!!!! createEvpPkeyFromRsa \n";
    if (!rsa) {
      return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
    EVP_PKEY_set1_RSA(key.get(), rsa);
    return key;
  }

  bssl::UniquePtr<BIGNUM> createBigNumFromBase64UrlString(
      const std::string& s) {
	  std::cerr << "!!!!!!!!!!!!!!!! createBigNumFromBase64UrlString \n";
    std::string s_decoded;
    if (!absl::WebSafeBase64Unescape(s, &s_decoded)) {
      return nullptr;
    }
    return bssl::UniquePtr<BIGNUM>(
        BN_bin2bn(castToUChar(s_decoded), s_decoded.length(), NULL));
  }

  bssl::UniquePtr<RSA> createRsaFromJwk(const std::string& n,
                                          const std::string& e) {
	  std::cerr << "!!!!!!!!!!!!!!!! createRsaFromJwk \n";
	bssl::UniquePtr<RSA> rsa(RSA_new());
	bssl::UniquePtr<BIGNUM> bn_n = createBigNumFromBase64UrlString(n);
	bssl::UniquePtr<BIGNUM> bn_e = createBigNumFromBase64UrlString(e);

	if (bn_n.get() == nullptr || bn_e.get() == nullptr) {
      // RSA public key field is missing or has parse error.
      updateStatus(Status::JwksRsaParseError);
	  return nullptr;
	}
	RSA_set0_key(rsa.get(), bn_n.get(), bn_e.get(), NULL);
	if (bn_cmp_word(bn_e.get(), 3) != 0 && bn_cmp_word(bn_e.get(), 65537) != 0) {
      // non-standard key; reject it early.
      updateStatus(Status::JwksRsaParseError);
	  return nullptr;
	}
	return rsa;
  }

  int bn_cmp_word(const BIGNUM *a, BN_ULONG b) {
	  std::cerr << "!!!!!!!!!!!!!!!! bn_cmp_word \n";
    BIGNUM* b_bn = BN_new();

    BN_set_word(b_bn, b);
    BN_set_flags(b_bn, BN_FLG_STATIC_DATA);

    int result = BN_cmp(a, b_bn);

    BN_free(b_bn);

    return result;
  }

  RSA* public_key_from_bytes(const uint8_t *in, size_t in_len) {
	  std::cerr << "!!!!!!!!!!!!!!!! public_key_from_bytes \n";
    Cbs cbs(in, in_len);
    RSA* ret = parse_public_key(&cbs);
    if (ret == NULL) {
      return NULL;
    }
    return ret;
  }

  RSA* parse_public_key(Cbs *cbs) {
	  std::cerr << "!!!!!!!!!!!!!!!! parse_public_key \n";
	RSA *rsa = RSA_new();
    if (rsa == NULL) {
  	  return NULL;
    }
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_e = NULL;
    Cbs child(NULL, 0);
    if (!cbs_get_asn1(cbs, &child, CBS_ASN1_SEQUENCE, 1)){
      RSA_free(rsa);
      return NULL;
    } else {

      if (!parse_integer(&child, &bn_n) || !parse_integer(&child, &bn_e) || child.len_ != 0) {
        RSA_free(rsa);
        return NULL;
      } else {
    	 RSA_set0_key(rsa, bn_n, bn_e, NULL);
      }
    }

    if (!BN_is_odd(bn_e) ||
        BN_num_bits(bn_e) < 2) {
      RSA_free(rsa);
      return NULL;
    }

    return rsa;
  }

  int cbs_get_asn1(Cbs *cbs, Cbs *out, unsigned tag_value,
                          int skip_header) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_asn1 \n";
    size_t header_len;
    unsigned tag;
    Cbs throwaway(NULL, 0);

    if (out == NULL) {
      out = &throwaway;
    }

    if (!cbs_get_any_asn1_element(cbs, out, &tag, &header_len, 0) ||
        tag != tag_value) {
      return 0;
    }

    if (skip_header && !cbs_skip(out, header_len)) {
      assert(0);
      return 0;
    }

    return 1;
  }

  int cbs_skip(Cbs *cbs, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_skip \n";
    const uint8_t *dummy;
    return cbs_get(cbs, &dummy, len);
  }

  int cbs_get(Cbs *cbs, const uint8_t **p, size_t n) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get \n";
    if (cbs->len_ < n) {
      return 0;
    }

    *p = cbs->data_;
    cbs->data_ += n;
    cbs->len_ -= n;
    return 1;
  }

  int cbs_get_any_asn1_element(Cbs *cbs, Cbs *out, unsigned *out_tag,
                                      size_t *out_header_len, int ber_ok) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_any_asn1_element \n";
    Cbs header = *cbs;
    Cbs throwaway(NULL, 0);

    if (out == NULL) {
      out = &throwaway;
    }

    unsigned tag;
    if (!parse_asn1_tag(&header, &tag)) {
      return 0;
    }
    if (out_tag != NULL) {
      *out_tag = tag;
    }

    uint8_t length_byte;
    if (!cbs_get_u8(&header, &length_byte)) {
      return 0;
    }

    size_t header_len = cbs->len_ - header.len_;

    size_t len;
    // The format for the length encoding is specified in ITU-T X.690 section
    // 8.1.3.
    if ((length_byte & 0x80) == 0) {
      // Short form length.
      len = ((size_t) length_byte) + header_len;
      if (out_header_len != NULL) {
        *out_header_len = header_len;
      }
    } else {
      // The high bit indicate that this is the long form, while the next 7 bits
      // encode the number of subsequent octets used to encode the length (ITU-T
      // X.690 clause 8.1.3.5.b).
      const size_t num_bytes = length_byte & 0x7f;
      uint32_t len32;

      if (ber_ok && (tag & CBS_ASN1_CONSTRUCTED) != 0 && num_bytes == 0) {
        // indefinite length
        if (out_header_len != NULL) {
          *out_header_len = header_len;
        }
        return cbs_get_bytes(cbs, out, header_len);
      }

      // ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
      // used as the first byte of the length. If this parser encounters that
      // value, num_bytes will be parsed as 127, which will fail the check below.
      if (num_bytes == 0 || num_bytes > 4) {
        return 0;
      }
      if (!cbs_get_u(&header, &len32, num_bytes)) {
        return 0;
      }
      // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
      // with the minimum number of octets.
      if (len32 < 128) {
        // Length should have used short-form encoding.
        return 0;
      }
      if ((len32 >> ((num_bytes-1)*8)) == 0) {
        // Length should have been at least one byte shorter.
        return 0;
      }
      len = len32;
      if (len + header_len + num_bytes < len) {
        // Overflow.
        return 0;
      }
      len += header_len + num_bytes;
      if (out_header_len != NULL) {
        *out_header_len = header_len + num_bytes;
      }
    }

    return cbs_get_bytes(cbs, out, len);
  }

  int cbs_get_u(Cbs *cbs, uint32_t *out, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_u \n";
    uint32_t result = 0;
    const uint8_t *data;

    if (!cbs_get(cbs, &data, len)) {
      return 0;
    }
    for (size_t i = 0; i < len; i++) {
      result <<= 8;
      result |= data[i];
    }
    *out = result;
    return 1;
  }


  int cbs_get_bytes(Cbs *cbs, Cbs *out, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_bytes \n";
    const uint8_t *v;
    if (!cbs_get(cbs, &v, len)) {
      return 0;
    }
    cbs_init(out, v, len);
    return 1;
  }

  void cbs_init(Cbs *cbs, const uint8_t *data, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_init \n";
    cbs->data_ = data;
    cbs->len_ = len;
  }

  int cbs_get_u8(Cbs *cbs, uint8_t *out) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_u8 \n";
    const uint8_t *v;
    if (!cbs_get(cbs, &v, 1)) {
      return 0;
    }
    *out = *v;
    return 1;
  }

  int parse_asn1_tag(Cbs *cbs, unsigned *out) {
	  std::cerr << "!!!!!!!!!!!!!!!! parse_asn1_tag \n";
    uint8_t tag_byte;
    if (!cbs_get_u8(cbs, &tag_byte)) {
      return 0;
    }

    // ITU-T X.690 section 8.1.2.3 specifies the format for identifiers with a tag
    // number no greater than 30.
    //
    // If the number portion is 31 (0x1f, the largest value that fits in the
    // allotted bits), then the tag is more than one byte long and the
    // continuation bytes contain the tag number. This parser only supports tag
    // numbers less than 31 (and thus single-byte tags).
    unsigned tag = ((unsigned)tag_byte & 0xe0) << CBS_ASN1_TAG_SHIFT;
    unsigned tag_number = tag_byte & 0x1f;
    if (tag_number == 0x1f) {
      uint64_t v;
      if (!parse_base128_integer(cbs, &v) ||
          // Check the tag number is within our supported bounds.
          v > CBS_ASN1_TAG_NUMBER_MASK ||
          // Small tag numbers should have used low tag number form.
          v < 0x1f) {
        return 0;
      }
      tag_number = (unsigned)v;
    }

    tag |= tag_number;

    *out = tag;
    return 1;
  }

  int bn_parse_asn1_unsigned(Cbs *cbs, BIGNUM *ret) {
	  std::cerr << "!!!!!!!!!!!!!!!! bn_parse_asn1_unsigned \n";
    Cbs child(NULL, 0);
    if (!cbs_get_asn1(cbs, &child, CBS_ASN1_INTEGER, 1) || child.len_ == 0) {
//      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
      return 0;
    }

    if (child.data_[0] & 0x80) {
//      OPENSSL_PUT_ERROR(BN, BN_R_NEGATIVE_NUMBER);
      return 0;
    }

    // INTEGERs must be minimal.
    if (child.data_[0] == 0x00 &&
        child.len_ > 1 &&
        !(child.data_[1] & 0x80)) {
//      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
      return 0;
    }

    return BN_bin2bn(child.data_, child.len_, ret) != NULL;
  }


  int parse_base128_integer(Cbs *cbs, uint64_t *out) {
	  std::cerr << "!!!!!!!!!!!!!!!! parse_base128_integer \n";
    uint64_t v = 0;
    uint8_t b;
    do {
      if (!cbs_get_u8(cbs, &b)) {
        return 0;
      }
      if ((v >> (64 - 7)) != 0) {
        // The value is too large.
        return 0;
      }
      if (v == 0 && b == 0x80) {
        // The value must be minimally encoded.
        return 0;
      }
      v = (v << 7) | (b & 0x7f);

      // Values end at an octet with the high bit cleared.
    } while (b & 0x80);

    *out = v;
    return 1;
  }


  int parse_integer(Cbs *cbs, BIGNUM **out) {
		std::cerr << "!!!!!!!!!!!!!!!! parse_integer \n";

    assert(*out == NULL);
    *out = BN_new();
    if (*out == NULL) {
      return 0;
    }
    return bn_parse_asn1_unsigned(cbs, *out);
  }

};

Status extractJwkFromJwkRSA(const ::google::protobuf::Struct& jwk_pb,
                            Jwks::Pubkey* jwk) {
	std::cerr << "!!!!!!!!!!!!!!!! extractJwkFromJwkRSA \n";

  if (jwk->alg_specified_ &&
      (jwk->alg_.size() < 2 || jwk->alg_.compare(0, 2, "RS") != 0)) {
    return Status::JwksRSAKeyBadAlg;
  }

  StructUtils jwk_getter(jwk_pb);
  std::string n_str;
  auto code = jwk_getter.GetString("n", &n_str);
  if (code == StructUtils::MISSING) {
    return Status::JwksRSAKeyMissingN;
  }
  if (code == StructUtils::WRONG_TYPE) {
    return Status::JwksRSAKeyBadN;
  }

  std::string e_str;
  code = jwk_getter.GetString("e", &e_str);
  if (code == StructUtils::MISSING) {
    return Status::JwksRSAKeyMissingE;
  }
  if (code == StructUtils::WRONG_TYPE) {
    return Status::JwksRSAKeyBadE;
  }

  EvpPkeyGetter e;
  jwk->evp_pkey_ = e.createEvpPkeyFromJwkRSA(n_str, e_str);
  return e.getStatus();
}

Status extractJwkFromJwkEC(const ::google::protobuf::Struct& jwk_pb,
                           Jwks::Pubkey* jwk) {
	std::cerr << "!!!!!!!!!!!!!!!! extractJwkFromJwkEC \n";

  if (jwk->alg_specified_ && jwk->alg_ != "ES256") {
    return Status::JwksECKeyBadAlg;
  }

  StructUtils jwk_getter(jwk_pb);
  std::string x_str;
  auto code = jwk_getter.GetString("x", &x_str);
  if (code == StructUtils::MISSING) {
    return Status::JwksECKeyMissingX;
  }
  if (code == StructUtils::WRONG_TYPE) {
    return Status::JwksECKeyBadX;
  }

  std::string y_str;
  code = jwk_getter.GetString("y", &y_str);
  if (code == StructUtils::MISSING) {
    return Status::JwksECKeyMissingY;
  }
  if (code == StructUtils::WRONG_TYPE) {
    return Status::JwksECKeyBadY;
  }

  EvpPkeyGetter e;
  jwk->ec_key_ = e.createEcKeyFromJwkEC(x_str, y_str);
  return e.getStatus();
}


Status extractJwk(const ::google::protobuf::Struct& jwk_pb, Jwks::Pubkey* jwk) {
	std::cerr << "!!!!!!!!!!!!!!!! extractJwk \n";

  StructUtils jwk_getter(jwk_pb);
  // Check "kty" parameter, it should exist.
  // https://tools.ietf.org/html/rfc7517#section-4.1
  auto code = jwk_getter.GetString("kty", &jwk->kty_);
  if (code == StructUtils::MISSING) {
    return Status::JwksMissingKty;
  }
  if (code == StructUtils::WRONG_TYPE) {
    return Status::JwksBadKty;
  }

  // "kid" and "alg" are optional, if they do not exist, set them to empty.
  // https://tools.ietf.org/html/rfc7517#page-8
  code = jwk_getter.GetString("kid", &jwk->kid_);
  if (code == StructUtils::OK) {
    jwk->kid_specified_ = true;
  }
  code = jwk_getter.GetString("alg", &jwk->alg_);
  if (code == StructUtils::OK) {
    jwk->alg_specified_ = true;
  }

  // Extract public key according to "kty" value.
  // https://tools.ietf.org/html/rfc7518#section-6.1
  if (jwk->kty_ == "EC") {
    return extractJwkFromJwkEC(jwk_pb, jwk);
  } else if (jwk->kty_ == "RSA") {
    return extractJwkFromJwkRSA(jwk_pb, jwk);
  }
  return Status::JwksNotImplementedKty;
}

}  // namespace

JwksPtr Jwks::createFrom(const std::string& pkey, Type type) {
  JwksPtr keys(new Jwks());
  switch (type) {
    case Type::JWKS:
      keys->createFromJwksCore(pkey);
      break;
    case Type::PEM:
      keys->createFromPemCore(pkey);
      break;
    default:
      break;
  }
  return keys;
}

void Jwks::createFromPemCore(const std::string& pkey_pem) {
  keys_.clear();
  PubkeyPtr key_ptr(new Pubkey());
  EvpPkeyGetter e;
  key_ptr->evp_pkey_ = e.createEvpPkeyFromStr(pkey_pem);
  key_ptr->pem_format_ = true;
  updateStatus(e.getStatus());
  assert((key_ptr->evp_pkey_ == nullptr) == (e.getStatus() != Status::Ok));
  if (e.getStatus() == Status::Ok) {
    keys_.push_back(std::move(key_ptr));
  }
}

void Jwks::createFromJwksCore(const std::string& jwks_json) {
std::cerr << "!!!!!!!!!!!!!!!! createFromJwksCore \n";

  keys_.clear();

  ::google::protobuf::util::JsonParseOptions options;
  ::google::protobuf::Struct jwks_pb;
  const auto status = ::google::protobuf::util::JsonStringToMessage(
      jwks_json, &jwks_pb, options);
  if (!status.ok()) {
    updateStatus(Status::JwksParseError);
    return;
  }

  const auto& fields = jwks_pb.fields();
  const auto keys_it = fields.find("keys");
  if (keys_it == fields.end()) {
    updateStatus(Status::JwksNoKeys);
    return;
  }
  if (keys_it->second.kind_case() != google::protobuf::Value::kListValue) {
    updateStatus(Status::JwksBadKeys);
    return;
  }

  for (const auto& key_value : keys_it->second.list_value().values()) {
    if (key_value.kind_case() != ::google::protobuf::Value::kStructValue) {
      continue;
    }
    PubkeyPtr key_ptr(new Pubkey());
    Status status = extractJwk(key_value.struct_value(), key_ptr.get());
    if (status == Status::Ok) {
      keys_.push_back(std::move(key_ptr));
    } else {
      updateStatus(status);
      break;
    }
  }

  if (keys_.empty()) {
    updateStatus(Status::JwksNoValidKeys);
  }

  std::cerr << "!!!!!!!!!!!!!!!! done createFromJwksCore \n";
}

}  // namespace jwt_verify
}  // namespace google
