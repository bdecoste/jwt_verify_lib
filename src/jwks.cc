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
#include "opensslcbs/cbs.h"
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

	bssl::UniquePtr<RSA> rsa = bssl::UniquePtr<RSA>(
        Openssl::Cbs::public_key_from_bytes(castToUChar(pkey_der), pkey_der.length()));


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
    BIGNUM *bn_x = createBigNumFromBase64UrlString(x);
    BIGNUM *bn_y = createBigNumFromBase64UrlString(y);
    if (!bn_x || !bn_y) {
      // EC public key field is missing or has parse error.
      updateStatus(Status::JwksEcParseError);
      return nullptr;
    }

    if (EC_KEY_set_public_key_affine_coordinates(ec_key.get(), bn_x,
                                                 bn_y) == 0) {
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

  BIGNUM* createBigNumFromBase64UrlString(
      const std::string& s) {
	  std::cerr << "!!!!!!!!!!!!!!!! createBigNumFromBase64UrlString \n";
    std::string s_decoded;
    if (!absl::WebSafeBase64Unescape(s, &s_decoded)) {
      return nullptr;
    }
    return BN_bin2bn(castToUChar(s_decoded), s_decoded.length(), NULL);
  }

  bssl::UniquePtr<RSA> createRsaFromJwk(const std::string& n,
                                          const std::string& e) {
	  std::cerr << "!!!!!!!!!!!!!!!! createRsaFromJwk \n";
	bssl::UniquePtr<RSA> rsa(RSA_new());
	BIGNUM *bn_n = createBigNumFromBase64UrlString(n);
	BIGNUM *bn_e = createBigNumFromBase64UrlString(e);

	if (bn_n == nullptr || bn_e == nullptr) {
      // RSA public key field is missing or has parse error.
		  std::cerr << "!!!!!!!!!!!!!!!! createRsaFromJwk JwksRsaParseError 1\n";
      updateStatus(Status::JwksRsaParseError);
	  return nullptr;
	}

	if (Openssl::Cbs::bn_cmp_word(bn_e, 3) != 0 && Openssl::Cbs::bn_cmp_word(bn_e, 65537) != 0) {
      // non-standard key; reject it early.
		  std::cerr << "!!!!!!!!!!!!!!!! createRsaFromJwk JwksRsaParseError 2\n";

	  BN_free(bn_n);
	  BN_free(bn_e);

      updateStatus(Status::JwksRsaParseError);

	  return nullptr;
	}

	int success = RSA_set0_key(rsa.get(), bn_n, bn_e, NULL);
	std::cerr << "!!!!!!!!!!!!!!!! createRsaFromJwk success " << success << " \n";
	return rsa;
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
	std::cerr << "!!!!!!!!!!!!!!!! createFrom \n";

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
	std::cerr << "!!!!!!!!!!!!!!!! createFromPemCore \n";

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
