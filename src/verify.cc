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

#include "jwt_verify_lib/verify.h"
#include "absl/strings/string_view.h"

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

namespace google {
namespace jwt_verify {
namespace {

// A convinence inline cast function.
inline const uint8_t* castToUChar(const absl::string_view& str) {
  return reinterpret_cast<const uint8_t*>(str.data());
}

bool verifySignatureRSA(EVP_PKEY* key, const EVP_MD* md,
                        const uint8_t* signature, size_t signature_len,
                        const uint8_t* signed_data, size_t signed_data_len) {
  if (key == nullptr || md == nullptr || signature == nullptr ||
      signed_data == nullptr) {
    return false;
  }
  EVP_MD_CTX* md_ctx(EVP_MD_CTX_create());

  EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, key);
  EVP_DigestVerifyUpdate(md_ctx, signed_data, signed_data_len);
  return (EVP_DigestVerifyFinal(md_ctx, signature, signature_len) == 1);
}

bool verifySignatureRSA(EVP_PKEY* key, const EVP_MD* md,
                        absl::string_view signature,
                        absl::string_view signed_data) {
  return verifySignatureRSA(key, md, castToUChar(signature), signature.length(),
                            castToUChar(signed_data), signed_data.length());
}

bool verifySignatureEC(EC_KEY* key, const uint8_t* signature,
                       size_t signature_len, const uint8_t* signed_data,
                       size_t signed_data_len) {
  if (key == nullptr || signature == nullptr || signed_data == nullptr) {
    return false;
  }
  // ES256 signature should be 64 bytes.
  if (signature_len != 2 * 32) {
    return false;
  }

  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(signed_data, signed_data_len, digest);

  const ECDSA_SIG* ecdsa_sig(ECDSA_SIG_new());
  if (!ecdsa_sig) {
    return false;
  }

  const BIGNUM *pr, *ps;
  ECDSA_SIG_get0(ecdsa_sig, &pr, &ps);

  if (BN_bin2bn(signature, 32, const_cast<BIGNUM*>(pr)) == nullptr ||
      BN_bin2bn(signature + 32, 32, const_cast<BIGNUM*>(ps)) == nullptr) {
    return false;
  }
  return (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, ecdsa_sig, key) ==
          1);
}

bool verifySignatureEC(EC_KEY* key, absl::string_view signature,
                       absl::string_view signed_data) {
  return verifySignatureEC(key, castToUChar(signature), signature.length(),
                           castToUChar(signed_data), signed_data.length());
}

}  // namespace

Status verifyJwt(const Jwt& jwt, const Jwks& jwks) {
  std::string signed_data =
      jwt.header_str_base64url_ + '.' + jwt.payload_str_base64url_;
  bool kid_alg_matched = false;
  for (const auto& jwk : jwks.keys()) {
    // If kid is specified in JWT, JWK with the same kid is used for
    // verification.
    // If kid is not specified in JWT, try all JWK.
    if (!jwt.kid_.empty() && jwk->kid_specified_ && jwk->kid_ != jwt.kid_) {
      continue;
    }

    // The same alg must be used.
    if (jwk->alg_specified_ && jwk->alg_ != jwt.alg_) {
      continue;
    }
    kid_alg_matched = true;

    if (jwk->kty_ == "EC" &&
        verifySignatureEC(jwk->ec_key_, jwt.signature_, signed_data)) {
      // Verification succeeded.
      return Status::Ok;
    } else if ((jwk->pem_format_ || jwk->kty_ == "RSA") &&
               verifySignatureRSA(jwk->evp_pkey_, EVP_sha256(),
                                  jwt.signature_, signed_data)) {
      // Verification succeeded.
      return Status::Ok;
    }
  }

  // Verification failed.
  return kid_alg_matched ? Status::JwtVerificationFail
                         : Status::JwksKidAlgMismatch;
}

}  // namespace jwt_verify
}  // namespace google
