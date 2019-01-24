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
// limitations under the License.#pragma once

#pragma once

#include <string>
#include <vector>

#include "bssl_wrapper/bssl_wrapper.h"

namespace google {
namespace jwt_verify {

class Cbs {
  public:
	Cbs(const uint8_t *data, size_t len);
	const uint8_t *data_;
	size_t len_;
};


}  // namespace jwt_verify
}  // namespace google
