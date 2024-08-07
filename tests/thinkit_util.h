// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PINS_INFRA_TESTS_THINKIT_UTIL_H_
#define PINS_INFRA_TESTS_THINKIT_UTIL_H_

#include "absl/time/time.h"
namespace pins_test {

constexpr char kEnabledFalse[] = "{\"enabled\":false}";
constexpr char kEnabledTrue[] = "{\"enabled\":true}";
constexpr char kStateUp[] = "UP";
constexpr char kStateDown[] = "DOWN";
constexpr char kStateNotPresent[] = "NOT_PRESENT";
constexpr char kInterfaces[] = "interfaces";
constexpr char kComponents[] = "components";
constexpr char kPortSpeed[] = "openconfig-if-ethernet:port-speed";
constexpr char kPlatformJson[] = "platform.json";
constexpr char kGB[] = "GB";

}  // namespace pins_test

#endif  // PINS_INFRA_TESTS_THINKIT_UTIL_H_
