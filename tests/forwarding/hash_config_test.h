// Copyright 2021 Google LLC
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

#ifndef PINS_INFRA_TESTS_FORWARDING_HASH_CONFIG_TEST_H_
#define PINS_INFRA_TESTS_FORWARDING_HASH_CONFIG_TEST_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "gtest/gtest.h"
#include "p4/config/v1/p4info.pb.h"
#include "tests/forwarding/hash_testfixture.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins_test {

struct HashConfigTestParameters {
  thinkit::MirrorTestbedInterface* mirror_testbed;
  p4::config::v1::P4Info p4_info;
};

// This class stores and reports data on received packets. Particularly, it
// keeps track of packets based on the egress port for the SUT / ingress port of
// the Control Switch.
// Test class for the hash config test.
class HashConfigTest
    : public HashTest,
      public testing::WithParamInterface<HashConfigTestParameters> {
 public:
  HashConfigTest()
      : HashTest(GetParam().mirror_testbed, std::move(GetParam().p4_info)) {}

  // Generates (by forwarding packets) and returns the baseline hash behavior of
  // the switch. If the baseline hash bevahior has already been generated,
  // returns a copy of the known behavior instead.
  absl::StatusOr<absl::flat_hash_map<std::string, TestData::ResultMap>>
  InitializeOrReturnBaselineHashResults(const p4::config::v1::P4Info& p4info);
};

}  // namespace pins_test

#endif  // PINS_INFRA_TESTS_FORWARDING_HASH_CONFIG_TEST_H_
