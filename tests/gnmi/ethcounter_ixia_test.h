// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef PINS_INFRA_TEST_GNMI_ETHCOUNTER_IXIA_TEST_H_
#define PINS_INFRA_TEST_GNMI_ETHCOUNTER_IXIA_TEST_H_

#include "absl/container/flat_hash_map.h"
#include "thinkit/generic_testbed_fixture.h"

namespace pins_test {

// Parameters used by the Counter tests.
struct ParamsForCountersTest {
  thinkit::GenericTestbedInterface* testbed_interface;
  p4::config::v1::P4Info p4_info;
  // CPU queue to use for any punted traffic.
  std::string cpu_queue_to_use;
  // DSCP to queue mapping.
  absl::flat_hash_map<int, std::string> queue_by_dscp;
};

class CountersTestFixture
    : public testing::TestWithParam<ParamsForCountersTest> {
 protected:
  void SetUp() override { GetParam().testbed_interface->SetUp(); }

  void TearDown() override { GetParam().testbed_interface->TearDown(); }

  ~CountersTestFixture() override { delete GetParam().testbed_interface; }
};

}  // namespace pins_test

#endif  // PINS_INFRA_TEST_GNMI_ETHCOUNTER_IXIA_TEST_H_
