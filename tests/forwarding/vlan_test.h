// Copyright 2024 Google LLC
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

#ifndef PINS_INFRA_TESTS_FORWARDING_VLAN_TEST_H_
#define PINS_INFRA_TESTS_FORWARDING_VLAN_TEST_H_

#include <memory>
#include <optional>

#include "dvaas/dataplane_validation.h"
#include "gtest/gtest.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins_test {

struct VlanTestParams {
  std::shared_ptr<thinkit::MirrorTestbedInterface> testbed;
  // If provided, installs the P4Info on the SUT. Otherwise, uses the P4Info
  // already on the SUT.
  std::optional<p4::config::v1::P4Info> sut_p4info;
  sai::Instantiation sut_instantiation;
  std::shared_ptr<dvaas::DataplaneValidator> validator;
  dvaas::DataplaneValidationParams validation_params;
};

class VlanTestFixture : public testing::TestWithParam<VlanTestParams> {
 public:
  void SetUp() override;
  void TearDown() override;

 protected:
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session_;
  pdpi::IrP4Info sut_ir_p4info_;
};

}  // namespace pins_test

#endif  // PINS_INFRA_TESTS_FORWARDING_VLAN_TEST_H_
