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

#ifndef PINS_INFRA_TESTS_THINKIT_GNMI_INTERFACE_TESTS_H_
#define PINS_INFRA_TESTS_THINKIT_GNMI_INTERFACE_TESTS_H_

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "p4/config/v1/p4info.pb.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "tests/thinkit_gnmi_interface_util.h"
#include "thinkit/ssh_client.h"
#include "thinkit/switch.h"

namespace pins_test {

// Test port breakout during parent port in use.
void TestGNMIParentPortInUseDuringBreakout(
    thinkit::Switch& sut, std::string& platform_json_contents,
    const p4::config::v1::P4Info& p4_info);

// Test port breakout during child port in use.
void TestGNMIChildPortInUseDuringBreakout(
    thinkit::Switch& sut, std::string& platform_json_contents,
    const p4::config::v1::P4Info& p4_info);

// Test port breakout on a port while other master port is in use.
void TestGNMIOtherMasterPortInUseDuringBreakout(
    thinkit::Switch& sut, std::string& platform_json_contents,
    const p4::config::v1::P4Info& p4_info);

// Helper function to test port in use.
void BreakoutDuringPortInUse(thinkit::Switch& sut,
                             gnmi::gNMI::StubInterface* sut_gnmi_stub,
                             RandomPortBreakoutInfo port_info,
                             absl::string_view platform_json_contents,
                             absl::string_view port_in_use,
                             const p4::config::v1::P4Info& p4_info,
                             const bool expect_breakout_failure);

}  // namespace pins_test
#endif  // PINS_INFRA_TESTS_THINKIT_GNMI_INTERFACE_TESTS_H_
