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

#ifndef PINS_INFRA_TESTS_FORWARDING_WATCH_PORT_TEST_H_
#define PINS_INFRA_TESTS_FORWARDING_WATCH_PORT_TEST_H_

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "gtest/gtest.h"
#include "lib/gnmi/openconfig.pb.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "proto/gnmi/gnmi.grpc.pb.h"
#include "tests/forwarding/packet_test_util.h"
#include "thinkit/mirror_testbed_fixture.h"
#include "thinkit/switch.h"

namespace gpins {

// Holds the common params needed for watch port test.
struct WatchPortTestParams {
  thinkit::MirrorTestbedInterface* testbed;
  // The test assumes that the switch is pre-configured if no `gnmi_config` is
  // given (default), or otherwise pushes the given config before starting.
  std::optional<std::string> gnmi_config;
  // P4Info to be used based on a specific instantiation.
  p4::config::v1::P4Info p4_info;
  // Optional function that raises critical alarm in the system.
  // Sets the system in critical state so that watch port down action can be
  // verified to work as expected. If this function is not provided, the
  // critical state related tests will be skipped.
  absl::optional<std::function<absl::Status(thinkit::Switch& test_switch)>>
      set_critical_alarm;
};

// WatchPortTestFixture for testing watch port action.
class WatchPortTestFixture
    : public testing::TestWithParam<WatchPortTestParams> {
 protected:
  void SetUp() override;

  void TearDown() override;

  TestData test_data_;
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4_session_;
  std::unique_ptr<pdpi::P4RuntimeSession> control_p4_session_;
  std::unique_ptr<gnmi::gNMI::StubInterface> sut_gnmi_stub_;
  std::unique_ptr<gnmi::gNMI::StubInterface> control_gnmi_stub_;

  // Captures the control interfaces at the start of the test. These may be
  // changed during testing to mirror those of the SUT. They will then be
  // returned to their previous state during teardown.
  pins_test::openconfig::Interfaces original_control_interfaces_;
};

}  // namespace gpins

#endif  // PINS_INFRA_TESTS_FORWARDING_WATCH_PORT_TEST_H_
