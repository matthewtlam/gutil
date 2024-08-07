// Copyright 2024 Google LLC
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

#ifndef PINS_INFRA_TESTS_PACKET_CAPTURE_PACKET_CAPTURE_TEST_H_
#define PINS_INFRA_TESTS_PACKET_CAPTURE_PACKET_CAPTURE_TEST_H_
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins_test {
// Parameters used by tests that don't require an Ixia.
struct ParamsForPacketCaptureTestsWithoutIxia {
  // Using a shared_ptr because parameterized tests require objects to be
  // copyable.
  std::shared_ptr<thinkit::MirrorTestbedInterface> testbed_interface;
  packetlib::Packet test_packet;
};

// These tests must be run on a testbed where the SUT is connected
// to a "control device" that can send and received packets.
class PacketCaptureTestWithoutIxia
    : public testing::TestWithParam<ParamsForPacketCaptureTestsWithoutIxia> {
 protected:
  void SetUp() override { GetParam().testbed_interface->SetUp(); }

  thinkit::MirrorTestbed& Testbed() {
    return GetParam().testbed_interface->GetMirrorTestbed();
  }

  void TearDown() override { GetParam().testbed_interface->TearDown(); }
};

}  // namespace pins_test

#endif  // PINS_INFRA_TESTS_PACKET_CAPTURE_PACKET_CAPTURE_TEST_H_
