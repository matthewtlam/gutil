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

#include "tests/forwarding/hash_config_test.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/proto_matchers.h"
#include "gutil/status.h"           // IWYU pragma: keep
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "lib/gnmi/gnmi_helper.h"
#include "lib/gnmi/openconfig.pb.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "proto/gnmi/gnmi.pb.h"
#include "re2/re2.h"
#include "tests/forwarding/hash_testfixture.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/test_environment.h"

namespace pins_test {
namespace {

using ::gutil::EqualsProto;
using ::testing::Not;
using ::testing::UnorderedElementsAreArray;

// The number of packets to generate for each test config.
constexpr int kNumPackets = 100;

// Modify the hash seed in the P4Info.
void ModifyHashSeed(const p4::config::v1::P4Info& original_p4info,
                    p4::config::v1::P4Info& modified_p4info) {
  std::string p4info_str = gutil::PrintTextProto(original_p4info);
  uint32_t original_seed;
  ASSERT_TRUE(RE2::PartialMatch(p4info_str, R"re(sai_hash_seed\(([^)]*)\))re",
                                &original_seed))
      << "Failed to find a hash seed in original P4Info.";
  uint32_t new_seed = original_seed ^ 0xAAAAAAAA;
  LOG(INFO) << "Changing hash seed from " << original_seed << " to "
            << new_seed;
  ASSERT_TRUE(RE2::Replace(&p4info_str, R"re(sai_hash_seed\([^)]*\))re",
                           absl::Substitute("sai_hash_seed($0)", new_seed)))
      << "Failed to replace the hash seed in the original P4Info.";
  ASSERT_OK_AND_ASSIGN(
      modified_p4info,
      gutil::ParseTextProto<p4::config::v1::P4Info>(p4info_str));
  ASSERT_THAT(modified_p4info, Not(EqualsProto(original_p4info)))
      << "Failed to replace the hash seed in the original P4Info.";
}

const TestPacketMap& HashingTestPackets() {
  static const auto* const kPackets = new TestPacketMap(
      *HashTest::GeneratePackets(HashingTestConfigs(), kNumPackets,
                                 HashTest::PacketGeneratorStyle::kSequential));
  return *kPackets;
}

}  // namespace

absl::StatusOr<absl::flat_hash_map<std::string, HashTest::TestData::ResultMap>>
HashConfigTest::InitializeOrReturnBaselineHashResults(
    const p4::config::v1::P4Info& p4info) {
  static auto* static_hash_results =
      new absl::node_hash_map<std::string, TestData>();
  static bool initialized = false;
  if (!initialized) {
    static_hash_results->clear();
    RETURN_IF_ERROR(SendPacketsToDefaultPortAndRecordResultsPerTest(
        HashingTestPackets(), p4info, "0_original", *static_hash_results));
    initialized = true;
  }
  absl::flat_hash_map<std::string, TestData::ResultMap> baseline_hash_results;
  for (const auto& [config, data] : *static_hash_results) {
    baseline_hash_results[config] = data.Results();
  }
  return baseline_hash_results;
}

TEST_P(HashConfigTest, HashIsStableWithSameSettings) {
  p4::config::v1::P4Info modified_p4info;
  ASSERT_NO_FATAL_FAILURE(ModifyHashSeed(test_p4_info(), modified_p4info));

  ASSERT_NO_FATAL_FAILURE(ForwardAllPacketsToPorts(test_p4_info(), PortIds()));

  absl::flat_hash_map<std::string, TestData::ResultMap> baseline_hash_results;
  ASSERT_OK_AND_ASSIGN(baseline_hash_results,
                       InitializeOrReturnBaselineHashResults(test_p4_info()));

  // Clear entities and modify the hash field. Then re-apply the original
  // settings to verify that the result is consistent when the original settings
  // are restored.
  ASSERT_OK(pdpi::ClearEntities(sut_p4_session()));
  ASSERT_OK(UpdateSutP4Info(modified_p4info));
  ASSERT_OK(UpdateSutP4Info(test_p4_info()));
  ASSERT_NO_FATAL_FAILURE(ForwardAllPacketsToPorts(test_p4_info(), PortIds()));

  // Send packets and record hash results.
  absl::node_hash_map<std::string, TestData> hash_test_data;
  ASSERT_OK(SendPacketsToDefaultPortAndRecordResultsPerTest(
      HashingTestPackets(), test_p4_info(), "1_original", hash_test_data));

  // Ensure that the same packet set with the same hash parameters produces
  // the same result.
  for (const auto& config : HashingTestConfigNames()) {
    EXPECT_THAT(hash_test_data.at(config).Results(),
                UnorderedElementsAreArray(baseline_hash_results.at(config)))
        << "No hash diff found for config: " << config;
  }
}

TEST_P(HashConfigTest, GnmiHashAlgorithmSettingsAffectPacketHash) {
  GetMirrorTestbed().Environment().SetTestCaseID(
      "1de932e8-666c-4ee4-960f-3a3aac717a25");

  ASSERT_NO_FATAL_FAILURE(ForwardAllPacketsToPorts(test_p4_info(), PortIds()));

  absl::flat_hash_map<std::string, TestData::ResultMap> baseline_hash_results;
  ASSERT_OK_AND_ASSIGN(baseline_hash_results,
                       InitializeOrReturnBaselineHashResults(test_p4_info()));

  ASSERT_OK_AND_ASSIGN(std::string gnmi_interface_name,
                       GnmiInterfaceName(DefaultIngressPort()));
  ASSERT_OK_AND_ASSIGN(auto sut_gnmi_stub,
                       GetMirrorTestbed().Sut().CreateGnmiStub());
  ASSERT_OK_AND_ASSIGN(
      openconfig::Interfaces interfaces,
      GetInterfacesAsProto(*sut_gnmi_stub, gnmi::GetRequest::CONFIG));
  std::string original_hash_algorithm;
  absl::flat_hash_set<std::string> algorithms;
  for (const auto& interface : interfaces.interfaces()) {
    const std::string& algorithm = interface.config().ecmp_hash_algorithm();
    if (interface.name() == gnmi_interface_name) {
      original_hash_algorithm = algorithm;
    }
    if (!algorithm.empty()) {
      algorithms.insert(algorithm);
    }
  }
  std::string p4_algorithm;
  if (RE2::PartialMatch(
          gutil::PrintTextProto(test_p4_info()),
          R"re(sai_hash_algorithm\(SAI_HASH_ALGORITHM_([^)]*)\))re",
          &p4_algorithm)) {
    LOG(INFO) << "P4 Algorithm detected: " << p4_algorithm;
    algorithms.insert(p4_algorithm);
  }
  ASSERT_FALSE(original_hash_algorithm.empty());
  LOG(INFO) << "In-use hash alorithms: [" << absl::StrJoin(algorithms, ", ")
            << "]";

  // Select a new algorithm. Prefer an in-use algorithm if available.
  std::string new_hash_algorithm =
      original_hash_algorithm == "CRC_CCITT" ? "CRC_32HI" : "CRC_CCITT";
  if (algorithms.size() >= 2) {
    algorithms.erase(original_hash_algorithm);
    new_hash_algorithm = *algorithms.begin();
  }
  LOG(INFO) << "Changing hash algorithm from " << original_hash_algorithm
            << " to " << new_hash_algorithm;
  std::string ingress_port_ecmp_hash_path = absl::Substitute(
      "interfaces/interface[name=$0]/config/ecmp-hash-algorithm",
      gnmi_interface_name);
  ASSERT_OK(UpdateAndVerifyGnmiConfigLeaf(
      sut_gnmi_stub.get(), ingress_port_ecmp_hash_path, new_hash_algorithm));

  LOG(INFO) << "Testing hash with algorithm: " << new_hash_algorithm;
  // Use EXPECT instead of ASSERT so we still clean up at the end.
  absl::node_hash_map<std::string, TestData> hashing_results;
  EXPECT_OK(SendPacketsToDefaultPortAndRecordResultsPerTest(
      HashingTestPackets(), test_p4_info(), "1_modified", hashing_results));

  // Analyze hash results
  if (!HasFailure()) {  // Skip if we had transmission errors
    std::vector<std::string> differing_configs;
    std::vector<std::string> matching_configs;
    for (const auto& config : HashingTestConfigNames()) {
      EXPECT_THAT(
          hashing_results.at(config).Results(),
          Not(UnorderedElementsAreArray(baseline_hash_results.at(config))))
          << "No hash diff found for config: " << config;
    }
  }

  LOG(INFO) << "Restoring original hash algorithm " << original_hash_algorithm;
  ASSERT_OK(UpdateAndVerifyGnmiConfigLeaf(sut_gnmi_stub.get(),
                                          ingress_port_ecmp_hash_path,
                                          original_hash_algorithm));
}

TEST_P(HashConfigTest, GnmiHashOffsetSettingsAffectPacketHash) {
  int kMaxHashOffset = 15;
  GetMirrorTestbed().Environment().SetTestCaseID(
      "0a584c71-a701-4ea5-b4f3-5e4e37171d9c");

  ASSERT_NO_FATAL_FAILURE(ForwardAllPacketsToPorts(test_p4_info(), PortIds()));
  absl::flat_hash_map<std::string, TestData::ResultMap> baseline_hash_results;
  ASSERT_OK_AND_ASSIGN(baseline_hash_results,
                       InitializeOrReturnBaselineHashResults(test_p4_info()));

  ASSERT_OK_AND_ASSIGN(std::string gnmi_interface_name,
                       GnmiInterfaceName(DefaultIngressPort()));
  ASSERT_OK_AND_ASSIGN(auto sut_gnmi_stub,
                       GetMirrorTestbed().Sut().CreateGnmiStub());
  ASSERT_OK_AND_ASSIGN(
      openconfig::Interfaces interfaces,
      GetInterfacesAsProto(*sut_gnmi_stub, gnmi::GetRequest::CONFIG));
  int original_hash_offset = -1;
  for (const auto& interface : interfaces.interfaces()) {
    if (interface.name() == gnmi_interface_name) {
      original_hash_offset = interface.config().ecmp_hash_offset();
    }
  }
  ASSERT_NE(original_hash_offset, -1)
      << "Unable to find original hash offset for interface "
      << gnmi_interface_name;

  int new_hash_offset = (original_hash_offset + 1) % (kMaxHashOffset + 1);
  LOG(INFO) << "Changing hash offset from " << original_hash_offset << " to "
            << new_hash_offset;

  std::string ingress_port_ecmp_hash_path =
      absl::Substitute("interfaces/interface[name=$0]/config/ecmp-hash-offset",
                       gnmi_interface_name);
  ASSERT_OK(UpdateAndVerifyGnmiConfigLeaf(sut_gnmi_stub.get(),
                                          ingress_port_ecmp_hash_path,
                                          absl::StrCat(new_hash_offset)));

  LOG(INFO) << "Testing hash with offset: " << new_hash_offset;
  // Use EXPECT instead of ASSERT so we still clean up at the end.
  absl::node_hash_map<std::string, TestData> hashing_results;
  EXPECT_OK(SendPacketsToDefaultPortAndRecordResultsPerTest(
      HashingTestPackets(), test_p4_info(), "1_modified", hashing_results));

  // Analyze hash results
  if (!HasFailure()) {  // Skip if we had transmission errors
    for (const auto& config : HashingTestConfigNames()) {
      EXPECT_THAT(
          hashing_results.at(config).Results(),
          Not(UnorderedElementsAreArray(baseline_hash_results.at(config))))
          << "No hash diff found for config: " << config;
    }
  }

  LOG(INFO) << "Restoring original hash offset: " << original_hash_offset;
  ASSERT_OK(UpdateAndVerifyGnmiConfigLeaf(sut_gnmi_stub.get(),
                                          ingress_port_ecmp_hash_path,
                                          absl::StrCat(original_hash_offset)));
}

TEST_P(HashConfigTest, P4InfoHashSeedSettingsAffectPacketHash) {
  GetMirrorTestbed().Environment().SetTestCaseID(
      "13170845-0d6d-4ff6-aa1f-873c349ba84e");

  ASSERT_OK_AND_ASSIGN(const p4::config::v1::P4Info p4info, GetSutP4Info());
  EXPECT_OK(RecordP4Info("0_original", p4info));

  ASSERT_NO_FATAL_FAILURE(ForwardAllPacketsToPorts(p4info, PortIds()));
  absl::flat_hash_map<std::string, TestData::ResultMap> baseline_hash_results;
  ASSERT_OK_AND_ASSIGN(baseline_hash_results,
                       InitializeOrReturnBaselineHashResults(p4info));

  p4::config::v1::P4Info modified_p4info;
  ASSERT_NO_FATAL_FAILURE(ModifyHashSeed(p4info, modified_p4info));
  LOG(INFO) << "Applying the modified P4Info";
  EXPECT_OK(RecordP4Info("1_modified", modified_p4info));
  ASSERT_OK(UpdateSutP4Info(modified_p4info));
  ASSERT_THAT(GetSutP4Info(), IsOkAndHolds(EqualsProto(modified_p4info)))
      << "Failed to modify the hash seed in the P4Info.";

  LOG(INFO) << "Testing hash with modified seed";
  // Use EXPECT instead of ASSERT so we still clean up at the end.
  absl::node_hash_map<std::string, TestData> hashing_results;
  EXPECT_OK(SendPacketsToDefaultPortAndRecordResultsPerTest(
      HashingTestPackets(), p4info, "1_modified", hashing_results));

  // Analyze hash results
  if (!HasFailure()) {  // Skip if we had transmission errors
    for (const auto& config : HashingTestConfigNames()) {
      EXPECT_THAT(
          hashing_results.at(config).Results(),
          Not(UnorderedElementsAreArray(baseline_hash_results.at(config))))
          << "No hash diff found for config: " << config;
    }
  }

  EXPECT_OK(SaveSwitchLogs("teardown_before_reboot"));
  LOG(INFO) << "Restoring the original P4Info.";
  ASSERT_OK(UpdateSutP4Info(p4info));
}
}  // namespace pins_test
