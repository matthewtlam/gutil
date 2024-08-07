// Copyright 2022 Google LLC
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

#include "tests/forwarding/hash_distribution_test.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/container/btree_set.h"
#include "absl/container/node_hash_map.h"
#include "absl/random/random.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "boost/math/distributions/chi_squared.hpp"  // IWYU pragma: keep
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "lib/p4rt/p4rt_port.h"
#include "tests/forwarding/group_programming_util.h"
#include "tests/forwarding/hash_statistics_util.h"
#include "tests/forwarding/hash_testfixture.h"
#include "tests/forwarding/packet_test_util.h"

namespace pins_test {

// Test that the switch can produce the desired hash distribution.
// Repeats the test for IPv4 and IPv6, each with num_packets packets.
void HashDistributionTest::TestHashDistribution(
    std::vector<gpins::GroupMember>& members, int num_packets,
    double confidence, Statistic statistic) {
  absl::node_hash_map<std::string, TestData> hash_test_data;
  {
    // Prefix with 0 so it's easier to find in an alphabetized list.
    std::string record_prefix = "0_hash_distribution_";
    EXPECT_OK(RecordP4Info(record_prefix, test_p4_info()));
    ASSERT_NO_FATAL_FAILURE(
        ForwardAllPacketsToMembers(test_p4_info(), members));
    ASSERT_OK_AND_ASSIGN(auto ipv4_packets,
                         GeneratePackets(Ipv4HashingOptions(), num_packets));
    ASSERT_OK_AND_ASSIGN(auto ipv6_packets,
                         GeneratePackets(Ipv6HashingOptions(), num_packets));
    TestPacketMap test_packets = {
        {"IPv4Packets", std::move(ipv4_packets)},
        {"Ipv6Packets", std::move(ipv6_packets)},
    };
    LOG(INFO) << "Sending " << num_packets << " IPv4 packets and "
              << num_packets << " IPv6 packets.";
    ASSERT_OK(SendPacketsToDefaultPortAndRecordResultsPerTest(
        test_packets, test_p4_info(), record_prefix, hash_test_data));
  }

  for (const auto& [config, data] : hash_test_data) {
    Distribution actual_distribution;
    for (const auto& [port, packets] : data.Results()) {
      int port_id;
      ASSERT_TRUE(absl::SimpleAtoi(port, &port_id));
      actual_distribution[port_id] = packets.size();
    }

    SCOPED_TRACE(absl::StrCat("Failed to verify ", config));
    LOG(INFO) << "Results for " << config;
    double actual_confidence;
    EXPECT_OK(TestDistribution(members, actual_distribution, confidence,
                               num_packets, statistic, actual_confidence));
    testing::Test::RecordProperty("confidence", actual_confidence);
  }
}

TEST_P(EcmpHashDistributionTest, EcmpDistribution) {
  GetMirrorTestbed().Environment().SetTestCaseIDs(
      {"fdaa1b1e-67a3-497f-aa62-fd62d711c415"});
  constexpr int kTotalWeight = 16;
  std::vector<gpins::GroupMember> members;
  for (const P4rtPortId& port_id : PortIds()) {
    members.push_back(
        {.weight = 1,
         .port = static_cast<int>(port_id.GetOpenConfigEncoding())});
    if (members.size() >= kTotalWeight) break;
  }
  ASSERT_NO_FATAL_FAILURE(
      TestHashDistribution(members, PercentErrorTestPacketCount(kTotalWeight),
                           /*confidence=*/0.60, Statistic::kPercentError));
}

// Test with a non-uniform hash distribution. Here, we choose to use a roughly
// Gaussian distribution.
// TODO: Enable this test when we can reliably pass.
TEST_P(WcmpHashDistributionTest, WcmpDistribution) {
  GetMirrorTestbed().Environment().SetTestCaseIDs(
      {"29b21ea3-91b2-4a0c-840b-f78257321826"});
  // The member count should allow for diversity in weights between each member.
  constexpr int kMaxMembers = 9;

  std::vector<gpins::GroupMember> members;
  int weights_remaining = GetParam().total_weight;
  for (const P4rtPortId& port_id : PortIds()) {
    members.push_back(
        {.weight = 1,
         .port = static_cast<int>(port_id.GetOpenConfigEncoding())});
    --weights_remaining;
    // Limit the ports to <= kMaxMembers and <= total_weight.
    if (members.size() > kMaxMembers || weights_remaining == 0) break;
  }
  // TODO: Add a wcmp distribution flag and bypass generation.
  absl::BitGen bit_gen;
  while (weights_remaining > 0) {
    // Gaussian has a 99.7% Confidence interval within +/- 3 stdev of the mean.
    // To get 99.7 of results to fall within the port id set, we construct a
    // gaussian distribution with a mean of 1/2 the port size and a stdev of 1/6
    // the port size.
    int index = absl::Gaussian(
        bit_gen, /*mean=*/static_cast<double>(members.size()) / 2,
        /*stddev=*/static_cast<double>(members.size()) / 6);
    if (index >= 0 && index < members.size()) {
      ++members.at(index).weight;
      --weights_remaining;
    }
  }

  ASSERT_NO_FATAL_FAILURE(TestHashDistribution(
      members, PercentErrorTestPacketCount(GetParam().total_weight),
      GetParam().error_threshold, Statistic::kPercentError));
}

namespace {
absl::StatusOr<std::string> DescribePacketDistribution(
    const HashTest::TestData::ResultMap& results) {
  // Create an int-sorted map of port first so the port order is logical.
  absl::btree_map<int, int> packet_count_map;
  for (const auto& [port, packets] : results) {
    std::vector<int> port_ids;
    int port_id;
    if (!absl::SimpleAtoi(port, &port_id)) {
      return gutil::InternalErrorBuilder()
             << "Unable to translate egress port " << port << " to an integer.";
    }
    packet_count_map[port_id] = packets.size();
  }
  std::vector<std::string> ports, packet_counts;
  for (const auto& [port, packets] : packet_count_map) {
    ports.push_back(absl::StrFormat("%4d", port));
    packet_counts.push_back(absl::StrFormat("%4d", packets));
  }
  return absl::Substitute(
      R"(
    Port: $0
 Packets: $1
)",
      absl::StrJoin(ports, " "), absl::StrJoin(packet_counts, " "));
}

void ExpectNonHashingResult(const absl::string_view config,
                            const HashTest::TestData::ResultMap& results) {
  ASSERT_OK_AND_ASSIGN(auto packet_log, DescribePacketDistribution(results));
  LOG(INFO) << "Results for " << config;
  LOG(INFO) << packet_log;
  SCOPED_TRACE(packet_log);

  ASSERT_EQ(results.size(), 1)
      << "Expected all packets to egress on a single port.";
}
}  // namespace

TEST_P(EcmpHashDistributionTest, NonHashingFieldsHaveNoDistribution) {
  GetMirrorTestbed().Environment().SetTestCaseIDs(
      {"789dad22-96d1-4550-8acb-d42c1f69ca21"});

  constexpr int kTotalWeight = 15;
  // Use less packets since we don't need to determine a distribution.
  constexpr int kNonHashingPackets = 1000;

  std::vector<gpins::GroupMember> members;
  for (auto port_id : PortIds()) {
    members.push_back(
        {.weight = 1,
         .port = static_cast<int>(port_id.GetOpenConfigEncoding())});
    if (members.size() >= kTotalWeight) break;
  }
  absl::node_hash_map<std::string, TestData> hash_test_data;
  {
    // Prefix with 0 so it's easier to find in an alphabetized list.
    std::string record_prefix = "0_hash_distribution_";
    EXPECT_OK(RecordP4Info(record_prefix, test_p4_info()));
    ASSERT_NO_FATAL_FAILURE(
        ForwardAllPacketsToMembers(test_p4_info(), members));

    TestPacketMap test_packets;
    for (const auto& [field, config] : NonHashingTestConfigs()) {
      ASSERT_OK_AND_ASSIGN(
          test_packets[field],
          GeneratePackets(config,
                          std::min(kNonHashingPackets, gpins::Range(config)),
                          PacketGeneratorStyle::kSequential));
    }

    LOG(INFO) << "Sending non-hashing packets.";
    ASSERT_OK(SendPacketsToDefaultPortAndRecordResultsPerTest(
        test_packets, test_p4_info(), record_prefix, hash_test_data));
  }

  for (const auto& [config, data] : hash_test_data) {
    SCOPED_TRACE(absl::StrCat("Failed to verify ", config));
    ExpectNonHashingResult(config, data.Results());
  }
}

}  // namespace pins_test
