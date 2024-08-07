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

#ifndef PINS_INFRA_TESTS_FORWARDING_HASH_DISTRIBUTION_TEST_H_
#define PINS_INFRA_TESTS_FORWARDING_HASH_DISTRIBUTION_TEST_H_

#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "p4/config/v1/p4info.pb.h"
#include "tests/forwarding/group_programming_util.h"
#include "tests/forwarding/hash_statistics_util.h"
#include "tests/forwarding/hash_testfixture.h"
#include "thinkit/mirror_testbed_fixture.h"

namespace pins_test {

struct EcmpHashDistributionTestParameters {
  thinkit::MirrorTestbedInterface* mirror_testbed;
  p4::config::v1::P4Info p4_info;
};

struct WcmpHashDistributionTestParameters {
  thinkit::MirrorTestbedInterface* mirror_testbed;
  p4::config::v1::P4Info p4_info;
  int total_weight;
  double error_threshold;
};

// This class stores and reports data on received packets. Particularly, it
// keeps track of packets based on the egress port for the SUT / ingress port of
// the Control Switch.
// Test class for the hash config test.
class HashDistributionTest : public HashTest {
 public:
  HashDistributionTest(thinkit::MirrorTestbedInterface* mirror_testbed,
                       p4::config::v1::P4Info p4info,
                       HashTest::TearDownCondition testbed_teardown_condition)
      : HashTest(mirror_testbed, std::move(p4info),
                 testbed_teardown_condition) {}

  // Test that the hash distribution matches the provided member weights.
  // Runs the test against all packet fields that are expected to generate a
  // hashing difference and that allow for at least the minimum amount of
  // variation.
  // Confidence is the threshold for declaring success / failure.
  // * For ChiSquared tests, success is measured by confidence < p_value
  // * For PercentError tests, success is when 1 - confidence > percent error
  void TestHashDistribution(std::vector<gpins::GroupMember>& members,
                            int num_packets, double confidence,
                            Statistic statistic);
};

class EcmpHashDistributionTest
    : public HashDistributionTest,
      public testing::WithParamInterface<EcmpHashDistributionTestParameters> {
 public:
  EcmpHashDistributionTest()
      : HashDistributionTest(GetParam().mirror_testbed,
                             std::move(GetParam().p4_info),
                             HashTest::TearDownCondition::kAlways) {}
};

class WcmpHashDistributionTest
    : public HashDistributionTest,
      public testing::WithParamInterface<WcmpHashDistributionTestParameters> {
 public:
  WcmpHashDistributionTest()
      : HashDistributionTest(GetParam().mirror_testbed,
                             std::move(GetParam().p4_info),
                             // Skip teardown for passing tests to save time by
                             // skipping artifact retrieval.
                             HashTest::TearDownCondition::kOnFailure) {}
};

}  // namespace pins_test

#endif  // PINS_INFRA_TESTS_FORWARDING_HASH_DISTRIBUTION_TEST_H_
