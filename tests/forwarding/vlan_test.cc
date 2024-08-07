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

#include "tests/forwarding/vlan_test.h"

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "dvaas/test_vector.h"
#include "dvaas/test_vector.pb.h"
#include "dvaas/validation_result.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"
#include "gutil/testing.h"
#include "p4_pdpi/netaddr/mac_address.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/p4_runtime_session_extras.h"
#include "p4_pdpi/packetlib/packetlib.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "sai_p4/instantiations/google/test_tools/test_entries.h"
#include "tests/lib/switch_test_setup_helpers.h"
#include "thinkit/mirror_testbed.h"

namespace pins_test {

void VlanTestFixture::SetUp() {
  GetParam().testbed->SetUp();
  thinkit::MirrorTestbed& testbed = GetParam().testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(
      sut_p4rt_session_,
      ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.Sut(), /*gnmi=*/std::nullopt, GetParam().sut_p4info));

  ASSERT_OK_AND_ASSIGN(sut_ir_p4info_, pdpi::GetIrP4Info(*sut_p4rt_session_));
}

void VlanTestFixture::TearDown() { GetParam().testbed->TearDown(); }

namespace {

void PreparePacketOrDie(packetlib::Packet& packet) {
  CHECK_OK(packetlib::PadPacketToMinimumSize(packet).status());   // Crash OK.
  CHECK_OK(packetlib::UpdateAllComputedFields(packet).status());  // Crash OK.
}

packetlib::Packet GetIpv4PacketOrDie() {
  auto packet = gutil::ParseProtoOrDie<packetlib::Packet>(R"pb(
    headers {
      ethernet_header {
        ethernet_destination: "02:03:04:05:06:07"
        ethernet_source: "00:01:02:03:04:05"
        ethertype: "0x0800"  # IPv4
      }
    }
    headers {
      ipv4_header {
        version: "0x4"
        ihl: "0x5"
        dscp: "0x1c"
        ecn: "0x0"
        identification: "0x0000"
        flags: "0x0"
        fragment_offset: "0x0000"
        ttl: "0x20"
        protocol: "0xfe"
        ipv4_source: "192.168.100.2"
        ipv4_destination: "192.168.100.1"
      }
    }
    payload: "Untagged IPv4 packet."
  )pb");
  PreparePacketOrDie(packet);
  return packet;
}

packetlib::Packet GetVlanIpv4PacketOrDie(absl::string_view vid_hexstr) {
  auto packet = gutil::ParseProtoOrDie<packetlib::Packet>(R"pb(
    headers {
      ethernet_header {
        ethernet_destination: "02:03:04:05:06:07"
        ethernet_source: "00:01:02:03:04:05"
        ethertype: "0x8100"  # VLAN
      }
    }
    headers {
      vlan_header {
        priority_code_point: "0x0",
        drop_eligible_indicator: "0x0",
        vlan_identifier: "0x0",
        ethertype: "0x0800"  # IPv4
      }
    }
    headers {
      ipv4_header {
        version: "0x4"
        ihl: "0x5"
        dscp: "0x1c"
        ecn: "0x0"
        identification: "0x0000"
        flags: "0x0"
        fragment_offset: "0x0000"
        ttl: "0x20"
        protocol: "0xfe"
        ipv4_source: "192.168.100.2"
        ipv4_destination: "192.168.100.1"
      }
    }
    payload: "VLAN tagged IPv4 packet."
  )pb");
  packet.mutable_headers()
      ->Mutable(1)
      ->mutable_vlan_header()
      ->set_vlan_identifier(vid_hexstr);
  PreparePacketOrDie(packet);
  return packet;
}

std::string GetVlanIdHexStr(int vlan_id) {
  return absl::StrCat("0x", absl::Hex(vlan_id, absl::kZeroPad3));
}

struct PreIngressReplaceOuterVlanParams {
  std::optional<std::string> vlan_match;
  std::string vlan_set;
};

struct MatchOnVidAndRedirectParams {
  int vid_match;
  sai::NexthopRewriteOptions nexthop_rewrites;
};

struct IngressAclParams {
  bool punt_any_packet = false;
  std::optional<MatchOnVidAndRedirectParams> match_on_vid_and_redirect;
};

struct VlanMembership {
  int vlan;
  std::string port;
  sai::VlanTaggingMode tagging_mode;
};

constexpr absl::string_view kDefaultIngressPort = "1";
constexpr absl::string_view kDefaultEgressPort = "2";

// Parameters for configuring forwarding behavior. The default parameters
// forward all IPv4 packets to a certain port (without a VLAN tag). VLAN checks
// are enabled by default.
struct VlanForwardingParams {
  bool disable_vlan_checks = false;
  bool disable_ingress_vlan_checks = false;
  bool disable_egress_vlan_checks = false;
  std::optional<PreIngressReplaceOuterVlanParams> pre_ingress_replace_vlan;
  sai::NexthopRewriteOptions nexthop_rewrites;
  std::optional<IngressAclParams> ingress_acl_params;
  std::string egress_port = (std::string)kDefaultEgressPort;
  std::vector<VlanMembership> vlan_membership;
};

std::vector<p4::v1::Entity> GetTableEntriesForVlanForwardingOrDie(
    const VlanForwardingParams& params, const pdpi::IrP4Info& ir_p4_info) {
  sai::EntryBuilder entry_builder;
  entry_builder.AddEntrySettingVrfForAllPackets("vrf-forward")
      .AddVrfEntry("vrf-forward")
      .AddEntryAdmittingAllPacketsToL3()
      .AddDefaultRouteForwardingAllPacketsToGivenPort(
          params.egress_port, sai::IpVersion::kIpv4, "vrf-forward",
          params.nexthop_rewrites);
  if (params.disable_vlan_checks) {
    entry_builder.AddDisableVlanChecksEntry();
  }
  if (params.disable_ingress_vlan_checks) {
    entry_builder.AddDisableIngressVlanChecksEntry();
  }
  if (params.disable_egress_vlan_checks) {
    entry_builder.AddDisableEgressVlanChecksEntry();
  }
  if (params.pre_ingress_replace_vlan.has_value()) {
    entry_builder.AddEntrySettingVlanIdInPreIngress(
        params.pre_ingress_replace_vlan->vlan_set,
        params.pre_ingress_replace_vlan->vlan_match);
  }
  if (params.ingress_acl_params.has_value()) {
    if (params.ingress_acl_params->punt_any_packet) {
      entry_builder.AddEntryPuntingAllPackets(sai::PuntAction::kTrap);
    }
    if (params.ingress_acl_params->match_on_vid_and_redirect.has_value()) {
      auto redirect_params =
          params.ingress_acl_params->match_on_vid_and_redirect.value();
      constexpr absl::string_view kRedirectNexthopId = "redirect-nexthop";
      entry_builder
          .AddIngressAclEntryRedirectingToNexthop(
              kRedirectNexthopId, {.vlan_id = redirect_params.vid_match})
          .AddNexthopRifNeighborEntries(kRedirectNexthopId, params.egress_port,
                                        redirect_params.nexthop_rewrites);
    }
  }
  for (const auto& vlan_member : params.vlan_membership) {
    // Entities get deduplicated, so it is fine to add the vlan_table entry once
    // for each vlan_membership_table entry.
    entry_builder.AddVlanEntry(GetVlanIdHexStr(vlan_member.vlan));
    entry_builder.AddVlanMembershipEntry(GetVlanIdHexStr(vlan_member.vlan),
                                         vlan_member.port,
                                         vlan_member.tagging_mode);
  }

  auto entities = entry_builder.LogPdEntries().GetDedupedPiEntities(
      ir_p4_info, /*allow_unsupported=*/true);
  CHECK_OK(entities.status())
      << "Failed to get PI entities from sai::EntryBuilder.";  // Crash OK.
  return *entities;
}

dvaas::SwitchInput CreateSwitchInput(std::optional<int> vlan_id, int test_id) {
  // Prepare packet.
  packetlib::Packet packet =
      vlan_id.has_value() ? GetVlanIpv4PacketOrDie(GetVlanIdHexStr(*vlan_id))
                          : GetIpv4PacketOrDie();
  packet.set_payload(dvaas::MakeTestPacketTagFromUniqueId(
      test_id, "manually crafted test packet"));
  PreparePacketOrDie(packet);

  // Prepare switch input.
  dvaas::SwitchInput input;
  input.set_type(dvaas::SwitchInput_Type_DATAPLANE);
  input.mutable_packet()->set_port(kDefaultIngressPort);
  *input.mutable_packet()->mutable_parsed() = packet;
  input.mutable_packet()->set_hex(absl::BytesToHexString(
      packetlib::RawSerializePacket(packet).ValueOrDie()));

  return input;
}

dvaas::SwitchOutput CreateSwitchForwardedOutput(std::optional<int> vlan_id,
                                                int test_id) {
  sai::NexthopRewriteOptions default_rewrites;

  // Prepare packets along with rewrites.
  packetlib::Packet packet =
      vlan_id.has_value() ? GetVlanIpv4PacketOrDie(GetVlanIdHexStr(*vlan_id))
                          : GetIpv4PacketOrDie();
  packet.set_payload(dvaas::MakeTestPacketTagFromUniqueId(
      test_id, "manually crafted test packet"));
  (*packet.mutable_headers())[0].mutable_ethernet_header()->set_ethernet_source(
      default_rewrites.src_mac_rewrite->ToString());
  (*packet.mutable_headers())[0]
      .mutable_ethernet_header()
      ->set_ethernet_destination(default_rewrites.dst_mac_rewrite->ToString());
  // Assuming TTL is 0x20 for input packets.
  if (vlan_id.has_value()) {
    (*packet.mutable_headers())[2].mutable_ipv4_header()->set_ttl("0x1f");
  } else {
    (*packet.mutable_headers())[1].mutable_ipv4_header()->set_ttl("0x1f");
  }
  PreparePacketOrDie(packet);

  // Prepare switch output.
  dvaas::SwitchOutput output;
  auto& forwarded_packet = *output.mutable_packets()->Add();
  *forwarded_packet.mutable_parsed() = packet;
  forwarded_packet.set_port("2");
  forwarded_packet.set_hex(absl::BytesToHexString(
      packetlib::RawSerializePacket(packet).ValueOrDie()));

  return output;
}

dvaas::SwitchOutput CreateSwitchPuntedOutput(std::optional<int> vlan_id,
                                             int test_id) {
  // Prepare packets along with rewrites.
  packetlib::Packet packet =
      vlan_id.has_value() ? GetVlanIpv4PacketOrDie(GetVlanIdHexStr(*vlan_id))
                          : GetIpv4PacketOrDie();
  packet.set_payload(dvaas::MakeTestPacketTagFromUniqueId(
      test_id, "manually crafted test packet"));
  PreparePacketOrDie(packet);

  // Prepare switch output.
  dvaas::SwitchOutput output;

  auto& punted_packet = *output.mutable_packet_ins()->Add();
  punted_packet = gutil::ParseProtoOrDie<dvaas::PacketIn>(R"pb(
    metadata {
      name: "ingress_port"
      value { str: "1" }
    }
    metadata {
      name: "target_egress_port"
      value { str: "2" }
    }
  )pb");
  *punted_packet.mutable_parsed() = packet;
  punted_packet.set_hex(absl::BytesToHexString(
      packetlib::RawSerializePacket(packet).ValueOrDie()));

  return output;
}

enum PacketFate {
  kForward,
  kPunt,
  kDrop,
};

struct VlanPacketTestVector {
  std::optional<int> input_vlan_id;
  std::optional<int> expected_output_vlan_id;
  PacketFate expected_fate = kForward;
};

struct VlanTestVector {
  size_t test_id;
  VlanForwardingParams forwarding_params;
  std::vector<VlanPacketTestVector> packet_test_vectors;
};

void AssertSwitchUnderTestConformsToVlanTestVector(
    const VlanTestVector& vlan_test, const VlanTestParams& test_params) {
  SCOPED_TRACE(absl::StrCat("VlanTestVector #", vlan_test.test_id));

  ASSERT_OK_AND_ASSIGN(auto sut_p4rt_session,
                       pdpi::P4RuntimeSession::Create(
                           test_params.testbed->GetMirrorTestbed().Sut()));
  ASSERT_OK_AND_ASSIGN(auto sut_ir_p4info,
                       pdpi::GetIrP4Info(*sut_p4rt_session));
  ASSERT_OK(pdpi::ClearEntities(*sut_p4rt_session));
  ASSERT_OK(pdpi::InstallPiEntities(
      *sut_p4rt_session, GetTableEntriesForVlanForwardingOrDie(
                             vlan_test.forwarding_params, sut_ir_p4info)));

  // Create DVaaS packet test vectors.
  int packet_test_id = 0;
  std::vector<dvaas::PacketTestVector> test_vectors;
  for (const auto& packet_test_vector : vlan_test.packet_test_vectors) {
    dvaas::PacketTestVector test_vector;
    // Build input.
    *test_vector.mutable_input() = CreateSwitchInput(
        /*vlan_id=*/packet_test_vector.input_vlan_id, packet_test_id);

    // Build expected output.
    if (packet_test_vector.expected_fate == kPunt) {
      *test_vector.add_acceptable_outputs() = CreateSwitchPuntedOutput(
          /*vlan_id=*/packet_test_vector.expected_output_vlan_id,
          packet_test_id);
    } else if (packet_test_vector.expected_fate == kForward) {
      *test_vector.add_acceptable_outputs() = CreateSwitchForwardedOutput(
          /*vlan_id=*/packet_test_vector.expected_output_vlan_id,
          packet_test_id);
    } else if (packet_test_vector.expected_fate == kDrop) {
      test_vector.add_acceptable_outputs();
    } else {
      FAIL() << "Unexpected packet fate: " << packet_test_vector.expected_fate;
    }

    test_vectors.push_back(std::move(test_vector));
    ++packet_test_id;
  }

  // Run test with custom packet test vector.
  auto validation_params = test_params.validation_params;
  validation_params.packet_test_vector_override = std::move(test_vectors);
  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result,
      test_params.validator->ValidateDataplane(
          test_params.testbed->GetMirrorTestbed(), validation_params));

  // Check validation result.
  EXPECT_OK(validation_result.HasSuccessRateOfAtLeast(1.0));
}

// Check that VLAN-tagged input packets are forwarded without VLAN header (for
// non-special VLAN IDs 2-4094).
TEST_P(VlanTestFixture,
       SwitchForwardsVlanTaggedInputPacketsWhenVlanChecksDisabled) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "e097357e-6c90-4f51-a4be-68d06436fe6f");

  VlanTestVector test = {
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              // The default parameters forward the packet without VLAN header.
          },
  };
  constexpr int kStepSize = 100;  // Decrease step size to increase coverage.
  for (int vid = 2; vid < 4095; vid += kStepSize) {
    test.packet_test_vectors.push_back({
        .input_vlan_id = vid,
        .expected_output_vlan_id = std::nullopt,
    });
  }

  AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
}

// Check that setting egress VLAN ID for non-tagged input packets results in
// tagged egress packets (for non-special VLAN IDs 2-4094).
TEST_P(VlanTestFixture, SettingVlanForEgressPacketWorksWhenVlanChecksDisabled) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "97470934-8639-4dd1-9efe-ef666d01ea7d");

  std::vector<VlanTestVector> tests;
  constexpr int kStepSize = 1000;  // Decrease step size to increase coverage.
  for (int vid = 2; vid < 4095; vid += kStepSize) {
    tests.push_back({
        .forwarding_params =
            {
                .disable_vlan_checks = true,
                .nexthop_rewrites =
                    {
                        .egress_rif_vlan = GetVlanIdHexStr(vid),
                    },
            },
        .packet_test_vectors =
            {
                {
                    .input_vlan_id = std::nullopt,
                    .expected_output_vlan_id = vid,
                },
            },
    });
  }

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

TEST_P(VlanTestFixture,
       InteractionOfPreIngVlanSetAndNexthopRewritesWithVlanChecksDisabled) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "10913633-99ab-4382-b6e8-289b7cf32de3");

  if (GetParam().sut_instantiation != sai::Instantiation::kExperimentalTor &&
      GetParam().sut_instantiation != sai::Instantiation::kTor) {
    LOG(INFO)
        << "Skipping test for non-ToR and non-Experimental-ToR SUT because "
           "only these instantiations support acl_pre_ingress_vlan table ";
    GTEST_SKIP();
  }

  std::vector<VlanTestVector> tests;

  // =================== No pre-ingress VLAN replacement=======================

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .nexthop_rewrites = {.egress_rif_vlan = GetVlanIdHexStr(20)},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = 20,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 20,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 10,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .nexthop_rewrites =
                  {
                      .disable_vlan_rewrite = true,
                      .egress_rif_vlan = GetVlanIdHexStr(20),
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 10,
              },
          },
  });

  // ================== With pre-ingress VLAN replacement ======================

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
              .nexthop_rewrites = {.egress_rif_vlan = GetVlanIdHexStr(20)},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = 20,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 20,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // Pre-ingress ACL's SET_OUTER_VLAN_ID action affects the
                  // packet if and only if the input packet is VLAN tagged.
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 30,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{.vlan_set =
                                                       GetVlanIdHexStr(30)},
              .nexthop_rewrites =
                  {
                      .disable_vlan_rewrite = true,
                      .egress_rif_vlan = GetVlanIdHexStr(20),
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // Pre-ingress ACL's SET_OUTER_VLAN_ID action affects the
                  // packet if and only if the input packet is VLAN tagged.
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 30,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

TEST_P(VlanTestFixture, HandlingOfSpecialVlanIds) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "94274666-41fd-416e-a0de-dfed0fbb10dd");

  if (GetParam().sut_instantiation != sai::Instantiation::kExperimentalTor &&
      GetParam().sut_instantiation != sai::Instantiation::kTor) {
    LOG(INFO)
        << "Skipping test for non-ToR and non-Experimental-ToR SUT because "
           "only these instantiations support acl_pre_ingress_vlan table ";
    GTEST_SKIP();
  }

  std::vector<VlanTestVector> tests;

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = 4095,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 0,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = 4095,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 0,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{.vlan_set =
                                                       GetVlanIdHexStr(4095)},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{.vlan_set =
                                                       GetVlanIdHexStr(4095)},
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = 1,
                  .expected_output_vlan_id = 1,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .nexthop_rewrites = {.egress_rif_vlan = GetVlanIdHexStr(1)},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = 1,
              },
          },
  });

  // This test shows that SET_OUTER_VLAN_ID in pre-ingress ACL table affects
  // the packet if and only if the input packet is VLAN tagged (even if the
  // tag's VID is 0 or 4095).
  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = 4095,
                  .expected_output_vlan_id = 30,
              },
              {
                  .input_vlan_id = 0,
                  .expected_output_vlan_id = 30,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 30,
              },
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

TEST_P(VlanTestFixture, VlanMatch) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "b7b2dab1-e6db-4763-ae2b-02a08c472d5a");

  if (GetParam().sut_instantiation != sai::Instantiation::kExperimentalTor) {
    LOG(INFO) << "Skipping test for non-Experimental-ToR SUT because "
                 "only that instantiation support acl_pre_ingress_vlan and "
                 "acl_ingress_mirror_and_redirect_table together.";
    GTEST_SKIP();
  }
  std::vector<VlanTestVector> tests;

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_match = GetVlanIdHexStr(10),
                      .vlan_set = GetVlanIdHexStr(20),
                  },
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
              .ingress_acl_params =
                  IngressAclParams{
                      .match_on_vid_and_redirect =
                          MatchOnVidAndRedirectParams{
                              .vid_match = 20,
                              .nexthop_rewrites =
                                  {
                                      .egress_rif_vlan = GetVlanIdHexStr(40),
                                  },
                          },
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 40,
              },
              {
                  .input_vlan_id = 20,
                  .expected_output_vlan_id = 40,
              },
              {
                  .input_vlan_id = 30,
                  .expected_output_vlan_id = 30,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = true,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(20),
                  },
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
              .ingress_acl_params =
                  IngressAclParams{
                      .match_on_vid_and_redirect =
                          MatchOnVidAndRedirectParams{
                              .vid_match = 20,
                              .nexthop_rewrites =
                                  {
                                      .egress_rif_vlan = GetVlanIdHexStr(40),
                                  },
                          },
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // Pre-ingress ACL's SET_OUTER_VLAN_ID action affects the
                  // packet if and only if the input packet is VLAN tagged.
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 40,
              },
              {
                  .input_vlan_id = 20,
                  .expected_output_vlan_id = 40,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

TEST_P(VlanTestFixture, PacketInWithPreIngressVlanSet) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "3fca1f44-0ef1-481d-9746-05a5c6c78ca0");

  if (GetParam().sut_instantiation != sai::Instantiation::kExperimentalTor &&
      GetParam().sut_instantiation != sai::Instantiation::kTor) {
    LOG(INFO)
        << "Skipping test for non-ToR and non-Experimental-ToR SUT because "
           "only these instantiations support acl_pre_ingress_vlan table ";
    GTEST_SKIP();
  }

  VlanTestVector test = {.forwarding_params =
                             {
                                 .disable_vlan_checks = true,
                                 .pre_ingress_replace_vlan =
                                     PreIngressReplaceOuterVlanParams{
                                         .vlan_set = GetVlanIdHexStr(30),
                                     },
                                 .ingress_acl_params =
                                     IngressAclParams{
                                         .punt_any_packet = true,
                                     },
                             },
                         .packet_test_vectors = {
                             {
                                 .input_vlan_id = std::nullopt,
                                 .expected_output_vlan_id = std::nullopt,
                                 .expected_fate = kPunt,
                             },
                             {
                                 .input_vlan_id = 10,
                                 .expected_output_vlan_id = 10,
                                 .expected_fate = kPunt,
                             },
                             {
                                 .input_vlan_id = 0,
                                 .expected_output_vlan_id = 0,
                                 .expected_fate = kPunt,
                             },
                             {
                                 .input_vlan_id = 1,
                                 .expected_output_vlan_id = 1,
                                 .expected_fate = kPunt,
                             },
                             {
                                 .input_vlan_id = 4095,
                                 .expected_output_vlan_id = std::nullopt,
                                 .expected_fate = kPunt,
                             },
                         }};

  AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
}

TEST_P(VlanTestFixture, ForwardingWithVlanChecksEnabled) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "6bf5c5d0-bedb-4529-96e1-3434a84fb744");

  if (GetParam().sut_instantiation != sai::Instantiation::kExperimentalTor &&
      GetParam().sut_instantiation != sai::Instantiation::kTor) {
    LOG(INFO)
        << "Skipping test for non-ToR and non-Experimental-ToR SUT because "
           "only these instantiations support acl_pre_ingress_vlan table ";
    GTEST_SKIP();
  }

  std::vector<VlanTestVector> tests;

  // =================== No pre-ingress VLAN replacement=======================

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .nexthop_rewrites = {.egress_rif_vlan = GetVlanIdHexStr(20)},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // The packet does not get dropped because SUB_PORT RIF makes
                  // the egress port a member of the VLAN.
                  .expected_output_vlan_id = 20,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .nexthop_rewrites =
                  {
                      .disable_vlan_rewrite = true,
                      .egress_rif_vlan = GetVlanIdHexStr(20),
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  // ================== With pre-ingress VLAN replacement ======================

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // Pre-ingress ACL's SET_OUTER_VLAN_ID action affects the
                  // packet if and only if the input packet is VLAN tagged.
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
              .nexthop_rewrites = {.egress_rif_vlan = GetVlanIdHexStr(20)},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // The packet does not get dropped because SUB_PORT RIF makes
                  // the egress port a member of the VLAN.
                  .expected_output_vlan_id = 20,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{
                      .vlan_set = GetVlanIdHexStr(30),
                  },
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // Pre-ingress ACL's SET_OUTER_VLAN_ID action affects the
                  // packet if and only if the input packet is VLAN tagged.
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .pre_ingress_replace_vlan =
                  PreIngressReplaceOuterVlanParams{.vlan_set =
                                                       GetVlanIdHexStr(30)},
              .nexthop_rewrites =
                  {
                      .disable_vlan_rewrite = true,
                      .egress_rif_vlan = GetVlanIdHexStr(20),
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  // Pre-ingress ACL's SET_OUTER_VLAN_ID action affects the
                  // packet if and only if the input packet is VLAN tagged.
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_fate = kDrop,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

void AssertSwitchUnderTestFailsToInstallInvalidEntries(
    const VlanForwardingParams& forwarding_params,
    const VlanTestParams& test_params) {
  ASSERT_OK_AND_ASSIGN(auto sut_p4rt_session,
                       pdpi::P4RuntimeSession::Create(
                           test_params.testbed->GetMirrorTestbed().Sut()));
  ASSERT_OK_AND_ASSIGN(auto sut_ir_p4info,
                       pdpi::GetIrP4Info(*sut_p4rt_session));
  ASSERT_OK(pdpi::ClearEntities(*sut_p4rt_session));
  ASSERT_THAT(pdpi::InstallPiEntities(*sut_p4rt_session,
                                      GetTableEntriesForVlanForwardingOrDie(
                                          forwarding_params, sut_ir_p4info)),
              testing::Not(gutil::StatusIs(absl::StatusCode::kOk)));
}

TEST_P(VlanTestFixture, RejectedVlanEntries) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "24f52bc5-480a-4649-8cba-1ee2d0b0d104");

  if (GetParam().sut_instantiation != sai::Instantiation::kExperimentalTor) {
    LOG(INFO) << "Skipping test for non-Experimental-ToR SUT because "
                 "only that instantiation support acl_pre_ingress_vlan and "
                 "acl_ingress_mirror_and_redirect_table together.";
    GTEST_SKIP();
  }

  std::vector<VlanForwardingParams> invalid_params;

  // Setting VID 4095 in RIF is not allowed on the switch. Also we don't have a
  // use case.
  invalid_params.push_back({
      .nexthop_rewrites = {.egress_rif_vlan = GetVlanIdHexStr(4095)},
  });

  // Match on VID 4095 is disallowed by P4 constraints. Also currently we don't
  // have a use case.
  invalid_params.push_back({
      .pre_ingress_replace_vlan =
          PreIngressReplaceOuterVlanParams{
              .vlan_match = GetVlanIdHexStr(4095),
              .vlan_set = GetVlanIdHexStr(20),
          },
  });

  // TODO: Re-enable this test once we add the P4-constraint to
  // the mirror_and_redirect table.
  // // Match on VID 4095 is disallowed by P4 constraints. Also currently we
  // // don't have a use case.
  // invalid_params.push_back({
  //     .ingress_acl_params =
  //         IngressAclParams{
  //             .match_on_vid_and_redirect =
  //                 MatchOnVidAndRedirectParams{
  //                     .vid_match = 4095,
  //                     .nexthop_rewrites =
  //                         {
  //                             .egress_rif_vlan = GetVlanIdHexStr(40),
  //                         },
  //                 },
  //         },
  // });

  int test_id = 0;
  for (const auto& invalid_param : invalid_params) {
    ++test_id;
    LOG(INFO) << "Test " << test_id << ": ";
    AssertSwitchUnderTestFailsToInstallInvalidEntries(invalid_param,
                                                      GetParam());
  }
}

TEST_P(VlanTestFixture, DISABLED_SubmitToIngress) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "ce6e2a9c-9c01-42ad-946d-8162e1a1ea75");

  // TODO: implemente.
}

TEST_P(VlanTestFixture, DISABLED_DoubleVlanTaggedInputPackets) {
  GetParam().testbed->GetMirrorTestbed().Environment().SetTestCaseID(
      "2d9beb30-99a9-40f7-8470-bbed5e5dddff");

  // TODO: implemente.
}

// TODO: Enable this test once the switch supports the
// vlan_membership table.
TEST_P(VlanTestFixture, DISABLED_VlanMembership) {
  std::vector<VlanTestVector> tests;
  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
              .vlan_membership =
                  {
                      {
                          .vlan = 10,
                          .port = (std::string)kDefaultIngressPort,
                          .tagging_mode = sai::VlanTaggingMode::kTagged,
                      },
                      {
                          .vlan = 10,
                          .port = (std::string)kDefaultEgressPort,
                          .tagging_mode = sai::VlanTaggingMode::kTagged,
                      },
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 10,
              },
              {
                  .input_vlan_id = 20,
                  .expected_fate = kDrop,
              },
          },
  });

  tests.push_back({
      .forwarding_params =
          {
              .disable_vlan_checks = false,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
              .vlan_membership =
                  {
                      {
                          .vlan = 10,
                          .port = (std::string)kDefaultIngressPort,
                          .tagging_mode = sai::VlanTaggingMode::kTagged,
                      },
                      {
                          .vlan = 10,
                          .port = (std::string)kDefaultEgressPort,
                          .tagging_mode = sai::VlanTaggingMode::kUntagged,
                      },
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 20,
                  .expected_fate = kDrop,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

// TODO: Enable this test once the switch supports the
// disable_ingress_vlan_checks table.
TEST_P(VlanTestFixture, DISABLED_DisableIngressVlanChecks) {
  std::vector<VlanTestVector> tests;
  tests.push_back({
      .forwarding_params =
          {
              .disable_ingress_vlan_checks = true,
              .disable_egress_vlan_checks = false,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
              .vlan_membership =
                  {
                      {
                          .vlan = 10,
                          .port = (std::string)kDefaultEgressPort,
                          .tagging_mode = sai::VlanTaggingMode::kTagged,
                      },
                      {
                          .vlan = 20,
                          .port = (std::string)kDefaultEgressPort,
                          .tagging_mode = sai::VlanTaggingMode::kUntagged,
                      },
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 10,
              },
              {
                  .input_vlan_id = 20,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 30,
                  .expected_fate = kDrop,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

// TODO: Enable this test once the switch supports the
// disable_egress_vlan_checks table.
TEST_P(VlanTestFixture, DISABLED_DisableEgressVlanChecks) {
  std::vector<VlanTestVector> tests;
  tests.push_back({
      .forwarding_params =
          {
              .disable_ingress_vlan_checks = false,
              .disable_egress_vlan_checks = true,
              .nexthop_rewrites = {.disable_vlan_rewrite = true},
              .vlan_membership =
                  {
                      {
                          .vlan = 10,
                          .port = (std::string)kDefaultIngressPort,
                          .tagging_mode = sai::VlanTaggingMode::kTagged,
                      },
                  },
          },
      .packet_test_vectors =
          {
              {
                  .input_vlan_id = std::nullopt,
                  .expected_output_vlan_id = std::nullopt,
              },
              {
                  .input_vlan_id = 10,
                  .expected_output_vlan_id = 10,
              },
              {
                  .input_vlan_id = 20,
                  .expected_fate = kDrop,
              },
          },
  });

  int test_id = 0;
  for (auto& test : tests) {
    test.test_id = test_id++;
    LOG(INFO) << "Test " << test.test_id << ": ";
    AssertSwitchUnderTestConformsToVlanTestVector(test, GetParam());
  }
}

}  // namespace

}  // namespace pins_test
