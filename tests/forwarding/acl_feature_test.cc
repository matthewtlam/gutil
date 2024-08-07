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

#include "tests/forwarding/acl_feature_test.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "dvaas/dataplane_validation.h"
#include "dvaas/test_vector.h"
#include "dvaas/validation_result.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/status.h"  // IWYU pragma: keep
#include "gutil/status.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "gutil/testing.h"
#include "lib/gnmi/gnmi_helper.h"
#include "net/google::protobuf/contrib/fixtures/proto-fixture-repository.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/netaddr/mac_address.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/p4_runtime_session_extras.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "p4_pdpi/pd.h"
#include "sai_p4/instantiations/google/sai_pd.pb.h"
#include "sai_p4/instantiations/google/test_tools/test_entries.h"
#include "tests/lib/switch_test_setup_helpers.h"
#include "thinkit/mirror_testbed.h"

namespace pins_test {
namespace {

using ::google::protobuf::contrib::fixtures::ProtoFixtureRepository;

// Setup ingress ACL forward all packets.
absl::Status SetUpIngressAclForwardingAllPackets(
    pdpi::P4RuntimeSession* p4_session, const pdpi::IrP4Info& ir_p4info) {
  sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
      R"pb(
        acl_ingress_table_entry {
          match {}  # Wildcard match.
          action { acl_forward {} }
          priority: 1
        }
      )pb");

  ASSIGN_OR_RETURN(
      const p4::v1::TableEntry pi_entry,
      pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));
  return pdpi::InstallPiTableEntry(p4_session, pi_entry);
}

// Helper function to build:
// - an IPv4 UDP input packet with output expectations depending on
//   `punt_action`.
// - an IPv6 UDP input packet with output expectations depending on
//   `punt_action`.
std::vector<dvaas::PacketTestVector> MakePackets(
    absl::string_view egress_port,
    const sai::NexthopRewriteOptions& rewrite_options,
    std::optional<sai::PuntAction> punt_action) {
  ProtoFixtureRepository repo;
  repo.RegisterValue("@payload_ipv4",
                     dvaas::MakeTestPacketTagFromUniqueId(1, "IPv4 UDP packet"))
      .RegisterValue("@payload_ipv6",
                     dvaas::MakeTestPacketTagFromUniqueId(2, "IPv6 UDP packet"))
      .RegisterValue("@ingress_port", egress_port)
      .RegisterValue("@egress_port", egress_port)
      .RegisterValue("@ingress_dst_mac", "00:aa:bb:cc:cc:dd")
      .RegisterValue("@ingress_src_mac", "00:00:22:22:00:00")
      .RegisterValue("@egress_dst_mac",
                     (rewrite_options.dst_mac_rewrite.has_value()
                          ? rewrite_options.dst_mac_rewrite->ToString()
                          : "@ingress_dst_mac"))
      .RegisterValue("@egress_src_mac",
                     (rewrite_options.src_mac_rewrite.has_value()
                          ? rewrite_options.src_mac_rewrite->ToString()
                          : "@ingress_src_mac"))
      .RegisterValue("@ttl", "0x10")
      .RegisterValue("@decremented_ttl", "0x0f");

  repo.RegisterSnippetOrDie<packetlib::Header>("@ethernet_ipv4", R"pb(
        ethernet_header {
          ethernet_destination: @ingress_dst_mac,
          ethernet_source: @ingress_src_mac,
          ethertype: "0x0800"  # IPv4
        }
      )pb")
      .RegisterSnippetOrDie<packetlib::Header>("@ipv4", R"pb(
        ipv4_header {
          version: "0x4"
          dscp: "0x1b"
          ecn: "0x1"
          ihl: "0x5"
          identification: "0x0000"
          flags: "0x0"
          ttl: @ttl
          fragment_offset: "0x0000"
          # payload_length: filled in automatically.
          protocol: "0x11"  # UDP
          ipv4_source: "10.0.0.8"
          ipv4_destination: "10.0.0.1"
        }
      )pb")
      .RegisterSnippetOrDie<packetlib::Header>("@udp", R"pb(
        udp_header { source_port: "0x0014" destination_port: "0x000a" }
      )pb")
      .RegisterMessage("@input_packet_ipv4",
                       repo.ParseTextOrDie<packetlib::Packet>(
                           R"pb(
                             headers: @ethernet_ipv4
                             headers: @ipv4
                             headers: @udp
                             payload: @payload_ipv4
                           )pb"))
      .RegisterMessage(
          "@output_packet_ipv4", repo.ParseTextOrDie<packetlib::Packet>(R"pb(
            headers: @ethernet_ipv4 {
              ethernet_header {
                ethernet_destination: @egress_dst_mac
                ethernet_source: @egress_src_mac
              }
            }
            headers: @ipv4 { ipv4_header { ttl: @decremented_ttl } }
            headers: @udp
            payload: @payload_ipv4
          )pb"))
      .RegisterSnippetOrDie<packetlib::Header>("@ethernet_ipv6", R"pb(
        ethernet_header {
          ethernet_destination: @ingress_dst_mac,
          ethernet_source: @ingress_src_mac,
          ethertype: "0x86dd"  # IPv6
        }
      )pb")
      .RegisterSnippetOrDie<packetlib::Header>("@ipv6", R"pb(
        ipv6_header {
          version: "0x6"
          dscp: "0x1b"
          ecn: "0x1"
          flow_label: "0x12345"
          # payload_length: filled in automatically.
          next_header: "0x11"  # UDP
          hop_limit: @ttl
          ipv6_source: "2002:ad12:4100:3::"
          ipv6_destination: "2002:ad12:4100:1::"
        }
      )pb")
      .RegisterMessage("@input_packet_ipv6",
                       repo.ParseTextOrDie<packetlib::Packet>(
                           R"pb(
                             headers: @ethernet_ipv6
                             headers: @ipv6
                             headers: @udp
                             payload: @payload_ipv6
                           )pb"))
      .RegisterMessage(
          "@output_packet_ipv6", repo.ParseTextOrDie<packetlib::Packet>(R"pb(
            headers: @ethernet_ipv6 {
              ethernet_header {
                ethernet_destination: @egress_dst_mac
                ethernet_source: @egress_src_mac
              }
            }
            headers: @ipv6 { ipv6_header { hop_limit: @decremented_ttl } }
            headers: @udp
            payload: @payload_ipv6
          )pb"));

  std::vector<dvaas::PacketTestVector> test_vectors;
  // Add IPv4 test vector.
  test_vectors.push_back(repo.ParseTextOrDie<dvaas::PacketTestVector>(R"pb(
    input {
      type: DATAPLANE
      packet { port: @ingress_port parsed: @input_packet_ipv4 }
    }
    acceptable_outputs {
      packets { port: @egress_port parsed: @output_packet_ipv4 }
      packet_ins {
        metadata {
          name: "ingress_port"
          value: { str: @ingress_port }
        }
        metadata {
          name: "target_egress_port"
          value: { str: @egress_port }
        }
        parsed: @input_packet_ipv4
      }
    }
  )pb"));

  // Add IPv6 test vector.
  test_vectors.push_back(repo.ParseTextOrDie<dvaas::PacketTestVector>(R"pb(
    input {
      type: DATAPLANE
      packet { port: @ingress_port parsed: @input_packet_ipv6 }
    }
    acceptable_outputs {
      packets { port: @egress_port parsed: @output_packet_ipv6 }
      packet_ins {
        metadata {
          name: "ingress_port"
          value: { str: @ingress_port }
        }
        metadata {
          name: "target_egress_port"
          value: { str: @egress_port }
        }
        parsed: @input_packet_ipv6
      }
    }
  )pb"));

  for (dvaas::PacketTestVector& test_vector : test_vectors) {
    for (dvaas::SwitchOutput& output :
         *test_vector.mutable_acceptable_outputs()) {
      if (!punt_action.has_value()) {
        output.clear_packet_ins();
      } else if (punt_action.value() == sai::PuntAction::kTrap) {
        output.clear_packets();
      }
    }
  }
  return test_vectors;
}

// Helper routine to install L3 route
absl::Status InstallL3Route(pdpi::P4RuntimeSession* switch_session,
                            const pdpi::IrP4Info& ir_p4info,
                            absl::string_view egress_port,
                            const sai::NexthopRewriteOptions& rewrite_options,
                            std::optional<sai::PuntAction> punt_action) {
  std::vector<p4::v1::Entity> pi_entities;
  LOG(INFO) << "Installing L3 route";

  sai::EntryBuilder entry_builder =
      sai::EntryBuilder().AddEntriesForwardingIpPacketsToGivenPort(
          egress_port, sai::IpVersion::kIpv4And6, rewrite_options);

  if (punt_action.has_value()) {
    entry_builder.AddEntryPuntingAllPackets(punt_action.value());
  } else {
    RETURN_IF_ERROR(
        SetUpIngressAclForwardingAllPackets(switch_session, ir_p4info));
  }
  ASSIGN_OR_RETURN(
      pi_entities,
      entry_builder.LogPdEntries().GetDedupedPiEntities(ir_p4info));
  RETURN_IF_ERROR(pdpi::InstallPiEntities(*switch_session, pi_entities));
  return absl::OkStatus();
}

TEST_P(AclFeatureTestFixture, AclDenyAction) {
  const AclFeatureTestParams& params = GetParam();
  dvaas::DataplaneValidationParams dvaas_params = params.dvaas_params;

  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();

  if (params.punt_action == sai::PuntAction::kTrap) {
    testbed.Environment().SetTestCaseID("bbff38be-2da4-40fb-b895-8a44c5e7e909");
  } else if (params.punt_action == sai::PuntAction::kCopy) {
    testbed.Environment().SetTestCaseID("b0d0353f-21d5-4863-82fb-2b1b3239147b");
  } else {
    testbed.Environment().SetTestCaseID("6debdcf9-8079-461f-ad4f-4bbe67f8279e");
  }

  // Initialize the connection, clear all entities, and (for the SUT) push
  // P4Info.
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.Sut(), /*gnmi_config=*/std::nullopt, GetParam().sut_p4info));
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<pdpi::P4RuntimeSession> control_switch_p4rt_session,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.ControlSwitch(), /*gnmi_config=*/std::nullopt,
          /*p4info=*/std::nullopt));
  ASSERT_NE(sut_p4rt_session, nullptr);
  ASSERT_NE(control_switch_p4rt_session, nullptr);

  ASSERT_OK_AND_ASSIGN(
      p4::v1::GetForwardingPipelineConfigResponse sut_config,
      pdpi::GetForwardingPipelineConfig(sut_p4rt_session.get()));
  ASSERT_OK(testbed.Environment().StoreTestArtifact(
      "sut_p4Info.textproto", sut_config.config().p4info().DebugString()));
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info sut_ir_p4info,
                       pdpi::CreateIrP4Info(sut_config.config().p4info()));

  // Get control ports to test on.
  ASSERT_OK_AND_ASSIGN(
      auto gnmi_stub_control,
      GetParam().mirror_testbed->GetMirrorTestbed().Sut().CreateGnmiStub());
  ASSERT_OK_AND_ASSIGN(std::string control_port,
                       pins_test::GetAnyUpInterfacePortId(*gnmi_stub_control));

  // Since we don't care about the egress packet's source and destination mac,
  // we use the default rewrite options.
  const sai::NexthopRewriteOptions rewrite_options;

  ASSERT_OK(InstallL3Route(sut_p4rt_session.get(), sut_ir_p4info, control_port,
                           rewrite_options, params.punt_action));

  // Run test with custom packet test vector.
  dvaas_params.packet_test_vector_override =
      MakePackets(control_port, rewrite_options, params.punt_action);
  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result,
      GetParam().dvaas->ValidateDataplane(testbed, dvaas_params));

  // Log statistics and check that things succeeded.
  validation_result.LogStatistics();
  EXPECT_OK(validation_result.HasSuccessRateOfAtLeast(1.0));

  ASSERT_OK_AND_ASSIGN(sut_p4rt_session,
                       pdpi::P4RuntimeSession::Create(testbed.Sut()));

  // Install AclDeny
  ASSERT_OK_AND_ASSIGN(auto proto_entry,
                       gutil::ParseTextProto<pdpi::IrTableEntry>(
                           R"pb(table_name: "acl_ingress_security_table"
                                priority: 1
                                action { name: "acl_deny" }
                           )pb"));

  EXPECT_OK(pdpi::InstallIrTableEntry(*sut_p4rt_session.get(), proto_entry));
  for (dvaas::PacketTestVector& test_vector :
       dvaas_params.packet_test_vector_override) {
    for (dvaas::SwitchOutput& output :
         *test_vector.mutable_acceptable_outputs()) {
      output.clear_packet_ins();
      output.clear_packets();
    }
  }

  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result2,
      GetParam().dvaas->ValidateDataplane(testbed, dvaas_params));

  // Log statistics and check that things succeeded.
  validation_result2.LogStatistics();
  EXPECT_OK(validation_result2.HasSuccessRateOfAtLeast(1.0));
}

TEST_P(AclFeatureTestFixture, AclEgressL2Table) {
  const AclFeatureTestParams& params = GetParam();
  dvaas::DataplaneValidationParams dvaas_params = params.dvaas_params;
  dvaas_params.artifact_prefix = "sanity_dvaas";
  const netaddr::MacAddress output_src_mac(0x1, 0x2, 0x3, 0x1, 0x2, 0x3);

  // we are not testing punt action in this test
  // so skip for those variants
  if (params.punt_action.has_value()) {
    GTEST_SKIP();
  }

  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();

  testbed.Environment().SetTestCaseID("3ff70f54-5b35-44ff-8084-deedc98afe2d");

  // Initialize the connection, clear all entities, and (for the SUT) push
  // P4Info.
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.Sut(), /*gnmi_config=*/std::nullopt, GetParam().sut_p4info));
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<pdpi::P4RuntimeSession> control_switch_p4rt_session,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.ControlSwitch(), /*gnmi_config=*/std::nullopt,
          /*p4info=*/std::nullopt));
  ASSERT_NE(sut_p4rt_session, nullptr);
  ASSERT_NE(control_switch_p4rt_session, nullptr);

  ASSERT_OK_AND_ASSIGN(
      p4::v1::GetForwardingPipelineConfigResponse sut_config,
      pdpi::GetForwardingPipelineConfig(sut_p4rt_session.get()));
  ASSERT_OK(testbed.Environment().StoreTestArtifact(
      "sut_p4Info.textproto", sut_config.config().p4info().DebugString()));
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info sut_ir_p4info,
                       pdpi::CreateIrP4Info(sut_config.config().p4info()));

  // Get control ports to test on.
  ASSERT_OK_AND_ASSIGN(
      auto gnmi_stub_control,
      GetParam().mirror_testbed->GetMirrorTestbed().Sut().CreateGnmiStub());
  ASSERT_OK_AND_ASSIGN(std::string control_port,
                       pins_test::GetAnyUpInterfacePortId(*gnmi_stub_control));

  const sai::NexthopRewriteOptions rewrite_options = {.src_mac_rewrite =
                                                          output_src_mac};

  ASSERT_OK(InstallL3Route(sut_p4rt_session.get(), sut_ir_p4info, control_port,
                           rewrite_options, /*punt_action=*/std::nullopt));

  // Run test with custom packet test vector.
  dvaas_params.packet_test_vector_override =
      MakePackets(control_port, rewrite_options, /*punt_action=*/std::nullopt);
  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result,
      GetParam().dvaas->ValidateDataplane(testbed, dvaas_params));

  // Log statistics and check that things succeeded.
  validation_result.LogStatistics();
  EXPECT_OK(validation_result.HasSuccessRateOfAtLeast(1.0));

  ASSERT_OK_AND_ASSIGN(sut_p4rt_session,
                       pdpi::P4RuntimeSession::Create(testbed.Sut()));

  // Install AclEgress Drop
  ASSERT_OK_AND_ASSIGN(auto proto_entry,
                       gutil::ParseTextProto<pdpi::IrTableEntry>(
                           R"pb(table_name: "acl_egress_l2_table"
                                priority: 1
                                matches {
                                  name: "src_mac"
                                  ternary {
                                    value { mac: "01:02:03:01:02:03" }
                                    mask { mac: "ff:ff:ff:ff:ff:ff" }
                                  }
                                }
                                action { name: "acl_drop" }
                           )pb"));

  EXPECT_OK(pdpi::InstallIrTableEntry(*sut_p4rt_session.get(), proto_entry));

  for (dvaas::PacketTestVector& test_vector :
       dvaas_params.packet_test_vector_override) {
    for (dvaas::SwitchOutput& output :
         *test_vector.mutable_acceptable_outputs()) {
      output.clear_packets();
    }
  }

  dvaas_params.artifact_prefix = "real_test_dvaas";
  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result2,
      GetParam().dvaas->ValidateDataplane(testbed, dvaas_params));

  // Log statistics and check that things succeeded.
  validation_result2.LogStatistics();
  EXPECT_OK(validation_result2.HasSuccessRateOfAtLeast(1.0));
}

}  // namespace
}  // namespace pins_test
