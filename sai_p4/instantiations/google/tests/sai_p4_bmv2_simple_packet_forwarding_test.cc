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

// Test packets with various headers can be forwarded by BMv2.
//
// These tests implicitly test these properties of P4 and Packetlib for various
// packets:
// - P4's parser and deparser can handle headers of packets under test and
//   maintain roundtrip property such that a parsed packet under test can be
//   deparsed back to the original packet.
// - Packetlib can handle headers of packets under test during packet
//   construction and during Packetlib's packet parsing.
//
// Note, even though the test file name contains words that suggest we are
// testing forwarding, forwarding is just a means to an end. The end goal is to
// test the above properties of P4 and Packetlib.
//
// Most, if not all the tests, will follow the following pattern:
// - Create a BMv2 and install entries to forward all packets without rewrites
//   to a fixed port.
// - Create a packet with a set of headers we are interested in testing.
// - Send the packet to the BMv2.
// - Verify the packet is forwarded to the expected port.
// - Verify the received packets are identical (modulo rewrites that are not
//   disabled) to the sent packet.

#include <optional>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/packetlib/packetlib.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "platforms/networking/p4/p4_infra/bmv2/bmv2.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "sai_p4/instantiations/google/sai_p4info.h"
#include "sai_p4/instantiations/google/test_tools/set_up_bmv2.h"
#include "sai_p4/instantiations/google/test_tools/test_entries.h"

namespace pins {
namespace {

using SimplePacketForwardingTest = testing::TestWithParam<sai::Instantiation>;
using PacketsByPort = absl::flat_hash_map<int, packetlib::Packets>;
using ::orion::p4::test::Bmv2;
using ::testing::EqualsProto;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;
using ::testing::status::IsOkAndHolds;

constexpr absl::string_view kEgressPortProto = "\001";
constexpr int kEgressPort = 1;
constexpr int kIngressPort = 2;

void PreparePacketOrDie(packetlib::Packet& packet) {
  CHECK_OK(packetlib::PadPacketToMinimumSize(packet).status());  // Crash OK.
  CHECK_OK(
      packetlib::UpdateMissingComputedFields(packet).status());  // Crash OK.
}

// Returns a PSAMP-encapsulated packet with all the fields in the headers set
// to some hard-coded values.
absl::StatusOr<packetlib::Packet> PsampEncappedPacket() {
  packetlib::Packet packet;

  packetlib::Header& ethernet_header = *packet.add_headers();
  ethernet_header.mutable_ethernet_header()->set_ethertype("0x8100");
  ethernet_header.mutable_ethernet_header()->set_ethernet_destination(
      "00:08:08:08:08:08");
  ethernet_header.mutable_ethernet_header()->set_ethernet_source(
      "01:09:09:09:09:09");

  packetlib::Header& vlan_header = *packet.add_headers();
  vlan_header.mutable_vlan_header()->set_priority_code_point("0x0");
  vlan_header.mutable_vlan_header()->set_drop_eligible_indicator("0x0");
  vlan_header.mutable_vlan_header()->set_vlan_identifier("0x123");
  vlan_header.mutable_vlan_header()->set_ethertype("0x86dd");

  packetlib::Header& ipv6_header = *packet.add_headers();
  ipv6_header.mutable_ipv6_header()->set_dscp("0x00");
  ipv6_header.mutable_ipv6_header()->set_ecn("0x0");
  ipv6_header.mutable_ipv6_header()->set_flow_label("0x00000");
  ipv6_header.mutable_ipv6_header()->set_hop_limit("0x10");
  ipv6_header.mutable_ipv6_header()->set_version("0x6");
  // IP_PROTOCOL for UDP.
  ipv6_header.mutable_ipv6_header()->set_next_header("0x11");
  ipv6_header.mutable_ipv6_header()->set_ipv6_source("::3");
  ipv6_header.mutable_ipv6_header()->set_ipv6_destination("::4");

  packetlib::Header& udp_header = *packet.add_headers();
  udp_header.mutable_udp_header()->set_source_port("0x1234");
  // Must be 0x1283 to indicate the next header is IPFIX.
  udp_header.mutable_udp_header()->set_destination_port("0x1283");

  packetlib::IpfixHeader& ipfix = *packet.add_headers()->mutable_ipfix_header();
  ipfix.set_version(packetlib::IpfixVersion(0x0A));
  ipfix.set_export_time(
      packetlib::IpfixExportTime(absl::ToUnixSeconds(absl::Now()) - 10));
  ipfix.set_sequence_number(packetlib::IpfixSequenceNumber(1));
  ipfix.set_observation_domain_id(packetlib::IpfixObservationDomainId(1));

  packetlib::PsampHeader& psamp = *packet.add_headers()->mutable_psamp_header();
  psamp.set_template_id(packetlib::PsampTemplateId(0));
  psamp.set_observation_time(
      packetlib::PsampObservationTime(absl::ToUnixNanos(absl::Now())));
  psamp.set_flowset(packetlib::PsampFlowset(0x1234));
  psamp.set_next_hop_index(packetlib::PsampNextHopIndex(0));
  psamp.set_epoch(packetlib::PsampEpoch(0xABCD));
  psamp.set_ingress_port(packetlib::PsampIngressPort(0x0d));
  psamp.set_egress_port(packetlib::PsampEgressPort(0x0f));
  psamp.set_user_meta_field(packetlib::PsampUserMetaField(0));
  psamp.set_dlb_id(packetlib::PsampDlbId(0));

  packet.set_payload("random payload...");

  PreparePacketOrDie(packet);
  return packet;
}

// Test PSAMP encapped packets.
TEST_P(SimplePacketForwardingTest, PsampEncappedPacketsTest) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install entries to disable VLAN checks and forward all IP packets without
  // rewrites.
  sai::EntryBuilder entry_builder;
  ASSERT_OK(entry_builder
                .AddEntriesForwardingIpPacketsToGivenPort(
                    kEgressPortProto, sai::IpVersion::kIpv4And6,
                    sai::NexthopRewriteOptions{
                        .disable_decrement_ttl = true,
                        .src_mac_rewrite = std::nullopt,
                        .dst_mac_rewrite = std::nullopt,
                        .disable_vlan_rewrite = true,
                    })
                .AddDisableVlanChecksEntry()
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  ASSERT_OK_AND_ASSIGN(const packetlib::Packet input_packet,
                       PsampEncappedPacket());

  packetlib::Packets output_packets;
  *output_packets.add_packets() = input_packet;

  EXPECT_THAT(bmv2.SendPacket(kIngressPort, input_packet),
              IsOkAndHolds(UnorderedElementsAre(
                  Pair(kEgressPort, EqualsProto(output_packets)))));
}

INSTANTIATE_TEST_SUITE_P(
    SimplePacketForwardingTest, SimplePacketForwardingTest,
    testing::ValuesIn(sai::AllSaiInstantiations()),
    [&](const testing::TestParamInfo<sai::Instantiation>& info) {
      return InstantiationToString(info.param);
    });

}  // namespace
}  // namespace pins
