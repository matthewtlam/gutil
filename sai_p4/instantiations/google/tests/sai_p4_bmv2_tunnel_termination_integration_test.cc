// Tests that tunnel termination (in particular, `tunnel_termination.p4`)
// functions as intended on BMv2.

// Copyright 2023 Google LLC
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

#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/proto_matchers.h"
#include "gutil/status.h"
#include "gutil/status_matchers.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/netaddr/ipv4_address.h"
#include "p4_pdpi/netaddr/ipv6_address.h"
#include "p4_pdpi/netaddr/mac_address.h"
#include "p4_pdpi/p4_runtime_matchers.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/p4_runtime_session_extras.h"
#include "p4_pdpi/packetlib/packetlib.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "p4_pdpi/packetlib/packetlib_matchers.h"
#include "platforms/networking/p4/p4_infra/bmv2/bmv2.h"
#include "sai_p4/fixed/ids.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "sai_p4/instantiations/google/sai_p4info.h"
#include "sai_p4/instantiations/google/sai_pd.pb.h"
#include "sai_p4/instantiations/google/test_tools/set_up_bmv2.h"
#include "sai_p4/instantiations/google/test_tools/test_entries.h"
#include "tests/forwarding/packet_at_port.h"

namespace pins {
namespace {

using ::gutil::EqualsProto;
using ::gutil::IsOkAndHolds;
using ::orion::p4::test::Bmv2;
using ::packetlib::HasHeaderCase;
using ::pdpi::HasPacketIn;
using ::pdpi::ParsedPayloadIs;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::StrEq;

constexpr netaddr::MacAddress kSrcMac = netaddr::MacAddress(0, 1, 2, 3, 4, 5);
constexpr netaddr::MacAddress kDstMac = netaddr::MacAddress(2, 3, 4, 5, 6, 7);
constexpr netaddr::Ipv4Address kDstIp4 = netaddr::Ipv4Address(192, 168, 100, 1);
const netaddr::Ipv6Address kDstIp6 = netaddr::Ipv6Address(0x2001, 0x2);
// IPv4 multicast MAC, see
// https://en.wikipedia.org/wiki/Multicast_address#Ethernet
constexpr netaddr::MacAddress kMcDstMacV4 =
    netaddr::MacAddress(0x01, 0x00, 0x5e, 0x05, 0x06, 0x07);
// IPv6 multicast MAC, see
// https://en.wikipedia.org/wiki/Multicast_address#Ethernet
constexpr netaddr::MacAddress kMcDstMacV6 =
    netaddr::MacAddress(0x33, 0x33, 0x04, 0x05, 0x06, 0x07);
// "Source-specific multicast" address, see
// https://en.wikipedia.org/wiki/Multicast_address#I0Pv4
constexpr netaddr::Ipv4Address kMcDstIp4 = netaddr::Ipv4Address(232, 1, 2, 3);
// "Source-specific multicast" address, see
// https://en.wikipedia.org/wiki/Multicast_address#IPv6
const netaddr::Ipv6Address kMcDstIp6 = netaddr::Ipv6Address(0xff30, 0x2);

absl::StatusOr<packetlib::Packet> GetIpv4InIpv6Packet(
    const netaddr::MacAddress& src_mac, const netaddr::MacAddress& dst_mac,
    const netaddr::Ipv4Address& ipv4_dst_ip,
    const netaddr::Ipv6Address& ipv6_dst_ip) {
  ASSIGN_OR_RETURN(auto packet,
                   gutil::ParseTextProto<packetlib::Packet>(absl::Substitute(
                       R"pb(
                         headers {
                           ethernet_header {
                             ethernet_source: "$0"
                             ethernet_destination: "$1"
                             ethertype: "0x86dd"  # IPv6
                           }
                         }
                         headers {
                           ipv6_header {
                             version: "0x6"
                             dscp: "0x00"
                             ecn: "0x0"
                             flow_label: "0x12345"
                             next_header: "0x04"  # IPv4
                             hop_limit: "0x03"
                             ipv6_source: "2001::1"
                             ipv6_destination: "$2"
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
                             ipv4_destination: "$3"
                           }
                         }
                         payload: "A beautiful IPv4-in-IPv6 test packet."
                       )pb",
                       src_mac.ToString(), dst_mac.ToString(),
                       ipv6_dst_ip.ToString(), ipv4_dst_ip.ToString())));
  RETURN_IF_ERROR(packetlib::UpdateAllComputedFields(packet).status());
  return packet;
}

absl::StatusOr<packetlib::Packet> GetIpv6InIpv6Packet(
    const netaddr::MacAddress& src_mac, const netaddr::MacAddress& dst_mac,
    const netaddr::Ipv6Address& ipv6_inner_dst_ip,
    const netaddr::Ipv6Address& ipv6_outer_dst_ip) {
  ASSIGN_OR_RETURN(auto packet,
                   gutil::ParseTextProto<packetlib::Packet>(
                       R"pb(
                         headers {
                           ethernet_header {
                             ethertype: "0x86dd"  # IPv6
                             # ethernet_source: assigned below
                             # ethernet_destination: assigned below
                           }
                         }
                         headers {
                           ipv6_header {
                             version: "0x6"
                             dscp: "0x00"
                             ecn: "0x0"
                             flow_label: "0x12345"
                             next_header: "0x29"  # IPv6
                             hop_limit: "0x03"
                             ipv6_source: "2001::1"
                             # ipv6_destination: assigned below
                           }
                         }
                         headers {
                           ipv6_header {
                             version: "0x6"
                             dscp: "0x00"
                             ecn: "0x0"
                             flow_label: "0x12345"
                             next_header: "0xfe"
                             hop_limit: "0x03"
                             ipv6_source: "2001::1"
                             # ipv6_destination: assigned below
                           }
                         }
                         payload: "A beautiful IPv4-in-IPv6 test packet."
                       )pb"));
  packet.mutable_headers(0)->mutable_ethernet_header()->set_ethernet_source(
      src_mac.ToString());
  packet.mutable_headers(0)
      ->mutable_ethernet_header()
      ->set_ethernet_destination(dst_mac.ToString());
  packet.mutable_headers(1)->mutable_ipv6_header()->set_ipv6_destination(
      ipv6_outer_dst_ip.ToString());
  packet.mutable_headers(2)->mutable_ipv6_header()->set_ipv6_destination(
      ipv6_inner_dst_ip.ToString());
  RETURN_IF_ERROR(packetlib::UpdateAllComputedFields(packet).status());
  return packet;
}

using TunnelTerminationTest = testing::TestWithParam<sai::Instantiation>;

// Conditions for tunnel termination: go/tunneldecap_and_multicast_verification.
TEST_P(TunnelTerminationTest, PacketMustMeetConditionsToBeTunnelTerminated) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: entries for decap (l3 and tunnel termination) and
  // entries that will forward IPv4 packets.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntrySettingVrfForAllPackets("vrf")
                .AddEntryAdmittingAllPacketsToL3()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddDefaultRouteForwardingAllPacketsToGivenPort(
                    /*egress_port=*/"\001", sai::IpVersion::kIpv4, "vrf")
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Start with valid input packet that decaps and forwards IPv4 packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet valid_input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(valid_input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);

  // No tunnel termination due to non-UNICAST DMAC.
  packetlib::Packet non_unicast_dmac_packet = valid_input_packet;
  non_unicast_dmac_packet.mutable_headers(0)
      ->mutable_ethernet_header()
      ->set_ethernet_destination(kMcDstMacV6.ToString());
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(non_unicast_dmac_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  EXPECT_TRUE(output_packets.empty());

  // No tunnel termination due to hop limit being 0.
  packetlib::Packet hop_limit_0_packet = valid_input_packet;
  hop_limit_0_packet.mutable_headers(1)->mutable_ipv6_header()->set_hop_limit(
      "0x00");
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(hop_limit_0_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  EXPECT_TRUE(output_packets.empty());

  // No tunnel termination due to src address being 0.
  packetlib::Packet src_addr_0_packet = valid_input_packet;
  src_addr_0_packet.mutable_headers(1)->mutable_ipv6_header()->set_ipv6_source(
      "::");
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(src_addr_0_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  EXPECT_TRUE(output_packets.empty());

  // No tunnel termination due to src address being dst address.
  packetlib::Packet src_addr_eq_dst_addr_packet = valid_input_packet;
  *src_addr_eq_dst_addr_packet.mutable_headers(1)
       ->mutable_ipv6_header()
       ->mutable_ipv6_source() = src_addr_eq_dst_addr_packet.mutable_headers(1)
                                     ->mutable_ipv6_header()
                                     ->ipv6_destination();
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(src_addr_eq_dst_addr_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  EXPECT_TRUE(output_packets.empty());

  // No tunnel termination due to src address being loopback address.
  packetlib::Packet loopback_src_addr_packet = valid_input_packet;
  loopback_src_addr_packet.mutable_headers(1)
      ->mutable_ipv6_header()
      ->set_ipv6_source("::1");
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(src_addr_eq_dst_addr_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  EXPECT_TRUE(output_packets.empty());

  // No tunnel termination due to src address being multicast address.
  packetlib::Packet multicast_src_addr_packet = valid_input_packet;
  multicast_src_addr_packet.mutable_headers(1)
      ->mutable_ipv6_header()
      ->set_ipv6_source(kMcDstIp6.ToString());
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(multicast_src_addr_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  EXPECT_TRUE(output_packets.empty());
}

TEST_P(TunnelTerminationTest, OuterDscpFieldPreservedOnDecap) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: entries for decap (l3 and tunnel termination) and
  // entries forwarding all packets.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntrySettingVrfForAllPackets("vrf")
                .AddEntryAdmittingAllPacketsToL3()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddDefaultRouteForwardingAllPacketsToGivenPort(
                    /*egress_port=*/"\001", sai::IpVersion::kIpv4And6, "vrf")
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  const std::string kOuterDscp = "0x01";
  const std::string kInnerDscp = "0x07";

  // Expect DSCP to be copied over on decap of 4in6 packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet ip_4in6_input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ip_4in6_input_packet.mutable_headers(1)->mutable_ipv6_header()->set_dscp(
      kOuterDscp);
  ip_4in6_input_packet.mutable_headers(2)->mutable_ipv4_header()->set_dscp(
      kInnerDscp);
  ASSERT_OK(packetlib::UpdateAllComputedFields(ip_4in6_input_packet).status());
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(ip_4in6_input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_EQ(output_packet.headers().size(), 2);
  EXPECT_EQ(output_packet.headers(1).ipv4_header().dscp(), kOuterDscp);

  // Expect DSCP to be copied over on decap of 6in6 packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet ip_6in6_input_packet,
                       GetIpv6InIpv6Packet(kSrcMac, kDstMac, kDstIp6, kDstIp6));
  ip_6in6_input_packet.mutable_headers(1)->mutable_ipv6_header()->set_dscp(
      kOuterDscp);
  ip_6in6_input_packet.mutable_headers(2)->mutable_ipv6_header()->set_dscp(
      kInnerDscp);
  ASSERT_OK(packetlib::UpdateAllComputedFields(ip_6in6_input_packet).status());
  ASSERT_OK_AND_ASSIGN(raw_input_packet,
                       packetlib::SerializePacket(ip_6in6_input_packet));
  ASSERT_OK_AND_ASSIGN(output_packets, bmv2.SendPacket(pins::PacketAtPort{
                                           .port = 42,
                                           .data = raw_input_packet,
                                       }));
  ASSERT_EQ(output_packets.size(), 1);
  output_packet = packetlib::ParsePacket(output_packets[0].data);
  EXPECT_EQ(output_packet.headers().size(), 2);
  EXPECT_EQ(output_packet.headers(1).ipv6_header().dscp(), kOuterDscp);
}

TEST_P(
    TunnelTerminationTest,
    AclMatchesOnInnerHeaderAndPacketIsNotDecappedIfTunnelTerminatedAndNotL3Admitted) {  // NOLINT
  const sai::Instantiation kInstantiation = GetParam();
  // Only middleblock supports tunnel termination and redirect to port.
  if (kInstantiation != sai::Instantiation::kMiddleblock) {
    GTEST_SKIP() << "Skipping test for non-middleblock instantiation.";
  }
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: tunnel terminate and do not admit to L3 (no decap).
  // Match on both ipv4 and ipv6 to check that inner header is used.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddIngressAclEntryRedirectingToPort(
                    /*port=*/"\001",
                    sai::MirrorAndRedirectMatchFields{
                        .is_ipv4 = true,
                    },
                    /*priority=*/1)
                // Although this entry has higher priority, it will be ignored
                // as the inner header is used.
                .AddIngressAclEntryRedirectingToPort(
                    /*port=*/"\002",
                    sai::MirrorAndRedirectMatchFields{
                        .is_ipv6 = true,
                    },
                    /*priority=*/2)
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession(),
                                        /*allow_unsupported=*/true));

  // Inject Ipv4-in-IPv6 test packet and expect one undecapped output packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ASSERT_THAT(input_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_THAT(output_packet.reasons_invalid(), IsEmpty());

  // The forwarded packet should not be decapped and is forwarded according to
  // ipv6 rule (to port 1).
  EXPECT_EQ(output_packets[0].port, 1);
  // NOTE: ACL redirect to port does not update ttl.
  EXPECT_THAT(gutil::ProtoDiff(input_packet, output_packet),
              IsOkAndHolds(StrEq("")));
}

TEST_P(
    TunnelTerminationTest,
    AclMatchesOnInnerHeaderAndPacketIsDecappedIfTunnelTerminatedAndL3Admitted) {
  const sai::Instantiation kInstantiation = GetParam();
  // Only middleblock supports tunnel termination and redirect to port.
  if (kInstantiation != sai::Instantiation::kMiddleblock) {
    GTEST_SKIP() << "Skipping test for non-middleblock instantiation.";
  }
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: tunnel terminate and admit to L3 (decap). Match on
  // both ipv4 and ipv6 to check that inner header is used.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddEntryAdmittingAllPacketsToL3()
                .AddIngressAclEntryRedirectingToPort(
                    /*port=*/"\001",
                    sai::MirrorAndRedirectMatchFields{
                        .is_ipv4 = true,
                    },
                    /*priority=*/1)
                // Although this entry has higher priority, it will be ignored
                // as the inner header is used.
                .AddIngressAclEntryRedirectingToPort(
                    /*port=*/"\002",
                    sai::MirrorAndRedirectMatchFields{
                        .is_ipv6 = true,
                    },
                    /*priority=*/2)
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession(),
                                        /*allow_unsupported=*/true));

  // Inject Ipv4-in-IPv6 test packet and expect one decapped output packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ASSERT_THAT(input_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_THAT(output_packet.reasons_invalid(), IsEmpty());

  // The forwarded packet should be like the input packet but with the outer IP
  // header stripped and ethertype updated.
  EXPECT_EQ(output_packets[0].port, 1);
  ASSERT_THAT(output_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  auto decapped_packet = input_packet;
  decapped_packet.mutable_headers()->erase(
      decapped_packet.mutable_headers()->begin() + 1);
  // NOTE: ACL redirect to port does not update ttl.
  EXPECT_THAT(
      gutil::ProtoDiff(decapped_packet, output_packet),
      IsOkAndHolds(StrEq(
          R"(modified: headers[0].ethernet_header.ethertype: "0x86dd" -> "0x0800"
modified: headers[1].ipv4_header.dscp: "0x1c" -> "0x00"
modified: headers[1].ipv4_header.checksum: "0x5003" -> "0x5073"
)")));
}

TEST_P(
    TunnelTerminationTest,
    MulticastMatchesOnOuterHeaderAndPacketIsNotDecappedIfTunnelTerminatedAndNotL3Admitted) {  // NOLINT
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  constexpr int kIpv4McGroup = 4;
  constexpr int kIpv6McGroup = 6;

  // Install table entries: tunnel terminate and do not admit to L3 (no decap).
  // Match on both ipv4 and ipv6 to check that outer header is used.
  ASSERT_OK(sai::EntryBuilder()
                .AddVrfEntry("vrf")
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddEntrySettingVrfForAllPackets("vrf")
                .AddMulticastRoute("vrf", kMcDstIp4, kIpv4McGroup)
                .AddMulticastRoute("vrf", kMcDstIp6, kIpv6McGroup)
                .AddMulticastGroupEntry(
                    kIpv4McGroup,
                    {
                        sai::Replica{.egress_port = "\1", .instance = 0},
                    })
                .AddMulticastGroupEntry(
                    kIpv6McGroup,
                    {
                        sai::Replica{.egress_port = "\2", .instance = 0},
                    })
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Inject Ipv4-in-IPv6 test packet and expect one undecapped output packet.
  ASSERT_OK_AND_ASSIGN(
      packetlib::Packet input_packet,
      GetIpv4InIpv6Packet(kSrcMac, kMcDstMacV6, kMcDstIp4, kMcDstIp6));
  ASSERT_THAT(input_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_THAT(output_packet.reasons_invalid(), IsEmpty());

  // The forwarded packet should not be decapped and is forwarded according to
  // ipv6 rule (to port 2).
  EXPECT_EQ(output_packets[0].port, 2);
  EXPECT_THAT(
      gutil::ProtoDiff(input_packet, output_packet),
      IsOkAndHolds(StrEq(
          R"(modified: headers[1].ipv6_header.hop_limit: "0x03" -> "0x02"
)")));
}

TEST_P(
    TunnelTerminationTest,
    MulticastMatchesOnInnerHeaderAndPacketIsDecappedIfTunnelTerminatedAndL3Admitted) {  // NOLINT
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  constexpr int kIpv4McGroup = 4;
  constexpr int kIpv6McGroup = 6;

  // Install table entries: tunnel terminate and do not admit to L3 ( no decap).
  // Match on both ipv4 and ipv6 to check that outer header is used.
  ASSERT_OK(sai::EntryBuilder()
                .AddVrfEntry("vrf")
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddEntryAdmittingAllPacketsToL3()
                .AddEntrySettingVrfForAllPackets("vrf")
                .AddMulticastRoute("vrf", kMcDstIp4, kIpv4McGroup)
                .AddMulticastRoute("vrf", kMcDstIp6, kIpv6McGroup)
                .AddMulticastGroupEntry(
                    kIpv4McGroup,
                    {
                        sai::Replica{.egress_port = "\1", .instance = 0},
                    })
                .AddMulticastGroupEntry(
                    kIpv6McGroup,
                    {
                        sai::Replica{.egress_port = "\2", .instance = 0},
                    })
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Inject Ipv4-in-IPv6 test packet and expect one decapped output packet.
  ASSERT_OK_AND_ASSIGN(
      packetlib::Packet input_packet,
      GetIpv4InIpv6Packet(kSrcMac, kDstMac, kMcDstIp4, kMcDstIp6));
  ASSERT_THAT(input_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_THAT(output_packet.reasons_invalid(), IsEmpty());

  // The forwarded packet should be like the input packet but with the outer IP
  // header stripped and ethertype and MAC updated.
  EXPECT_EQ(output_packets[0].port, 1);
  ASSERT_THAT(output_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  auto decapped_packet = input_packet;
  decapped_packet.mutable_headers()->erase(
      decapped_packet.mutable_headers()->begin() + 1);
  EXPECT_THAT(
      gutil::ProtoDiff(decapped_packet, output_packet),
      IsOkAndHolds(StrEq(
          R"(modified: headers[0].ethernet_header.ethernet_destination: "02:03:04:05:06:07" -> "01:00:5e:01:02:03"
modified: headers[0].ethernet_header.ethertype: "0x86dd" -> "0x0800"
modified: headers[1].ipv4_header.dscp: "0x1c" -> "0x00"
modified: headers[1].ipv4_header.ttl: "0x20" -> "0x1f"
modified: headers[1].ipv4_header.checksum: "0x8aa8" -> "0x8c18"
)")));
}

TEST_P(TunnelTerminationTest, RewritesMacAddressWhenDecappingIPMCV6Packet) {
  const sai::Instantiation kInstantiation = GetParam();
  // Only middleblock supports tunnel termination and redirect to port.
  if (kInstantiation != sai::Instantiation::kMiddleblock) {
    GTEST_SKIP() << "Skipping test for non-middleblock instantiation.";
  }
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: decap packet and forward to port 1.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddEntryAdmittingAllPacketsToL3()
                .AddIngressAclEntryRedirectingToPort(
                    /*port=*/"\001",
                    sai::MirrorAndRedirectMatchFields{
                        .is_ipv6 = true,
                    },
                    /*priority=*/1)
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession(),
                                        /*skip_acl_entries=*/true));

  // Inject Ipv6-in-IPv6 test packet and expect one decapped output packet.
  ASSERT_OK_AND_ASSIGN(
      packetlib::Packet input_packet,
      GetIpv6InIpv6Packet(kSrcMac, kDstMac, kMcDstIp6, kDstIp6));
  ASSERT_THAT(input_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header),
                          HasHeaderCase(packetlib::Header::kIpv6Header)));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_THAT(output_packet.reasons_invalid(), IsEmpty());

  // The forwarded packet should be decapped and the MAC address should be
  // rewritten.
  EXPECT_EQ(output_packets[0].port, 1);
  ASSERT_THAT(output_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header)));
  auto decapped_packet = input_packet;
  decapped_packet.mutable_headers()->erase(
      decapped_packet.mutable_headers()->begin() + 1);
  EXPECT_THAT(
      gutil::ProtoDiff(decapped_packet, output_packet),
      IsOkAndHolds(StrEq(
          R"(modified: headers[0].ethernet_header.ethernet_destination: "02:03:04:05:06:07" -> "33:33:00:00:00:00"
)")));
}

TEST_P(TunnelTerminationTest, IngressAclMatchesOnOriginalMac) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));
  // Install table entries: decap packet and forward to port 1.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddEntryAdmittingAllPacketsToL3()
                .AddEntryPuntingPacketsWithDstMac(kDstMac.ToString())
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Inject Ipv6-in-IPv6 test packet and expect punted packet.
  ASSERT_OK_AND_ASSIGN(
      packetlib::Packet input_packet,
      GetIpv6InIpv6Packet(kSrcMac, kDstMac, kMcDstIp6, kDstIp6));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  // The punted packet should be like the input packet.
  EXPECT_THAT(bmv2.P4RuntimeSession().ReadStreamChannelResponsesAndFinish(),
              IsOkAndHolds(ElementsAre(HasPacketIn())));
}

// Checks that decapsulation and VRF assignment work as expected for forwarded
// packets.
TEST_P(TunnelTerminationTest, PacketGetsDecapsulatedAndForwarded) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: decap & default route, so we can check that VRF
  // assignment works and observe the forwarded output packet.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntrySettingVrfForAllPackets("vrf")
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                // Needed for forwarding and decapping
                .AddEntryAdmittingAllPacketsToL3()
                .AddDefaultRouteForwardingAllPacketsToGivenPort(
                    /*egress_port=*/"\001", sai::IpVersion::kIpv4, "vrf",
                    // Rewrites to the same src and dst mac as the input packet.
                    sai::NexthopRewriteOptions{.src_mac_rewrite = kSrcMac,
                                               .dst_mac_rewrite = kDstMac})
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Inject Ipv4-in-IPv6 test packet and expect one output packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);
  packetlib::Packet output_packet =
      packetlib::ParsePacket(output_packets[0].data);
  EXPECT_THAT(output_packet.reasons_invalid(), IsEmpty());

  // The forwarded packet should be like the input packet but with the outer IP
  // header stripped, and some minor rewrites.
  ASSERT_THAT(input_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv6Header),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  ASSERT_THAT(output_packet.headers(),
              ElementsAre(HasHeaderCase(packetlib::Header::kEthernetHeader),
                          HasHeaderCase(packetlib::Header::kIpv4Header)));
  auto decapped_packet = input_packet;
  decapped_packet.mutable_headers()->erase(
      decapped_packet.mutable_headers()->begin() + 1);
  EXPECT_THAT(
      gutil::ProtoDiff(decapped_packet, output_packet),
      IsOkAndHolds(StrEq(
          R"(modified: headers[0].ethernet_header.ethertype: "0x86dd" -> "0x0800"
modified: headers[1].ipv4_header.dscp: "0x1c" -> "0x00"
modified: headers[1].ipv4_header.ttl: "0x20" -> "0x1f"
modified: headers[1].ipv4_header.checksum: "0x5003" -> "0x5173"
)")));
}

// Checks the interaction of pre ingress ACLs and tunnel termination:
// - Pre ingress ACLs see the original packet before decap.
TEST_P(TunnelTerminationTest,
       PreIngressAclMatchesOnUndecappedPacketAndOverridesDecapVrf) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: decap & default routes, so we can check that VRF
  // assignment works as expected by observing the egress port of the forwarded
  // output packet.
  ASSERT_OK(
      sai::EntryBuilder()
          .AddEntryTunnelTerminatingAllIpInIpv6Packets()
          // Needed for forwarding and decapping.
          .AddEntryAdmittingAllPacketsToL3()
          .AddPreIngressAclEntryAssigningVrfForGivenIpType(
              "acl-ipv4-vrf", sai::IpVersion::kIpv4)
          .AddPreIngressAclEntryAssigningVrfForGivenIpType(
              "acl-ipv6-vrf", sai::IpVersion::kIpv6)
          // Route that will apply if the ACL entry matching the decapped packet
          // determines the VRF.
          .AddDefaultRouteForwardingAllPacketsToGivenPort(
              /*egress_port=*/"\002", sai::IpVersion::kIpv4And6, "acl-ipv4-vrf")
          // Route that will apply if the ACL entry matching the undecapped
          // packet determines the VRF.
          .AddDefaultRouteForwardingAllPacketsToGivenPort(
              /*egress_port=*/"\003", sai::IpVersion::kIpv4And6, "acl-ipv6-vrf")
          .LogPdEntries()
          .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Inject Ipv4-in-IPv6 test packet and expect one output packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                       bmv2.SendPacket(pins::PacketAtPort{
                           .port = 42,
                           .data = raw_input_packet,
                       }));
  ASSERT_EQ(output_packets.size(), 1);

  // We expect the packet to receive VRF "acl-ipv6-vrf", and thus to egress on
  // port 3.
  EXPECT_EQ(output_packets[0].port, 3);
}

// Checks that decapsulation does not affect punted packets. See b/286604845.
TEST_P(TunnelTerminationTest, PuntedPacketIsNotDecapsulated) {
  const sai::Instantiation kInstantiation = GetParam();
  const pdpi::IrP4Info kIrP4Info = sai::GetIrP4Info(kInstantiation);
  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, sai::SetUpBmv2ForSaiP4(kInstantiation));

  // Install table entries: decap & punt to controller, so we can check that the
  // punted packet did not get decapped.
  ASSERT_OK(sai::EntryBuilder()
                .AddEntryTunnelTerminatingAllIpInIpv6Packets()
                .AddEntryAdmittingAllPacketsToL3()
                .AddEntryPuntingAllPackets(sai::PuntAction::kTrap)
                .LogPdEntries()
                .InstallDedupedEntities(kIrP4Info, bmv2.P4RuntimeSession()));

  // Inject Ipv4-in-IPv6 test packet and expect 0 forwarded packets and 1
  // punted packet.
  ASSERT_OK_AND_ASSIGN(packetlib::Packet input_packet,
                       GetIpv4InIpv6Packet(kSrcMac, kDstMac, kDstIp4, kDstIp6));
  ASSERT_OK_AND_ASSIGN(std::string raw_input_packet,
                       packetlib::SerializePacket(input_packet));
  ASSERT_THAT(bmv2.SendPacket(pins::PacketAtPort{
                  .port = 42,
                  .data = raw_input_packet,
              }),
              IsOkAndHolds(IsEmpty()));
  // The punted packet should be like the input packet.
  EXPECT_THAT(bmv2.P4RuntimeSession().ReadStreamChannelResponsesAndFinish(),
              IsOkAndHolds(ElementsAre(
                  HasPacketIn(ParsedPayloadIs(EqualsProto(input_packet))))));
}

INSTANTIATE_TEST_SUITE_P(
    TunnelTerminationTest, TunnelTerminationTest,
    // Decap is not supported on Taygeta-based roles.
    testing::Values(sai::Instantiation::kMiddleblock,
                    sai::Instantiation::kFabricBorderRouter),
    [&](const testing::TestParamInfo<sai::Instantiation>& info) {
      return InstantiationToString(info.param);
    });

}  // namespace
}  // namespace pins
