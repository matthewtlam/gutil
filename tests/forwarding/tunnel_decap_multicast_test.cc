#include "tests/forwarding/tunnel_decap_multicast_test.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "dvaas/dataplane_validation.h"
#include "dvaas/test_vector.h"
#include "dvaas/validation_result.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status.h"  // IWYU pragma: keep
#include "gutil/status.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "lib/gnmi/gnmi_helper.h"
#include "net/google::protobuf/contrib/fixtures/proto-fixture-repository.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/netaddr/ipv4_address.h"
#include "p4_pdpi/netaddr/ipv6_address.h"
#include "p4_pdpi/netaddr/mac_address.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/p4_runtime_session_extras.h"
#include "p4_pdpi/packetlib/packetlib.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "sai_p4/instantiations/google/sai_pd.pb.h"
#include "sai_p4/instantiations/google/test_tools/test_entries.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/switch.h"

namespace pins_test {
namespace {

using ::google::protobuf::contrib::fixtures::ProtoFixtureRepository;

static const auto kDstUnicastMacAddress =
    netaddr::MacAddress(0x00, 0xaa, 0xbb, 0xcc, 0xcc, 0xdd);
/* Multicast Ipv6 mac address */
static const auto kDstMulticastIpv6MacAddress =
    netaddr::MacAddress(0x33, 0x33, 0xbb, 0xcc, 0xcc, 0xdd);
static const auto kTunnelDstIpv6 = netaddr::Ipv6Address(
    0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
static const auto kTunnelSrcIpv6 = netaddr::Ipv6Address(
    0x1122, 0x1122, 0x3344, 0x3344, 0x5566, 0x5566, 0x7788, 0x7788);
static const auto kExactMask = netaddr::Ipv6Address(
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);
static const auto kTernaryMask =
    netaddr::Ipv6Address(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0);
static const auto kTunnelSrcIpv6Ternary =
    netaddr::Ipv6Address(0x1122, 0x1122, 0x3344, 0x3344, 0x5566, 0x5566, 0, 0);
static const auto kTunnelDstIpv6Ternary = netaddr::Ipv6Address(
    0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);
constexpr absl::string_view kDefaultMulticastVrf = "vrf-mcast";
constexpr netaddr::MacAddress kOriginalSrcMacAddress(0x00, 0x22, 0x33, 0x44,
                                                     0x55, 0x66);

struct ReplicaPair {
  std::string port_id;
  int instance;
};

enum class IpmcGroupAssignmentMechanism { kAclRedirect, kIpMulticastTable };

packetlib::Packet ParsePacketAndPadToMinimumSize(
    const ProtoFixtureRepository& repo, absl::string_view packet_pb) {
  packetlib::Packet packet = repo.ParseTextOrDie<packetlib::Packet>(packet_pb);
  CHECK_OK(packetlib::PadPacketToMinimumSize(packet));
  return packet;
}

// Multicast IPv4 addresses of the form 226.10.#.#. The last two bytes
// are computed based on the multicast group ID.
absl::StatusOr<netaddr::Ipv4Address> GetIpv4AddressForReplica(
    int multicast_group_id) {
  if (multicast_group_id >= 0 && multicast_group_id < 511) {
    return netaddr::Ipv4Address(226, 10, ((multicast_group_id + 1) >> 8) & 0xff,
                                (multicast_group_id + 1) & 0xff);
  } else {
    return absl::FailedPreconditionError(
        absl::StrCat("Multicast group ID '", multicast_group_id,
                     "' is larger than test's maximum value of 510"));
  }
}

absl::StatusOr<netaddr::MacAddress> GetSrcMacForReplica(int multicast_group_id,
                                                        int replicas_per_group,
                                                        int replicas_number) {
  if (multicast_group_id * replicas_per_group + replicas_number < 0xff) {
    return netaddr::MacAddress(
        0x00, 0x20, 0x30, 0x40, 0x50,
        multicast_group_id * replicas_per_group + replicas_number);
  } else {
    return absl::FailedPreconditionError(
        absl::StrCat("Combination of multicast group ID '", multicast_group_id,
                     "', replicas per group '", replicas_per_group,
                     "', and replicas_number '", replicas_number,
                     "' is larger than test's maximum value of ", 0xfe));
  }
}

// Build a test vector that injects one IPv4 and one IPv6 test packet.  The
// input packets are formatted such that they are expected to match the
// multicast group specified by the `input_group_index`.  The multicast group
// is expected to be active, and the output packets are expected to be formatted
// according to the multicast group specified by the `output_group_index`.
absl::StatusOr<std::vector<dvaas::PacketTestVector>> BuildInputOutputVectors(
    const std::vector<std::string>& port_ids, int input_group_index,
    int output_group_index, int replicas_per_group,
    const netaddr::MacAddress& dst_mac_addr,
    int output_replica_start_index = 0) {
  // Test packets injected and expected results.
  std::vector<dvaas::PacketTestVector> expectations;

  // All packets will be injected on the same port.
  const std::string& in_port = port_ids[0];

  // We will inject a packet to touch  multicast group using IPv4
  ASSIGN_OR_RETURN(const auto ipv4_mcast_address,
                   GetIpv4AddressForReplica(input_group_index));
  ProtoFixtureRepository repo;
  repo.RegisterValue("@ingress_port", in_port)
      .RegisterValue("@src_mac", kOriginalSrcMacAddress.ToString())
      .RegisterValue("@dst_mac", dst_mac_addr.ToString())
      .RegisterValue("@ttl", "0x40")
      .RegisterValue("@hop_limit", "0x50")
      .RegisterValue("@decremented_hop_limit", "0x4f")
      .RegisterValue("@decremented_ttl", "0x3f")
      .RegisterValue("@ipv4_mcast_dst", ipv4_mcast_address.ToString())
      .RegisterValue("@tunnel_dst_ip6", kTunnelDstIpv6.ToString())
      .RegisterValue("@tunnel_src_ip6", kTunnelSrcIpv6.ToString())
      .RegisterValue("@payload_ipv4",
                     dvaas::MakeTestPacketTagFromUniqueId(
                         1, "Testing Multicast IPv4-in-Ipv6 packets"));
  // Build headers.
  repo.RegisterSnippetOrDie<packetlib::Header>("@ethernet_ipv4", R"pb(
        ethernet_header {
          ethernet_destination: @dst_mac
          ethernet_source: @src_mac
          # ethertype: "0x0800"  # IPv4
          ethertype: "0x86dd"
        }
      )pb")
      .RegisterSnippetOrDie<packetlib::Header>("@ipv6", R"pb(
        ipv6_header {
          version: "0x6"
          dscp: "0x1b"
          ecn: "0x1"
          flow_label: "0x12345"
          # payload_length: filled in automatically.
          next_header: "0x04"  # next is ipv4
          hop_limit: 0x42
          ipv6_source: @tunnel_src_ip6
          ipv6_destination: @tunnel_dst_ip6
        }
      )pb")
      .RegisterSnippetOrDie<packetlib::Header>("@ipv4", R"pb(
        ipv4_header {
          version: "0x4"
          ihl: "0x5"
          dscp: "0x1b"
          ecn: "0x0"
          # total_length: filled in automatically.
          identification: "0x0000"
          flags: "0x0"
          fragment_offset: "0x0000"
          ttl: @ttl
          protocol: "0x11"
          # checksum: filled in automatically
          ipv4_source: "128.252.7.36"
          ipv4_destination: @ipv4_mcast_dst
        }
      )pb")
      .RegisterSnippetOrDie<packetlib::Header>("@udp", R"pb(
        udp_header {
          source_port: "0x0014"
          destination_port: "0x000a"
          # length: filled in automatically
          # checksum: filled in automatically
        }
      )pb")
      .RegisterMessage("@input_packet_ipv4",
                       ParsePacketAndPadToMinimumSize(repo,
                                                      R"pb(
                                                        headers: @ethernet_ipv4
                                                        headers: @ipv6
                                                        headers: @ipv4
                                                        headers: @udp
                                                        payload: @payload_ipv4
                                                      )pb"));
  // Build up acceptable_outputs string, to account for each replica.
  dvaas::SwitchOutput expected_ipv4_output;
  for (int r = output_replica_start_index; r < replicas_per_group; ++r) {
    ASSIGN_OR_RETURN(
        const auto src_mac,
        GetSrcMacForReplica(output_group_index, replicas_per_group, r));
    // IPv4
    *expected_ipv4_output.add_packets() =
        repo.RegisterValue("@egress_port", port_ids[r + 1])
            .RegisterValue("@src_mac", src_mac.ToString())
            .RegisterMessage(
                "@output_packet", ParsePacketAndPadToMinimumSize(repo, R"pb(
                  headers: @ethernet_ipv4 {
                    ethernet_header {
                      # inner packet is multicast so expecting multicast dst-mac
                      # changing the ipv4 multicast addresses, changes this
                      # value
                      ethernet_destination: "01:00:5e:0a:00:01"
                      ethernet_source: @src_mac
                      ethertype: "0x0800"
                    }
                  }
                  headers: @ipv4 { ipv4_header { ttl: @decremented_ttl } }
                  headers: @udp
                  payload: @payload_ipv4
                )pb"))
            .ParseTextOrDie<dvaas::Packet>(R"pb(
              port: @egress_port
              parsed: @output_packet
            )pb");
  }  // for replica
  LOG(INFO) << "Packets will be sent on port " << in_port;

  expectations.emplace_back() =
      repo.RegisterMessage("@expected_ipv4_output", expected_ipv4_output)
          .ParseTextOrDie<dvaas::PacketTestVector>(R"pb(
            input {
              type: DATAPLANE
              packet { port: @ingress_port parsed: @input_packet_ipv4 }
            }
            acceptable_outputs: @expected_ipv4_output
          )pb");

  return expectations;
}

// Build test packets that match the multicast table entries
absl::StatusOr<std::vector<dvaas::PacketTestVector>> BuildTestVectors(
    const std::vector<std::string>& port_ids, int number_multicast_groups,
    int replicas_per_group, const netaddr::MacAddress& dst_mac_addr) {
  // Test packets injected and expected results.
  std::vector<dvaas::PacketTestVector> expectations;
  for (int m = 0; m < number_multicast_groups; ++m) {
    ASSIGN_OR_RETURN(auto group_expectations,
                     BuildInputOutputVectors(port_ids,
                                             /*input_group_index=*/m,
                                             /*output_group_index=*/m,
                                             replicas_per_group, dst_mac_addr));
    expectations.insert(expectations.end(), group_expectations.begin(),
                        group_expectations.end());
  }  // for multicast group
  return expectations;
}

// Add table entries for multicast_router_interface_table.
absl::StatusOr<std::vector<p4::v1::Entity>> CreateRifTableEntities(
    const pdpi::IrP4Info& ir_p4info, const std::string& port_id,
    const int instance, const netaddr::MacAddress& src_mac) {
  ASSIGN_OR_RETURN(std::vector<p4::v1::Entity> entities,
                   sai::EntryBuilder()
                       .AddMulticastRouterInterfaceEntry(
                           {.multicast_replica_port = port_id,
                            .multicast_replica_instance = instance,
                            .src_mac = src_mac})
                       .LogPdEntries()
                       .GetDedupedPiEntities(ir_p4info));
  return entities;
}

// Add packet replication engine entries.
absl::StatusOr<std::vector<p4::v1::Entity>> CreateMulticastGroupEntities(
    const pdpi::IrP4Info& ir_p4info, int multicast_group_id,
    const std::vector<ReplicaPair>& replicas) {
  std::vector<sai::Replica> sai_replicas;
  for (const auto& [port, instance] : replicas) {
    sai_replicas.push_back(
        sai::Replica{.egress_port = port, .instance = instance});
  }
  ASSIGN_OR_RETURN(std::vector<p4::v1::Entity> entities,
                   sai::EntryBuilder()
                       .AddMulticastGroupEntry(multicast_group_id, sai_replicas)
                       .LogPdEntries()
                       .GetDedupedPiEntities(ir_p4info));
  return entities;
}

absl::StatusOr<std::vector<std::string>> GetNUpInterfaceIDs(
    thinkit::Switch& device, int num_interfaces) {
  // The test fixture pushes a new config during setup so we give the switch a
  // few minutes to converge before failing to report no valid ports.
  absl::Duration time_limit = absl::Minutes(3);
  absl::Time stop_time = absl::Now() + time_limit;
  std::vector<std::string> port_names;
  while (port_names.size() < num_interfaces) {
    if (absl::Now() > stop_time) {
      return absl::FailedPreconditionError(
          absl::StrCat("Could not find ", num_interfaces, " interfaces in ",
                       absl::FormatDuration(time_limit), "."));
    }
    ASSIGN_OR_RETURN(auto gnmi_stub, device.CreateGnmiStub());
    ASSIGN_OR_RETURN(port_names,
                     pins_test::GetUpInterfacesOverGnmi(
                         *gnmi_stub, pins_test::InterfaceType::kSingleton));
  }
  ASSIGN_OR_RETURN(auto gnmi_stub, device.CreateGnmiStub());
  ASSIGN_OR_RETURN(auto port_id_by_name,
                   GetAllInterfaceNameToPortId(*gnmi_stub));
  // Return encoded port ID as result.
  LOG(INFO) << "Port name to id mapping:";
  std::vector<std::string> result;
  for (const auto& port_name : port_names) {
    if (auto it = port_id_by_name.find(port_name);
        it != port_id_by_name.end()) {
      result.push_back(it->second);
      LOG(INFO) << "  " << port_name << " : " << it->second;
    }
  }
  return result;
}

// Add table entries for ipv4_multicast_table.
absl::StatusOr<std::vector<p4::v1::Entity>> CreateIpv4MulticastTableEntities(
    const pdpi::IrP4Info& ir_p4info, const std::string& vrf_id,
    const netaddr::Ipv4Address& ip_address, int multicast_group_id) {
  ASSIGN_OR_RETURN(
      std::vector<p4::v1::Entity> entities,
      sai::EntryBuilder()
          .AddMulticastRoute(vrf_id, ip_address, multicast_group_id)
          .LogPdEntries()
          .GetDedupedPiEntities(ir_p4info));
  return entities;
}
// Helper routine to install tunnel term table
absl::StatusOr<std::vector<p4::v1::Entity>> InstallTunnelTermTable(
    pdpi::P4RuntimeSession& switch_session, pdpi::IrP4Info& ir_p4info,
    const pins_test::TunnelMatchType tunnel_type) {
  std::vector<p4::v1::Entity> pi_entities;
  LOG(INFO) << "Installing Tunnel term table";

  sai::Ipv6TunnelTerminationParams params;
  switch (tunnel_type) {
    case pins_test::TunnelMatchType::kTernaryMatchSrcIp: {
      params.src_ipv6 = sai::P4RuntimeTernary<netaddr::Ipv6Address>{
          .value = kTunnelSrcIpv6Ternary,
          .mask = kTernaryMask,
      };
      params.dst_ipv6 = sai::P4RuntimeTernary<netaddr::Ipv6Address>{
          .value = kTunnelDstIpv6,
          .mask = kExactMask,
      };
      break;
    }
    case pins_test::TunnelMatchType::kTernaryMatchDstIp: {
      params.src_ipv6 = sai::P4RuntimeTernary<netaddr::Ipv6Address>{
          .value = kTunnelSrcIpv6,
          .mask = kExactMask,
      };
      params.dst_ipv6 = sai::P4RuntimeTernary<netaddr::Ipv6Address>{
          .value = kTunnelDstIpv6Ternary,
          .mask = kTernaryMask,
      };
      break;
    }
    case pins_test::TunnelMatchType::kExactMatch: {
      params.src_ipv6 = sai::P4RuntimeTernary<netaddr::Ipv6Address>{
          .value = kTunnelSrcIpv6,
          .mask = kExactMask,
      };
      params.dst_ipv6 = sai::P4RuntimeTernary<netaddr::Ipv6Address>{
          .value = kTunnelDstIpv6,
          .mask = kExactMask,
      };
      break;
    }
  }

  sai::EntryBuilder entry_builder =
      sai::EntryBuilder().AddIpv6TunnelTerminationEntry(params);

  ASSIGN_OR_RETURN(
      pi_entities,
      entry_builder.LogPdEntries().GetDedupedPiEntities(ir_p4info));
  RETURN_IF_ERROR(pdpi::InstallPiEntities(switch_session, pi_entities));
  return pi_entities;
}

// Setup multicast and other related tables for forwarding multicast packets.
absl::Status SetupDefaultMulticastProgramming(
    pdpi::P4RuntimeSession& session, const pdpi::IrP4Info& ir_p4info,
    const p4::v1::Update_Type& update_type, int number_multicast_groups,
    int replicas_per_group, const std::vector<std::string>& port_ids,
    std::vector<p4::v1::Entity>& entities_created) {
  if (port_ids.size() < replicas_per_group) {
    return gutil::InternalErrorBuilder()
           << "Not enough port IDs provided to setup multicast programming:"
           << " expected: " << replicas_per_group
           << " received: " << port_ids.size();
  }

  // Setup admission for all L3 packets, a default VRF,
  // assign all IP packets to the default VRF
  ASSIGN_OR_RETURN(std::vector<p4::v1::Entity> acl_entities,
                   sai::EntryBuilder()
                       .AddEntryAdmittingAllPacketsToL3()
                       .AddVrfEntry(kDefaultMulticastVrf)
                       .AddPreIngressAclEntryAssigningVrfForGivenIpType(
                           kDefaultMulticastVrf, sai::IpVersion::kIpv6)
                       .LogPdEntries()
                       .GetDedupedPiEntities(ir_p4info));

  RETURN_IF_ERROR(pdpi::InstallPiEntities(&session, ir_p4info, acl_entities));
  entities_created.insert(entities_created.end(), acl_entities.begin(),
                          acl_entities.end());
  // Setup multicast RIF table.
  std::vector<p4::v1::Entity> rif_entities;
  for (int m = 0; m < number_multicast_groups; ++m) {
    for (int r = 0; r < replicas_per_group; ++r) {
      const std::string& port_id = port_ids[r + 1];
      // Unique Ether src mac base address.
      ASSIGN_OR_RETURN(netaddr::MacAddress src_mac,
                       GetSrcMacForReplica(m, replicas_per_group, r));
      int instance = replicas_per_group * m + r;
      ASSIGN_OR_RETURN(auto rifs, CreateRifTableEntities(ir_p4info, port_id,
                                                         instance, src_mac));
      rif_entities.insert(rif_entities.end(), rifs.begin(), rifs.end());
    }
  }
  RETURN_IF_ERROR(pdpi::InstallPiEntities(&session, ir_p4info, rif_entities));
  entities_created.insert(entities_created.end(), rif_entities.begin(),
                          rif_entities.end());

  // Setup multicast groups and group members.
  std::vector<p4::v1::Entity> mc_entities;
  for (int m = 0; m < number_multicast_groups; ++m) {
    std::vector<ReplicaPair> replicas;
    for (int r = 0; r < replicas_per_group; ++r) {
      const std::string& port_id = port_ids[r + 1];
      int instance = replicas_per_group * m + r;
      replicas.push_back({port_id, instance});
    }
    // Note: multicast group ID 0 is not valid.
    int multicast_group_id = m + 1;
    ASSIGN_OR_RETURN(auto mcs, CreateMulticastGroupEntities(
                                   ir_p4info, multicast_group_id, replicas));
    mc_entities.insert(mc_entities.end(), mcs.begin(), mcs.end());
  }
  RETURN_IF_ERROR(pdpi::InstallPiEntities(&session, ir_p4info, mc_entities));
  entities_created.insert(entities_created.end(), mc_entities.begin(),
                          mc_entities.end());

  // Setup multicast group assignment (IPMC entries).
  std::vector<p4::v1::Entity> ipmc_entities;
  for (int m = 0; m < number_multicast_groups; ++m) {
    ASSIGN_OR_RETURN(const netaddr::Ipv4Address ipv4_address,
                     GetIpv4AddressForReplica(m));
    uint8_t multicast_group_id = m + 1;
    std::string vrf_id = std::string(kDefaultMulticastVrf);
    ASSIGN_OR_RETURN(auto ipmcs_v4,
                     CreateIpv4MulticastTableEntities(
                         ir_p4info, vrf_id, ipv4_address, multicast_group_id));
    ipmc_entities.insert(ipmc_entities.end(), ipmcs_v4.begin(), ipmcs_v4.end());
  }
  RETURN_IF_ERROR(pdpi::InstallPiEntities(&session, ir_p4info, ipmc_entities));
  entities_created.insert(entities_created.end(), ipmc_entities.begin(),
                          ipmc_entities.end());
  return absl::OkStatus();
}

TEST_P(TunnelDecapMulticastTestFixture, BasicTunnelTermDecapMulticastv4Inv6) {
  dvaas::DataplaneValidationParams dvaas_params = GetParam().dvaas_params;
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  const int kNumberMulticastGroupsInTest = 1;
  const int kPortsToUseInTest = 4;

  // Set testcases
  if (GetParam().tunnel_type == pins_test::TunnelMatchType::kExactMatch) {
    testbed.Environment().SetTestCaseID("a333da9b-a4cf-4473-bcbb-b1a17145ee79");
  } else if (GetParam().tunnel_type ==
             pins_test::TunnelMatchType::kTernaryMatchSrcIp) {
    testbed.Environment().SetTestCaseID("f8b3a566-d2dd-45d4-a6a9-2417563c40ce");
  } else {
    testbed.Environment().SetTestCaseID("e2fac3f4-2ad2-4cc1-bc37-d2256596da9b");
  }

  // Initialize the connection, clear all entities, and (for the SUT) push
  // P4Info.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
                       pdpi::P4RuntimeSession::Create(testbed.Sut()));

  ASSERT_OK(pdpi::ClearEntities(*sut_p4rt_session));

  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info sut_ir_p4info,
                       pdpi::GetIrP4Info(*sut_p4rt_session));

  // Collect port IDs.
  // Get SUT and control ports to test on.
  ASSERT_OK_AND_ASSIGN(
      const std::vector<std::string> sut_ports_ids,
      GetNUpInterfaceIDs(testbed.Sut(), kPortsToUseInTest + 1));

  LOG(INFO) << "Adding multicast programming.";
  std::vector<p4::v1::Entity> entities_created;

  // Install L3 route entry on SUT
  ASSERT_OK(SetupDefaultMulticastProgramming(
      *sut_p4rt_session.get(), sut_ir_p4info, p4::v1::Update::INSERT,
      kNumberMulticastGroupsInTest,
      /*replicas_per_group=*/kPortsToUseInTest, sut_ports_ids,
      entities_created));

  // Install tunnel term table entry on SUT
  ASSERT_OK_AND_ASSIGN(
      const auto tunnel_entities,
      InstallTunnelTermTable(*sut_p4rt_session.get(), sut_ir_p4info,
                             GetParam().tunnel_type));

  LOG(INFO) << "Send packets IP-in-IP multicast packet";
  // Build test packets.
  ASSERT_OK_AND_ASSIGN(
      auto vectors,
      BuildTestVectors(sut_ports_ids, kNumberMulticastGroupsInTest,
                       /*replicas_per_group=*/kPortsToUseInTest,
                       kDstUnicastMacAddress));

  // Send test packets.
  LOG(INFO) << "Sending traffic to verify added multicast programming.";
  dvaas_params.packet_test_vector_override = vectors;

  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result,
      GetParam().dvaas->ValidateDataplane(testbed, dvaas_params));
  // Validate traffic.
  validation_result.LogStatistics();
  EXPECT_OK(validation_result.HasSuccessRateOfAtLeast(1.0));

  // Build the packet with multicast ipv6 dst mac-address
  // with this decap should not happen and packet should get dropped

  ASSERT_OK_AND_ASSIGN(
      auto multicast_vectors,
      BuildTestVectors(sut_ports_ids, kNumberMulticastGroupsInTest,
                       // replicas_per_group=
                       kPortsToUseInTest, kDstMulticastIpv6MacAddress));

  for (dvaas::PacketTestVector& vector : multicast_vectors) {
    for (dvaas::SwitchOutput& output : *vector.mutable_acceptable_outputs()) {
      output.clear_packet_ins();
      output.clear_packets();
    }
  }

  dvaas_params.packet_test_vector_override = multicast_vectors;

  ASSERT_OK_AND_ASSIGN(
      dvaas::ValidationResult validation_result1,
      GetParam().dvaas->ValidateDataplane(testbed, dvaas_params));

  // Log statistics and check that things succeeded.
  validation_result1.LogStatistics();
  EXPECT_OK(validation_result1.HasSuccessRateOfAtLeast(1.0));
}

}  // namespace
}  // namespace pins_test
