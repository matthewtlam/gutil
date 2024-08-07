#include "dvaas/dataplane_validation.h"

#include <iostream>
#include <string>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "dvaas/packet_trace.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/status_matchers.h"
#include "gutil/test_artifact_writer.h"
#include "gutil/testing.h"

namespace dvaas {
namespace {

using ::gutil::IsOk;

class DummyArtifactWriter : public gutil::TestArtifactWriter {
  absl::Status StoreTestArtifact(absl::string_view filename,
                                 absl::string_view contents) override {
    return absl::OkStatus();
  }

  absl::Status AppendToTestArtifact(absl::string_view filename,
                                    absl::string_view contents) override {
    return absl::OkStatus();
  }
};

TEST(AttachPacketTraceTest, IsOk) {
  PacketTestOutcome failed_packet_test;
  *failed_packet_test.mutable_test_result()->mutable_failure() =
      gutil::ParseProtoOrDie<PacketTestValidationResult::Failure>(R"pb(
        description: "Test failed"
      )pb");
  *failed_packet_test.mutable_test_run()
       ->mutable_test_vector() = gutil::ParseProtoOrDie<PacketTestVector>(R"pb(
    input {
      type: DATAPLANE
      packet {
        port: "29"
        parsed {
          headers {
            ethernet_header {
              ethernet_destination: "02:1a:0a:d0:62:8b"
              ethernet_source: "36:47:08:6f:88:a1"
              ethertype: "0x86dd"
            }
          }
          headers {
            ipv6_header {
              version: "0x6"
              dscp: "0x1a"
              ecn: "0x0"
              flow_label: "0x00000"
              payload_length: "0x0025"
              next_header: "0x11"
              hop_limit: "0x20"
              ipv6_source: "2000::"
              ipv6_destination: "2800:3f0:c200:800::2000"
            }
          }
          headers {
            udp_header {
              source_port: "0x0000"
              destination_port: "0x03ea"
              length: "0x0025"
              checksum: "0x3712"
            }
          }
          payload: "test packet #1: Dummy payload"
        }
        hex: "021a0ad0628b3647086f88a186dd668000000025112020000000000000000000000000000000280003f0c20008000000000000002000000003ea0025371274657374207061636b65742023313a2044756d6d79207061796c6f6164"
      }
    }
  )pb");
  std::string packet_hex =
      failed_packet_test.test_run().test_vector().input().packet().hex();
  auto packet_trace = gutil::ParseProtoOrDie<PacketTrace>(R"pb(
    bmv2_textual_log: "BMv2 textual log"
    events { packet_replication { number_of_packets_replicated: 1 } }
  )pb");
  absl::btree_map<std::string, std::vector<PacketTrace>> packet_traces;
  packet_traces[packet_hex] = {packet_trace};
  DummyArtifactWriter dvaas_test_artifact_writer;
  EXPECT_THAT(AttachPacketTrace(failed_packet_test, packet_traces,
                                dvaas_test_artifact_writer),
              IsOk());
}

TEST(GetPacketTraceSummaryTest, GetPacketTraceSummaryGoldenTest) {
  dvaas::PacketTrace packet_trace = gutil::ParseProtoOrDie<PacketTrace>(R"pb(
    bmv2_textual_log: "BMv2 textual log"
    events {
      table_apply {
        table_name: "ingress.vlan_untag.disable_vlan_checks_table"
        hit_or_miss_textual_log: "Table \'ingress.vlan_untag.disable_vlan_checks_table\': hit with handle 0\n[0.0] [cxt 0] Dumping entry 0\nMatch key:\n* dummy_match         : TERNARY   00 &&& 00\nPriority: 2147483646\nAction entry: ingress.vlan_untag.disable_vlan_checks - "
        hit {
          table_entry {
            table_name: "disable_vlan_checks_table"
            priority: 1
            action { name: "disable_vlan_checks" }
          }
        }
      }
    }
    events {
      table_apply {
        table_name: "egress.packet_rewrites.multicast_rewrites.multicast_router_interface_table"
        hit_or_miss_textual_log: "Table \'egress.packet_rewrites.multicast_rewrites.multicast_router_interface_table\': hit with handle 2\n[0.1] [cxt 0] Dumping entry 2\nMatch key:\n* multicast_replica_port    : EXACT     0037\n* multicast_replica_instance: EXACT     04d2\nAction entry: egress.packet_rewrites.multicast_rewrites.set_multicast_src_mac - 70707070707,"
        hit {}
      }
    }
    events {
      table_apply {
        table_name: "ingress.ingress_vlan_checks.vlan_membership_table"
        hit_or_miss_textual_log: "Table \'ingress.ingress_vlan_checks.vlan_membership_table\': miss"
        miss {}
      }
    }
    events {
      mark_to_drop {
        source_location: "./third_party/pins_infra/sai_p4/fixed/routing.p4(275)"
      }
    }
    events { packet_replication { number_of_packets_replicated: 3 } }
  )pb");

  ASSERT_OK_AND_ASSIGN(std::string packet_trace_summary,
                       GetPacketTraceSummary(packet_trace));

  // Print the input packet trace and output packet trace summary to diff
  // against the golden file "dataplane_validation_test.expected". Golden
  // testing is preferable to using expectations as we expect the packet trace
  // summary to change and updating the test manually is tedious.
  std::cout << "== INPUT: dvaas::PacketTrace proto ====================\n"
            << gutil::PrintTextProto(packet_trace)
            << "== OUTPUT: PacketTraceSummary ====================\n"
            << packet_trace_summary;
}

}  // namespace
}  // namespace dvaas
