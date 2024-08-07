#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "devtools/build/runtime/get_runfiles_dir.h"
#include "file/base/helpers.h"
#include "file/base/options.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/proto_matchers.h"
#include "gutil/status.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "p4/config/v1/p4info.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/packetlib/packetlib.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "p4_symbolic/packet_synthesizer/coverage_goal.pb.h"
#include "p4_symbolic/packet_synthesizer/criteria_generator.h"
#include "p4_symbolic/packet_synthesizer/packet_synthesizer.h"
#include "p4_symbolic/packet_synthesizer/packet_synthesizer.pb.h"
#include "p4_symbolic/symbolic/symbolic.h"
#include "platforms/networking/p4/p4_infra/bmv2/bmv2.h"
#include "tests/forwarding/packet_at_port.h"

namespace pins {
namespace {

using ::gutil::EqualsProto;
using ::orion::p4::test::Bmv2;
using ::testing::Gt;
using ::testing::SizeIs;

absl::StatusOr<p4::v1::ForwardingPipelineConfig> GetBmv2ForwardingConfig() {
  p4::v1::ForwardingPipelineConfig config;
  ASSIGN_OR_RETURN(*config.mutable_p4info(),
                   file::GetTextProto<p4::config::v1::P4Info>(
                       devtools_build::GetDataDependencyFilepath(
                           "google3/third_party/pins_infra/sai_p4/"
                           "instantiations/google/tests/"
                           "testdata/forward_all.p4info.pb.txt"),
                       file::Defaults()));

  ASSIGN_OR_RETURN(
      *config.mutable_p4_device_config(),
      file::GetContents(devtools_build::GetDataDependencyFilepath(
                            "google3/third_party/pins_infra/sai_p4/"
                            "instantiations/google/tests/"
                            "testdata/forward_all.bmv2.json"),
                        file::Defaults()));
  return config;
}

absl::StatusOr<packetlib::Packet> ProcessIntoPacketlibPacket(
    absl::string_view packet_string) {
  // Parse and prepare the packet string.
  packetlib::Packet packet = packetlib::ParsePacket(packet_string);
  RETURN_IF_ERROR(packetlib::PadPacketToMinimumSize(packet).status());
  // Updates all computed fields on the assumption that those are more
  // interesting than whatever P4-Symbolic spits out.
  RETURN_IF_ERROR(packetlib::UpdateAllComputedFields(packet).status());
  // Serialize then reparse to get rid of invalidity reasons due to a previous
  // lack of padding or computed fields.
  ASSIGN_OR_RETURN(std::string serialized_packet,
                   packetlib::SerializePacket(packet));
  return packetlib::ParsePacket(serialized_packet);
}

absl::StatusOr<std::vector<std::string>> GeneratePackets() {
  using p4_symbolic::packet_synthesizer::CoverageGoals;
  using p4_symbolic::packet_synthesizer::PacketSynthesisCriteria;
  using p4_symbolic::packet_synthesizer::PacketSynthesisParams;
  using p4_symbolic::packet_synthesizer::PacketSynthesisResult;
  using p4_symbolic::packet_synthesizer::PacketSynthesizer;

  ASSIGN_OR_RETURN(p4::v1::ForwardingPipelineConfig p4_symbolic_config,
                   GetBmv2ForwardingConfig());

  // Generate Packet synthesis criteria to cover all protocols.
  ASSIGN_OR_RETURN(
      std::unique_ptr<p4_symbolic::symbolic::SolverState> solver_state,
      p4_symbolic::symbolic::EvaluateP4Program(p4_symbolic_config,
                                               /*entries=*/{}));
  ASSIGN_OR_RETURN(
      CoverageGoals protocol_coverage_goal,
      gutil::ParseTextProto<CoverageGoals>(R"pb(
        coverage_goals {
          cartesian_product_coverage {
            packet_fate_coverage { fates: [ NOT_DROP ] }
            header_coverage {
              headers { patterns: [ "*" ] }
              include_wildcard_header: true
              header_exclusions {
                patterns: [
                  # PacketIO is currently handled differently in dataplane
                  # tests.
                  "packet_in_header",
                  "packet_out_header"
                ]
                patterns: [
                  # The following are not satisfiable anyway (because the
                  # headers will never be valid in ingress).
                  "mirror_encap_ethernet",
                  "mirror_encap_ipfix",
                  "mirror_encap_ipv6",
                  "mirror_encap_psamp_extended",
                  "mirror_encap_udp",
                  "mirror_encap_vlan",
                  "tunnel_encap_gre",
                  "tunnel_encap_ipv6"
                ]
              }
            }
          }
        }
      )pb"));

  ASSIGN_OR_RETURN(
      std::vector<PacketSynthesisCriteria> synthesis_criteria_list,
      p4_symbolic::packet_synthesizer::GenerateSynthesisCriteriaFor(
          protocol_coverage_goal, *solver_state));

  // Get a packet synthesizer object.
  PacketSynthesisParams params;
  *params.mutable_pipeline_config() = std::move(p4_symbolic_config);
  ASSIGN_OR_RETURN(auto synthesizer, PacketSynthesizer::Create(params));
  std::vector<std::string> generated_packets;
  for (const auto& criteria : synthesis_criteria_list) {
    // Synthesize Packet.
    ASSIGN_OR_RETURN(const PacketSynthesisResult result,
                     synthesizer->SynthesizePacket(criteria));

    // Ensure that a packet was successfully synthesized.
    if (!result.has_synthesized_packet()) {
      return gutil::InternalErrorBuilder()
             << "Failed to synthesize a packet for criterion: "
             << criteria.DebugString();
    }

    generated_packets.push_back(result.synthesized_packet().packet());
  }
  return generated_packets;
}

// Parser/deparser roundtripping is relied upon by BMv2 generally as well as our
// various test infrastructure. It should hold for all packets.  See b/342187956
// for more details.
TEST(SimpleSaiTest, ParserAndDeparserRoundtrip) {
  constexpr int kIngressPort = 1;

  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, Bmv2::Create(/*args=*/{}));
  ASSERT_OK_AND_ASSIGN(p4::v1::ForwardingPipelineConfig config,
                       GetBmv2ForwardingConfig());
  ASSERT_OK(pdpi::SetMetadataAndSetForwardingPipelineConfig(
      &bmv2.P4RuntimeSession(),
      p4::v1::SetForwardingPipelineConfigRequest::VERIFY_AND_COMMIT, config));

  ASSERT_OK_AND_ASSIGN(std::vector<std::string> input_packets,
                       GeneratePackets());

  ASSERT_THAT(input_packets, SizeIs(Gt(0))) << "No packets generated.";
  for (const std::string& input_packet : input_packets) {
    auto packet_at_port = pins::PacketAtPort{
        .port = kIngressPort,
        .data = input_packet,
    };
    ASSERT_OK_AND_ASSIGN(std::vector<pins::PacketAtPort> output_packets,
                         bmv2.SendPacket(packet_at_port));

    ASSERT_NE(output_packets.size(), 0)
        << "No output packets from input packet:\n"
        << packet_at_port
        << "\nWas the packet dropped even though that should be impossible in "
           "this test?";
    EXPECT_EQ(output_packets.size(), 1)
        << "Expected a single packet, but got: "
        << absl::StrJoin(output_packets, "\n") << "\n\nFrom input packet:\n"
        << packet_at_port;
    EXPECT_EQ(output_packets[0], packet_at_port)
        << "The input packet and output packets are different, but we expect "
           "them to always be the same in this test. This indicates that the "
           "SAI P4 parser and deparser may not be in sync."
           "\n\nSee b/342187956 for more details about potential root cause.";
  }
}

// Extends previous test to also use Packetlib. Since some of our test
// infrastructure also depends on Packetlib (see e.g. b/342174749, though it
// really shouldn't, see b/342174808), we ensure that roundtripping works with
// Packetlib too. See b/342187956 for more details.
TEST(SimpleSaiTest, ParserAndDeparserRoundtripWithPacketlib) {
  constexpr int kIngressPort = 1;

  ASSERT_OK_AND_ASSIGN(Bmv2 bmv2, Bmv2::Create(/*args=*/{}));
  ASSERT_OK_AND_ASSIGN(p4::v1::ForwardingPipelineConfig config,
                       GetBmv2ForwardingConfig());
  ASSERT_OK(pdpi::SetMetadataAndSetForwardingPipelineConfig(
      &bmv2.P4RuntimeSession(),
      p4::v1::SetForwardingPipelineConfigRequest::VERIFY_AND_COMMIT, config));

  ASSERT_OK_AND_ASSIGN(std::vector<std::string> input_packet_strings,
                       GeneratePackets());
  ASSERT_THAT(input_packet_strings, SizeIs(Gt(0))) << "No packets generated.";

  // Process with Packetlib.
  std::vector<packetlib::Packet> input_packets;
  input_packets.reserve(input_packet_strings.size());
  for (const std::string& input_packet_string : input_packet_strings) {
    ASSERT_OK_AND_ASSIGN(input_packets.emplace_back(),
                         ProcessIntoPacketlibPacket(input_packet_string));
  }

  absl::flat_hash_set<packetlib::Header::HeaderCase> unique_header_types;
  for (const packetlib::Packet& input_packet : input_packets) {
    ASSERT_OK_AND_ASSIGN(
        (absl::flat_hash_map<int, packetlib::Packets> output_packets),
        bmv2.SendPacket(kIngressPort, input_packet));

    ASSERT_TRUE(output_packets.contains(kIngressPort))
        << "No output packets on egress port '" << kIngressPort
        << "' from input packet:\n"
        << input_packet.DebugString()
        << "\nWas the `forward_all.p4` program used correctly?";
    ASSERT_NE(output_packets[kIngressPort].packets_size(), 0)
        << "Expected a packet to egress on port '" << kIngressPort
        << "', but got none from input packet:\n"
        << input_packet.DebugString()
        << "\nWas the packet dropped even though that should be impossible in "
           "this test?";
    EXPECT_EQ(output_packets[kIngressPort].packets_size(), 1)
        << "Expected a single packet from ingress port '" << kIngressPort
        << "', but got: " << output_packets[kIngressPort].DebugString()
        << "\n\nFrom input packet:\n"
        << input_packet.DebugString();
    EXPECT_THAT(output_packets, SizeIs(1))
        << "Expected output packets on only a single port, but got packets on "
        << output_packets.size() << " ports.";
    EXPECT_THAT(output_packets[kIngressPort].packets(0),
                EqualsProto(input_packet))
        << "The input packet and output packets are different, but we expect "
           "them to always be the same in this test. There are two possible "
           "likely causes:"
           "\n  1. The SAI P4 parser and deparser may not be in sync."
           "\n  2. Packetlib parsing and deparsing may not correctly roundtrip "
           "for all packets."
           "\n\nSee b/342187956 for more details about potential root cause.";

    // Track all unique header types.
    for (const auto& header : input_packet.headers()) {
      unique_header_types.insert(header.header_case());
    }
  }

  LOG(INFO) << "Generated " << input_packets.size() << " packets covering "
            << unique_header_types.size() << " header types. Specifically: "
            << absl::StrJoin(
                   unique_header_types, ", ",
                   [](std::string* out,
                      const packetlib::Header::HeaderCase& header_type) {
                     absl::StrAppend(out,
                                     packetlib::HeaderCaseName(header_type));
                   });
}

}  // namespace
}  // namespace pins
