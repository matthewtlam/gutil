#include "tests/forwarding/arbitration_test.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "gtest/gtest.h"
#include "gutil/testing.h"
#include "ondatra/thinkit/ondatra_params.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/mirror_testbed_fixture.h"
#include "util/gtl/value_or_die.h"

ABSL_FLAG(
    std::string, p4info_file, "",
    "Path to the file containing the textproto of the P4Info to be pushed");

namespace gpins {
namespace {

// Returns the P4Info of the SUT.
// Creates a temporary mirror testbed instance to get the P4Info from the SUT.
p4::config::v1::P4Info GetSUTP4InfoOrDie() {
  thinkit::MirrorTestbedFixtureParams mirror_testbed_params =
      *gpins::GetOndatraMirrorTestbedFixtureParams();
  auto mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
      mirror_testbed_params.mirror_testbed);
  mirror_testbed->SetUp();
  auto session = gtl::ValueOrDie(pdpi::P4RuntimeSession::Create(
      mirror_testbed->GetMirrorTestbed().Sut(), {}));
  p4::v1::GetForwardingPipelineConfigResponse response =
      gtl::ValueOrDie(pdpi::GetForwardingPipelineConfig(session.get()));
  mirror_testbed->TearDown();
  return response.config().p4info();
}

// If the p4info_file flag is set, returns the P4Info from the file.
// Otherwise returns the P4Info from the SUT.
p4::config::v1::P4Info GetP4InfoOrDie() {
  std::string p4info_file = absl::GetFlag(FLAGS_p4info_file);
  return p4info_file.empty()
             ? GetSUTP4InfoOrDie()
             : gutil::ParseProtoFileOrDie<p4::config::v1::P4Info>(p4info_file);
}

INSTANTIATE_TEST_SUITE_P(
    GpinsArbitrationTest, ArbitrationTestFixture, testing::Values([]() {
      thinkit::MirrorTestbedFixtureParams mirror_testbed_params =
          *gpins::GetOndatraMirrorTestbedFixtureParams();
      return ArbitrationTestParams{
          .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
              mirror_testbed_params.mirror_testbed),
          .gnmi_config = std::move(mirror_testbed_params.gnmi_config),
          .p4info = GetP4InfoOrDie()};
    }()));

}  // namespace
}  // namespace gpins
