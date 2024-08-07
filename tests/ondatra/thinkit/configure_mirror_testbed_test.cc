#include "tests/forwarding/configure_mirror_testbed_test.h"

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "gtest/gtest.h"
// TODO: b/183966280 - Update to use Abseil log in upstream.
#include "absl/strings/string_view.h"
#include "gutil/testing.h"
#include "ondatra/thinkit/ondatra_params.h"
#include "p4/config/v1/p4info.pb.h"
#include "thinkit/mirror_testbed_fixture.h"

ABSL_FLAG(
    std::string, p4info_file, "",
    "Path to the file containing the textproto of the P4Info to be pushed");

namespace gpins {
namespace {

ConfigureMirrorTestbedTestParams GetTestInstanceOrDie() {
  CHECK(!absl::GetFlag(FLAGS_p4info_file).empty())
      << "--p4info_file is required.";

  auto p4info = gutil::ParseProtoFileOrDie<p4::config::v1::P4Info>(
      absl::GetFlag(FLAGS_p4info_file));

  return ConfigureMirrorTestbedTestParams{
      .mirror_testbed = std::shared_ptr<thinkit::MirrorTestbedInterface>(
          gpins::GetOndatraMirrorTestbedFixtureParams()->mirror_testbed),
      .sut_p4info = p4info,
      .control_switch_p4info = p4info,
  };
}

INSTANTIATE_TEST_SUITE_P(GpinsOndatraConfigureMirrorTestbedTest,
                         ConfigureMirrorTestbedTestFixture,
                         testing::Values(GetTestInstanceOrDie()));

}  // namespace
}  // namespace gpins
