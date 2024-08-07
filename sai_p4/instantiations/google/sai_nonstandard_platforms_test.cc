#include "sai_p4/instantiations/google/sai_nonstandard_platforms.h"

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"
#include "p4/config/v1/p4info.pb.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "thinkit/bazel_test_environment.h"

namespace sai {
namespace {

constexpr NonstandardPlatform kAllPlatforms[] = {
    NonstandardPlatform::kBmv2,
    NonstandardPlatform::kP4Symbolic,
};

class NonstandardPlatformsTest : public testing::Test,
                                 public thinkit::BazelTestEnvironment {
 public:
  NonstandardPlatformsTest()
      : thinkit::BazelTestEnvironment(/*mask_known_failures=*/false) {}
};

// GetNonstandardP4Config contains a CHECK; ensure it doesn't fail.
TEST_F(NonstandardPlatformsTest, GetNonstandardP4ConfigDoesNotCheckCrash) {
  for (auto instantiation : AllInstantiations()) {
    for (auto platform : kAllPlatforms) {
      std::string config = GetNonstandardP4Config(instantiation, platform);
      ASSERT_OK(StoreTestArtifact(
          absl::StrFormat("%s_%s_config.json",
                          InstantiationToString(instantiation),
                          PlatformName(platform)),
          config));
    }
  }
}

// GetNonstandardP4Info contains a CHECK; ensure it doesn't fail.
TEST_F(NonstandardPlatformsTest, GetNonstandardP4InfoDoesNotCheckCrash) {
  for (auto instantiation : AllInstantiations()) {
    for (auto platform : kAllPlatforms) {
      auto info = GetNonstandardP4Info(instantiation, platform);
      ASSERT_OK(StoreTestArtifact(
          absl::StrFormat("%s_%s_.p4info.textproto",
                          InstantiationToString(instantiation),
                          PlatformName(platform)),
          info));
    }
  }
}

// GetNonstandardForwardingPipelineConfig contains several CHECKs; ensure it
// doesn't fail.
TEST_F(NonstandardPlatformsTest,
       GetNonstandardForwardingPipelineConfigDoesNotCheckCrash) {
  for (auto instantiation : AllInstantiations()) {
    for (auto platform : kAllPlatforms) {
      auto config =
          GetNonstandardForwardingPipelineConfig(instantiation, platform);
      ASSERT_OK(StoreTestArtifact(
          absl::StrFormat("%s_%s_.config.textproto",
                          InstantiationToString(instantiation),
                          PlatformName(platform)),
          config));
    }
  }
}

TEST(NonstandardPlatformsFlagTest, ParsingValidNameSucceeds) {
  NonstandardPlatform platform;
  std::string error;
  ASSERT_TRUE(AbslParseFlag("bmv2", &platform, &error));
  ASSERT_THAT(platform, testing::Eq(NonstandardPlatform::kBmv2));
}

TEST(NonstandardPlatformsFlagTest, ParsingInvalidNameFails) {
  NonstandardPlatform platform;
  std::string error;
  ASSERT_FALSE(AbslParseFlag("non-existing-platform-name", &platform, &error));
}

TEST(NonstandardPlatformsFlagTest, UnparsingWorks) {
  ASSERT_THAT(AbslUnparseFlag(NonstandardPlatform::kBmv2), testing::Eq("bmv2"));
}

}  // namespace
}  // namespace sai
