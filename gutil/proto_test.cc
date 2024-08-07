#include "gutil/proto.h"

#include <cstdlib>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "gutil/proto_test.pb.h"
#include "gutil/status.h"
#include "gutil/status_matchers.h"

namespace gutil {
namespace {

using ::gutil::IsOkAndHolds;
using ::gutil::StatusIs;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::ResultOf;

// Get a writeable directory where bazel tests can save output files to.
// https://docs.bazel.build/versions/main/test-encyclopedia.html#initial-conditions
absl::StatusOr<std::string> GetTestTmpDir() {
  char* test_tmpdir = std::getenv("TEST_TMPDIR");
  if (test_tmpdir == nullptr) {
    return gutil::InternalErrorBuilder()
           << "Could not find environment variable ${TEST_TMPDIR}. Is this a "
              "bazel test run?";
  }
  return test_tmpdir;
}

TEST(IsEmptyProto, ReturnsTrueForEmptyProto) {
  EXPECT_TRUE(IsEmptyProto(TestMessage()));

  // Same things, but a bit more convoluted.
  TestMessage message;
  message.set_int_field(42);
  message.set_int_field(0);
  EXPECT_TRUE(IsEmptyProto(message))
      << "where message = " << message.DebugString();
}

TEST(IsEmptyProto, ReturnsFalseForNonEmptyProto) {
  EXPECT_THAT(ParseTextProto<TestMessage>("int_field: 42"),
              IsOkAndHolds(ResultOf(IsEmptyProto, Eq(false))));
}

TEST(ParseTextProto, EmptyTextProtoIsOk) {
  EXPECT_THAT(ParseTextProto<TestMessage>(""), IsOk());
}

TEST(ParseTextProto, InvalidTextProtoIsNotOk) {
  EXPECT_THAT(ParseTextProto<TestMessage>("bool_field: true"), Not(IsOk()));
}

TEST(ParseTextProto, NonEmptyValidTextProtoIsParsedCorrectly) {
  auto proto = ParseTextProto<TestMessage>(R"pb(
    int_field: 42
    string_field: "hello!"
  )pb");
  ASSERT_THAT(proto, IsOk());
  EXPECT_EQ(proto->int_field(), 42);
  EXPECT_EQ(proto->string_field(), "hello!");
}

TEST(ProtoDiff, ReturnsErrorForIncompatibleMessages) {
  ASSERT_OK_AND_ASSIGN(auto message1, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  ASSERT_OK_AND_ASSIGN(auto message2, ParseTextProto<AnotherTestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  EXPECT_THAT(ProtoDiff(message1, message2).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ProtoDiff, ReturnsEmptyDiffForEqualMessages) {
  ASSERT_OK_AND_ASSIGN(auto message1, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  EXPECT_THAT(ProtoDiff(message1, message1), IsOkAndHolds(IsEmpty()));
}

TEST(ProtoDiff, ReturnsNonEmptyDiffForUnequalMessages) {
  ASSERT_OK_AND_ASSIGN(auto message1, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  ASSERT_OK_AND_ASSIGN(auto message2, ParseTextProto<TestMessage>(R"pb(
                         int_field: 43
                         string_field: "bye"
                       )pb"));
  EXPECT_THAT(ProtoDiff(message1, message2), IsOkAndHolds(Not(IsEmpty())));
}

TEST(ProtoEqual, ReturnsErrorForIncompatibleMessages) {
  ASSERT_OK_AND_ASSIGN(auto message1, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  ASSERT_OK_AND_ASSIGN(auto message2, ParseTextProto<AnotherTestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  EXPECT_THAT(ProtoEqual(message1, message2), Eq(false));
}

TEST(ProtoEqual, ReturnsTrueForEqualMessages) {
  ASSERT_OK_AND_ASSIGN(auto message1, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  EXPECT_THAT(ProtoEqual(message1, message1), Eq(true));
}

TEST(ProtoEqual, ReturnsFalseForUnequalMessages) {
  ASSERT_OK_AND_ASSIGN(auto message1, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  ASSERT_OK_AND_ASSIGN(auto message2, ParseTextProto<TestMessage>(R"pb(
                         int_field: 43
                         string_field: "bye"
                       )pb"));
  EXPECT_THAT(ProtoEqual(message1, message2), Eq(false));
}

TEST(TextProtoHelpers, PrintTextProto) {
  TestMessage message;
  message.set_int_field(42);
  message.set_string_field("bye");
  EXPECT_THAT(PrintTextProto(message),
              "int_field: 42\nstring_field: \"bye\"\n");
}

TEST(TextProtoHelpers, PrintShortTextProto) {
  TestMessage message;
  message.set_int_field(42);
  message.set_string_field("bye");
  EXPECT_THAT(PrintShortTextProto(message),
              "int_field: 42 string_field: \"bye\"");
}

TEST(ParseJsonAsProto, ParsesTestMessage) {
  EXPECT_THAT(ParseJsonAsProto<TestMessage>(R"json({
                                              "int_field" : 42,
                                              "string_field" : "bye"
                                            })json"),
              IsOkAndHolds(EqualsProto(R"pb(
                int_field: 42 string_field: "bye"
              )pb")));
}

TEST(ParseJsonAsProto, CanIgnoreUnknownFields) {
  EXPECT_THAT(ParseJsonAsProto<TestMessage>(R"json({
                                              "int_field" : 42,
                                              "string_field" : "bye",
                                              "unknown_field": "please ignore"
                                            })json",
                                            /*ignore_unknown_field=*/false),
              Not(IsOk()));
  EXPECT_THAT(ParseJsonAsProto<TestMessage>(R"json({
                                              "int_field" : 42,
                                              "string_field" : "bye",
                                              "unknown_field": "please ignore"
                                            })json",
                                            /*ignore_unknown_field=*/true),
              IsOkAndHolds(EqualsProto(R"pb(
                int_field: 42 string_field: "bye"
              )pb")));
}

TEST(SerializeProtoAsJson, RoundTripsWithParseJsonAsProto) {
  ASSERT_OK_AND_ASSIGN(auto proto, ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  ASSERT_OK_AND_ASSIGN(std::string json, SerializeProtoAsJson(proto));
  EXPECT_THAT(ParseJsonAsProto<TestMessage>(json),
              IsOkAndHolds(EqualsProto(proto)));
}

TEST(SaveProtoToFile, SavesProtoToFileTruncatesFileOnOverwrite) {
  ASSERT_OK_AND_ASSIGN(std::string test_tmpdir, GetTestTmpDir());
  std::string proto_save_path =
      absl::StrCat(test_tmpdir, "/forwarding_config.pb.txt");
  ASSERT_OK_AND_ASSIGN(gutil::TestMessage proto,
                       ParseTextProto<TestMessage>(R"pb(
                         int_field: 42
                         string_field: "hello!"
                       )pb"));
  ASSERT_OK(SaveProtoToFile(proto_save_path, proto));

  gutil::TestMessage read_proto;
  ASSERT_OK(gutil::ReadProtoFromFile(proto_save_path, &read_proto));
  EXPECT_THAT(read_proto, EqualsProto(proto));

  gutil::TestMessage empty_proto;
  // Overite the saved file with empty proto.
  ASSERT_OK(SaveProtoToFile(proto_save_path, empty_proto));

  gutil::TestMessage read_empty_proto;
  ASSERT_OK(gutil::ReadProtoFromFile(proto_save_path, &read_empty_proto));
  // Verify the file is truncated.
  EXPECT_THAT(read_empty_proto, EqualsProto(empty_proto));
}

}  // namespace
}  // namespace gutil
