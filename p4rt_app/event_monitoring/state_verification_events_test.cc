// Copyright 2021 Google LLC
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
#include "p4rt_app/event_monitoring/state_verification_events.h"

#include <vector>

#include "absl/status/status.h"
#include "absl/synchronization/notification.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"
#include "p4rt_app/p4runtime/mock_p4runtime_impl.h"
#include "p4rt_app/sonic/adapters/mock_consumer_notifier_adapter.h"
#include "p4rt_app/sonic/adapters/mock_subscriber_state_table_adapter.h"
#include "p4rt_app/sonic/adapters/mock_table_adapter.h"
#include "swss/rediscommand.h"

namespace p4rt_app {
namespace {

using ::gutil::StatusIs;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::SetArgReferee;

class StateVerificationEventsTest : public testing::Test {
 protected:
  StateVerificationEventsTest()
      : state_verification_(StateVerificationEvents(
            mock_p4runtime_, mock_consumer_notifier_,
            mock_subscriber_state_table_, mock_table_)) {}

  StateVerificationEvents state_verification_;

  MockP4RuntimeImpl mock_p4runtime_;
  sonic::MockConsumerNotifierAdapter mock_consumer_notifier_;
  sonic::MockSubscriberStateTableAdapter mock_subscriber_state_table_;
  sonic::MockTableAdapter mock_table_;
};

TEST_F(StateVerificationEventsTest, GetEventAndUpdateRedisDbState) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"),
                      SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                          swss::FieldValueTuple{"alarm", "true"}}),
                      Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillOnce(DoAll(
          SetArgReferee<0>("swss:orchagent"), SetArgReferee<1>("not_used"),
          SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
              swss::FieldValueTuple{"timestamp", "sample_timestamp"},
              swss::FieldValueTuple{"status", "ready"},
          }),
          Return(true)));
  EXPECT_CALL(mock_p4runtime_, VerifyState(Eq(true)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_table_, set("p4rt:p4rt",
                               std::vector<swss::FieldValueTuple>{
                                   {"timestamp", "sample_timestamp"},
                                   {"status", "pass"},
                                   {"err_str", ""},
                               }))
      .Times(1);

  EXPECT_OK(state_verification_.WaitForEventAndVerifyP4Runtime());
}

TEST_F(StateVerificationEventsTest, GetReadyOnSecondAttemptFromOrchagent) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"),
                      SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                          swss::FieldValueTuple{"alarm", "true"}}),
                      Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillOnce(Return(false))
      .WillOnce(DoAll(
          SetArgReferee<0>("swss:orchagent"), SetArgReferee<1>("not_used"),
          SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
              swss::FieldValueTuple{"timestamp", "sample_timestamp"},
              swss::FieldValueTuple{"status", "ready"},
          }),
          Return(true)));
  EXPECT_CALL(mock_p4runtime_, VerifyState(Eq(true)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_table_, set("p4rt:p4rt",
                               std::vector<swss::FieldValueTuple>{
                                   {"timestamp", "sample_timestamp"},
                                   {"status", "pass"},
                                   {"err_str", ""},
                               }))
      .Times(1);

  EXPECT_OK(state_verification_.WaitForEventAndVerifyP4Runtime());
}

TEST_F(StateVerificationEventsTest, GetReadyFromOtherCompsAreIgnored) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"),
                      SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                          swss::FieldValueTuple{"alarm", "true"}}),
                      Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillRepeatedly(
          DoAll(SetArgReferee<0>("syncd:syncd"), SetArgReferee<1>("not_used"),
                SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                    swss::FieldValueTuple{"timestamp", "sample_timestamp"},
                    swss::FieldValueTuple{"status", "ready"},
                }),
                Return(true)));
  EXPECT_CALL(mock_table_,
              set("p4rt:p4rt",
                  std::vector<swss::FieldValueTuple>{
                      {"timestamp", "sample_timestamp"},
                      {"status", "not_run"},
                      {"err_str",
                       "DEADLINE_EXCEEDED: Timed out waiting for Orchagent to "
                       "complete state verification."},
                  }))
      .Times(1);
  EXPECT_THAT(state_verification_.WaitForEventAndVerifyP4Runtime(),
              StatusIs(absl::StatusCode::kDeadlineExceeded,
                       HasSubstr("Timed out waiting for Orchagent to complete "
                                 "state verification.")));
}

TEST_F(StateVerificationEventsTest, TimeoutWaitingForReadyFromOrchagent) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"),
                      SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                          swss::FieldValueTuple{"alarm", "true"}}),
                      Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_table_,
              set("p4rt:p4rt",
                  std::vector<swss::FieldValueTuple>{
                      {"timestamp", "sample_timestamp"},
                      {"status", "not_run"},
                      {"err_str",
                       "DEADLINE_EXCEEDED: Timed out waiting for Orchagent to "
                       "complete state verification."},
                  }))
      .Times(1);
  EXPECT_THAT(state_verification_.WaitForEventAndVerifyP4Runtime(),
              StatusIs(absl::StatusCode::kDeadlineExceeded,
                       HasSubstr("Timed out waiting for Orchagent to complete "
                                 "state verification.")));
}

TEST_F(StateVerificationEventsTest, PassOrFailFromOrchagentCausesP4rtToRun) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .Times(2)
      .WillRepeatedly(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                            SetArgReferee<1>("sample_timestamp"),
                            SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                                swss::FieldValueTuple{"alarm", "true"}}),
                            Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillOnce(DoAll(
          SetArgReferee<0>("swss:orchagent"), SetArgReferee<1>("not_used"),
          SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
              swss::FieldValueTuple{"timestamp", "sample_timestamp"},
              swss::FieldValueTuple{"status", "pass"},
              swss::FieldValueTuple{"err_str", ""},
          }),
          Return(true)))
      .WillOnce(DoAll(
          SetArgReferee<0>("swss:orchagent"), SetArgReferee<1>("not_used"),
          SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
              swss::FieldValueTuple{"timestamp", "sample_timestamp"},
              swss::FieldValueTuple{"status", "fail"},
              swss::FieldValueTuple{"err_str", ""},
          }),
          Return(true)));
  EXPECT_CALL(mock_p4runtime_, VerifyState(Eq(true)))
      .Times(2)
      .WillRepeatedly(Return(absl::OkStatus()));
  EXPECT_CALL(mock_table_, set("p4rt:p4rt",
                               std::vector<swss::FieldValueTuple>{
                                   {"timestamp", "sample_timestamp"},
                                   {"status", "pass"},
                                   {"err_str", ""},
                               }))
      .Times(2);
  // For Pass & Fail.
  EXPECT_OK(state_verification_.WaitForEventAndVerifyP4Runtime());
  EXPECT_OK(state_verification_.WaitForEventAndVerifyP4Runtime());
}

TEST_F(StateVerificationEventsTest, NotRunFromOrchagentCausesP4rtToTimeout) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"),
                      SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
                          swss::FieldValueTuple{"alarm", "true"}}),
                      Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillOnce(DoAll(
          SetArgReferee<0>("swss:orchagent"), SetArgReferee<1>("not_used"),
          SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
              swss::FieldValueTuple{"timestamp", "sample_timestamp"},
              swss::FieldValueTuple{"status", "not_run"},
              swss::FieldValueTuple{"err_str", ""},
          }),
          Return(true)))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_table_,
              set("p4rt:p4rt",
                  std::vector<swss::FieldValueTuple>{
                      {"timestamp", "sample_timestamp"},
                      {"status", "not_run"},
                      {"err_str",
                       "DEADLINE_EXCEEDED: Timed out waiting for Orchagent to "
                       "complete state verification."},
                  }))
      .Times(1);
  EXPECT_THAT(state_verification_.WaitForEventAndVerifyP4Runtime(),
              StatusIs(absl::StatusCode::kDeadlineExceeded,
                       HasSubstr("Timed out waiting for Orchagent to complete "
                                 "state verification.")));
}

TEST_F(StateVerificationEventsTest,
       GetEventAndUpdateRedisDbWhenP4rtIsInBadState) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"), Return(true)));
  EXPECT_CALL(mock_subscriber_state_table_, WaitForNotificationAndPop)
      .WillOnce(DoAll(
          SetArgReferee<0>("swss:orchagent"), SetArgReferee<1>("not_used"),
          SetArgReferee<2>(std::vector<swss::FieldValueTuple>{
              swss::FieldValueTuple{"timestamp", "sample_timestamp"},
              swss::FieldValueTuple{"status", "ready"},
          }),
          Return(true)));
  EXPECT_CALL(mock_p4runtime_, VerifyState(Eq(false)))
      .WillOnce(Return(absl::UnknownError("P4RT is in a bad state!")));
  EXPECT_CALL(mock_table_,
              set("p4rt:p4rt",
                  std::vector<swss::FieldValueTuple>{
                      {"timestamp", "sample_timestamp"},
                      {"status", "fail"},
                      {"err_str", "UNKNOWN: P4RT is in a bad state!"},
                  }))
      .Times(1);

  EXPECT_THAT(state_verification_.WaitForEventAndVerifyP4Runtime(),
              StatusIs(absl::StatusCode::kUnknown,
                       HasSubstr("P4RT is in a bad state")));
}

TEST_F(StateVerificationEventsTest, DoNotUpdateStateWhenNotificationFails) {
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("p4rt:p4rt"),
                      SetArgReferee<1>("sample_timestamp"), Return(false)));
  EXPECT_CALL(mock_p4runtime_, VerifyState).Times(0);
  EXPECT_CALL(mock_table_, set).Times(0);

  EXPECT_THAT(state_verification_.WaitForEventAndVerifyP4Runtime(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(StateVerificationEventsTest,
       DoNotUpdateStateWhenNotificationIsForDifferentComponent) {
  // Instead of getting a notification for p4rt, we get a notification for swss.
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce(DoAll(SetArgReferee<0>("swss:swss"),
                      SetArgReferee<1>("sample_timestamp"), Return(true)));
  EXPECT_CALL(mock_p4runtime_, VerifyState).Times(0);
  EXPECT_CALL(mock_table_, set).Times(0);

  EXPECT_OK(state_verification_.WaitForEventAndVerifyP4Runtime());
}

TEST_F(StateVerificationEventsTest, EventThreadStartStop) {
  // This test will spawn a thread inside the StateVerificationEvents object
  // which is stopped when the object is destroyed. To ensure we run through the
  // loop at least once we block on a notification.
  absl::Notification was_run;

  // We expect the wait call be be made at least once, but could be called again
  // while waiting for the thread to be stopped.
  EXPECT_CALL(mock_consumer_notifier_, WaitForNotificationAndPop)
      .WillOnce([&was_run](std::string& op, std::string& key,
                           std::vector<swss::FieldValueTuple>& fv,
                           int64_t timeout) {
        was_run.Notify();
        return false;
      })
      .WillRepeatedly(Return(false));

  // Spawn the thread, and wait for it to do work before finishing the test.
  state_verification_.Start();
  was_run.WaitForNotification();
  state_verification_.Stop();
}

}  // namespace
}  // namespace p4rt_app
