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
#include "p4rt_app/event_monitoring/state_db_warm_restart_table_events.h"

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"

namespace p4rt_app {
namespace {

using ::gutil::StatusIs;

// Expected SONiC commands assumed by state events.
constexpr char kSetCommand[] = "SET";

TEST(WarmRestartTableEventsTest, OrchagentReconcileSuccessful) {
  bool monitor_oa_reconcile_events = true;
  bool is_oa_reconciled = false;

  StateDbWarmRestartTableEventHandler event_handler{
      &monitor_oa_reconcile_events, &is_oa_reconciled};

  EXPECT_OK(event_handler.HandleEvent(kSetCommand, "orchagent",
                                      {{"state", "reconciled"}}));
  EXPECT_TRUE(is_oa_reconciled);
  EXPECT_TRUE(monitor_oa_reconcile_events);
}

TEST(WarmRestartTableEventsTest, OrchagentReconcileFailed) {
  bool monitor_oa_reconcile_events = true;
  bool is_oa_reconciled = false;

  StateDbWarmRestartTableEventHandler event_handler{
      &monitor_oa_reconcile_events, &is_oa_reconciled};

  EXPECT_THAT(event_handler.HandleEvent(kSetCommand, "orchagent",
                                        {{"state", "failed"}}),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_FALSE(is_oa_reconciled);
  // Stop monitoring reconcile events when OA reconcile fails.
  EXPECT_FALSE(monitor_oa_reconcile_events);
}

TEST(WarmRestartTableEventsTest, IgnoreOtherComponents) {
  bool monitor_oa_reconcile_events = true;
  bool is_oa_reconciled = false;

  StateDbWarmRestartTableEventHandler event_handler{
      &monitor_oa_reconcile_events, &is_oa_reconciled};

  EXPECT_OK(event_handler.HandleEvent(kSetCommand, "other",
                                      {{"state", "reconciled"}}));
  EXPECT_FALSE(is_oa_reconciled);
  EXPECT_TRUE(monitor_oa_reconcile_events);
}

}  // namespace
}  // namespace p4rt_app
