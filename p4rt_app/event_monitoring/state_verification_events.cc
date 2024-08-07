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

#include <chrono>  // NOLINT
#include <string>
#include <thread>  // NOLINT
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "glog/logging.h"
#include "gutil/status.h"
#include "p4rt_app/p4runtime/p4runtime_impl.h"
#include "p4rt_app/sonic/adapters/consumer_notifier_adapter.h"
#include "p4rt_app/sonic/adapters/subscriber_state_table_adapter.h"
#include "p4rt_app/sonic/adapters/table_adapter.h"
#include "swss/component_state_helper_interface.h"
#include "swss/rediscommand.h"
#include "swss/table.h"

namespace p4rt_app {

StateVerificationEvents::StateVerificationEvents(
    P4RuntimeImpl& p4runtime,
    sonic::ConsumerNotifierAdapter& notification_channel,
    sonic::SubscriberStateTableAdapter& subscriber_table,
    sonic::TableAdapter& response_channel)
    : p4runtime_(p4runtime),
      notification_channel_(notification_channel),
      subscriber_table_(subscriber_table),
      response_channel_(response_channel) {}

absl::Status StateVerificationEvents::WaitForReadyEvent(
    absl::string_view verify_req_timestamp) {
  const std::string kOrchagentComponentName =
      swss::SystemComponentToString(swss::SystemComponent::kOrchagent);
  auto start_time = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start_time <=
         std::chrono::seconds(60)) {
    std::string component_name;
    std::string unused_data;
    std::vector<swss::FieldValueTuple> field_values;
    {
      absl::MutexLock l(&event_lock_);
      if (!subscriber_table_.WaitForNotificationAndPop(
              component_name, unused_data, field_values, /*timeout_ms=*/100)) {
        continue;
      }
    }
    if (component_name != kOrchagentComponentName) continue;
    std::string update_timestamp;
    std::string status;
    for (const auto& field_value : field_values) {
      if (fvField(field_value) == "timestamp") {
        update_timestamp = fvValue(field_value);
      } else if (fvField(field_value) == "status") {
        status = fvValue(field_value);
      }
    }
    // Match the current update timestamp with the verify request
    // timestamp and check if Orchagent finished its part.
    if (update_timestamp == verify_req_timestamp) {
      if (status == "ready" || status == "pass" || status == "fail") {
        return absl::OkStatus();
      }
    }
  }

  return absl::DeadlineExceededError(
      "Timed out waiting for Orchagent to complete state verification.");
}

absl::Status StateVerificationEvents::WaitForEventAndVerifyP4Runtime() {
  const std::string kP4rtComponentName =
      swss::SystemComponentToString(swss::SystemComponent::kP4rt);
  constexpr absl::Duration timeout = absl::Hours(25);
  std::string operation;
  std::string key;
  std::vector<swss::FieldValueTuple> field_values;
  {
    absl::MutexLock l(&event_lock_);
    if (!notification_channel_.WaitForNotificationAndPop(
            operation, key, field_values, absl::ToInt64Milliseconds(timeout))) {
      return gutil::UnknownErrorBuilder()
             << "State verification events failed/timed-out waiting for a "
             << "notification.";
    }
  }

  // We only need to update state when asked about the P4RT App component.
  if (operation != kP4rtComponentName) {
    return absl::OkStatus();
  }

  bool update_component_state = false;
  for (const auto& field_value : field_values) {
    if (fvField(field_value) == "alarm" && fvValue(field_value) == "true") {
      update_component_state = true;
    }
  }

  // Wait for ready signal from Ochagent to indicate it has finished updating
  // the APP_DB.
  absl::Status verification_status;
  std::string p4rt_status = "pass";
  std::string error_string = "";
  auto ready_status = WaitForReadyEvent(key);
  if (ready_status.ok()) {
    // Run P4RuntimeImpl state verification.
    verification_status = p4runtime_.VerifyState(update_component_state);
    if (!verification_status.ok()) {
      p4rt_status = "fail";
      error_string = verification_status.ToString();
    }
  } else {
    p4rt_status = "not_run";
    error_string = ready_status.ToString();
    verification_status = ready_status;
  }

  // When updating AppStateDb we don't need to notify the caller. Simply
  // update the P4RT app entry with the current data.
  {
    absl::MutexLock l(&event_lock_);
    response_channel_.set(kP4rtComponentName, {
                                                  {"timestamp", key},
                                                  {"status", p4rt_status},
                                                  {"err_str", error_string},
                                              });
  }
  return verification_status;
}

void StateVerificationEvents::Start() {
  // There should only ever be one active thread.
  if (!event_thread_.joinable()) {
    event_thread_ = std::thread(
        &StateVerificationEvents::ContinuallyMonitorForEvents, this);
  }
}

void StateVerificationEvents::Stop() {
  stopping_.Notify();

  // Only join the thread if it has been started.
  if (event_thread_.joinable()) {
    event_thread_.join();
    LOG(INFO) << "Stop monitoring state verification events.";
  }
}

void StateVerificationEvents::ContinuallyMonitorForEvents() {
  LOG(INFO) << "Start monitoring state verification events.";
  while (!stopping_.HasBeenNotified()) {
    absl::Status status = WaitForEventAndVerifyP4Runtime();
    if (!status.ok()) {
      LOG(ERROR) << "Issue verifying P4RT App's state: " << status;
    }
  }
}

}  // namespace p4rt_app
