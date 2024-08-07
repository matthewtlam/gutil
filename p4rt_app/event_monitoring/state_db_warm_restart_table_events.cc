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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "glog/logging.h"
#include "p4rt_app/event_monitoring/state_event_monitor.h"
#include "p4rt_app/p4runtime/p4runtime_impl.h"
#include "swss/warm_restart.h"

namespace p4rt_app {

constexpr char kOrchagentComponent[] = "orchagent";

absl::Status StateDbWarmRestartTableEventHandler::HandleEvent(
    const std::string& operation, const std::string& key,
    const std::vector<std::pair<std::string, std::string>>& values) {
  // Only cares about OA warm start state.
  if (key != kOrchagentComponent) return absl::OkStatus();

  for (const auto& [field, value] : values) {
    if (field == "state") {
      swss::WarmStart::WarmStartState oa_state =
          swss::WarmStart::WarmStartState::WSUNKNOWN;

      for (const auto& [state, name] :
           *swss::WarmStart::warmStartStateNameMap()) {
        if (name == value) {
          oa_state = state;
          break;
        }
      }
      if (oa_state == swss::WarmStart::WarmStartState::RECONCILED) {
        *oa_reconciled_ = true;
        return absl::OkStatus();
      } else if (oa_state == swss::WarmStart::WarmStartState::FAILED) {
        // Stop monitoring OA reconcile events if OA failed to reconcile.
        *monitor_oa_reconcile_events_ = false;
        return absl::FailedPreconditionError("OA failed to reconcile.");
      }
    }
  }

  return absl::OkStatus();
}

void WaitForOrchAgentReconcileToUnfreezeP4rt(
    sonic::StateEventMonitor* state_db_monitor, P4RuntimeImpl* p4runtime_server,
    bool* monitor_oa_reconcile_events, bool* oa_reconciled) {
  absl::Status status = state_db_monitor->RegisterTableHandler(
      "WARM_RESTART_TABLE",
      std::make_unique<StateDbWarmRestartTableEventHandler>(
          monitor_oa_reconcile_events, oa_reconciled));
  if (!status.ok()) {
    LOG(ERROR) << "STATE_DB event monitor failed to register handler for "
                  "WARM_RESTART_TABLE: "
               << status;
    return;
  }

  while (*monitor_oa_reconcile_events && (!*oa_reconciled)) {
    status = state_db_monitor->WaitForNextEventAndHandle();
    if (!status.ok()) {
      LOG(ERROR)
          << "STATE_DB event monitor failed waiting for OA to reconcile: "
          << status;
    }
  }

  if (*oa_reconciled) {
    LOG(INFO) << "OA reconciled, unfreeze P4RT.";
    p4runtime_server->SetFreezeMode(/*freeze_mode=*/false);
  }
}

}  // namespace p4rt_app
