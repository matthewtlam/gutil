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
#ifndef PINS_INFRA_P4RT_APP_EVENT_MONITORING_STATE_DB_WARM_RESTART_TABLE_EVENTS_H_
#define PINS_INFRA_P4RT_APP_EVENT_MONITORING_STATE_DB_WARM_RESTART_TABLE_EVENTS_H_

#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "p4rt_app/event_monitoring/state_event_monitor.h"
#include "p4rt_app/p4runtime/p4runtime_impl.h"

namespace p4rt_app {

// Reacts to WARM_RESTART_TABLE OA warm start state changes in the STATE_DB.
class StateDbWarmRestartTableEventHandler : public sonic::StateEventHandler {
 public:
  // These two variables are used to control the event handler loop.
  // If *monitor_oa_reconcile_events == false, stop monitoring OA reconcile
  // events and exit the event handler loop.
  // If *oa_reconciled == true, OA has reconciled, stop monitoring OA reconcile
  // events and exit the event handler loop.
  StateDbWarmRestartTableEventHandler(bool* monitor_oa_reconcile_events,
                                      bool* oa_reconciled)
      : monitor_oa_reconcile_events_(monitor_oa_reconcile_events),
        oa_reconciled_(oa_reconciled) {}

  absl::Status HandleEvent(
      const std::string& operation, const std::string& key,
      const std::vector<std::pair<std::string, std::string>>& values) override;

 private:
  bool* monitor_oa_reconcile_events_;
  bool* oa_reconciled_;
};

// This function implements a loop to check for OA warm start state, wait for OA
// to reconcile and then exit the loop and unfreezes P4RT. It will also exit the
// loop if *monitor_oa_reconcile_events == false.
void WaitForOrchAgentReconcileToUnfreezeP4rt(
    sonic::StateEventMonitor* state_db_monitor, P4RuntimeImpl* p4runtime_server,
    bool* monitor_oa_reconcile_events, bool* oa_reconciled);

}  // namespace p4rt_app

#endif  // PINS_INFRA_P4RT_APP_EVENT_MONITORING_STATE_DB_WARM_RESTART_TABLE_EVENTS_H_
