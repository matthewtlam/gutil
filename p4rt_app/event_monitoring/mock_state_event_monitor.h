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
#ifndef PINS_INFRA_P4RT_APP_EVENT_MONITORING_MOCK_STATE_EVENT_MONITOR_H_
#define PINS_INFRA_P4RT_APP_EVENT_MONITORING_MOCK_STATE_EVENT_MONITOR_H_

#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "p4rt_app/event_monitoring/state_event_monitor.h"

namespace p4rt_app {
namespace sonic {

class MockStateEventMonitor : public StateEventMonitor {
 public:
  MOCK_METHOD(absl::Status, RegisterTableHandler,
              (absl::string_view table_name,
               std::unique_ptr<StateEventHandler> handler),
              (override));
  MOCK_METHOD(absl::Status, WaitForNextEventAndHandle, (), (override));
};

}  // namespace sonic
}  // namespace p4rt_app

#endif  // PINS_INFRA_P4RT_APP_EVENT_MONITORING_MOCK_STATE_EVENT_MONITOR_H_
