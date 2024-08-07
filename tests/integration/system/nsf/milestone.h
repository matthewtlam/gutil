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

#ifndef PINS_INFRA_TESTS_INTEGRATION_SYSTEM_NSF_MILESTONE_H_
#define PINS_INFRA_TESTS_INTEGRATION_SYSTEM_NSF_MILESTONE_H_

#include <string>

#include "absl/strings/string_view.h"

namespace pins_test {

enum class NsfMilestone {
  kAll,  // All NSF milestones in one.
  kShutdown,
  kBootup,
};

bool AbslParseFlag(absl::string_view milestone_text, NsfMilestone* milestone,
                   std::string* error);
std::string AbslUnparseFlag(NsfMilestone milestone);

}  // namespace pins_test

#endif  // PINS_INFRA_TESTS_INTEGRATION_SYSTEM_NSF_MILESTONE_H_
