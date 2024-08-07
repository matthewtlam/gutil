// Copyright (c) 2023, Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "dvaas/mirror_testbed_config.h"

#include <vector>

#include "absl/container/btree_set.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "glog/logging.h"
#include "gutil/status.h"
#include "lib/gnmi/gnmi_helper.h"
#include "lib/p4rt/p4rt_port.h"
#include "p4_pdpi/ir.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "proto/gnmi/gnmi.grpc.pb.h"
#include "tests/lib/switch_test_setup_helpers.h"
#include "thinkit/mirror_testbed.h"

namespace dvaas {
namespace {

// Tries to configure a subset of SUT's interfaces to map every given P4RT port
// ID in `p4rt_port_ids` to an enabled Ethernet interface.
absl::Status ConfigureSutInterfacesWithGivenP4RtPortIds(
    gnmi::gNMI::StubInterface& sut_gnmi_stub,
    absl::btree_set<pins_test::P4rtPortId>& p4rt_port_ids) {
  // Only map to enabled Ethernet interfaces.
  auto is_enabled_ethernet_interface =
      [](const pins_test::openconfig::Interfaces::Interface& interface) {
        return interface.config().enabled() &&
               // Ethernet interfaces are, so far, best identified by name.
               absl::StartsWith(interface.name(), "Ethernet");
      };

  absl::btree_set<int> open_config_p4rt_port_ids;
  for (const pins_test::P4rtPortId& p4rt_port_id : p4rt_port_ids) {
    open_config_p4rt_port_ids.insert(p4rt_port_id.GetOpenConfigEncoding());
  }
  // Map the required P4RT port IDs to matching interfaces on the SUT.
  RETURN_IF_ERROR(pins_test::MapP4rtIdsToMatchingInterfaces(
      sut_gnmi_stub, open_config_p4rt_port_ids, is_enabled_ethernet_interface));

  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<MirrorTestbedConfigurator> MirrorTestbedConfigurator::Create(
    thinkit::MirrorTestbed* testbed) {
  MirrorTestbedConfigurator configured_testbed(testbed);

  ASSIGN_OR_RETURN(configured_testbed.sut_api_.p4rt,
                   pdpi::P4RuntimeSession::Create(testbed->Sut()));
  ASSIGN_OR_RETURN(configured_testbed.sut_api_.gnmi,
                   testbed->Sut().CreateGnmiStub());
  ASSIGN_OR_RETURN(configured_testbed.control_switch_api_.p4rt,
                   pdpi::P4RuntimeSession::Create(testbed->ControlSwitch()));
  ASSIGN_OR_RETURN(configured_testbed.control_switch_api_.gnmi,
                   testbed->ControlSwitch().CreateGnmiStub());

  return configured_testbed;
}

absl::Status MirrorTestbedConfigurator::ConfigureForForwardingTest(
    const MirrorTestbedConfigurator::Params& params) {
  // The testbed must not have been configured before.
  if (original_control_interfaces_.has_value() ||
      original_sut_interfaces_.has_value()) {
    return absl::FailedPreconditionError(
        "Configure function called on an already configured testbed.");
  }
  if (params.configure_sut_port_ids_for_expected_entries) {
    if (!params.sut_entries_to_expect_after_configuration.has_value()) {
      return absl::InvalidArgumentError(
          "`expected_sut_entries` must have a value when "
          "`configure_sut_ports_for_expected_entries` is true.");
    }
    if (!params.mirror_sut_ports_ids_to_control_switch) {
      return absl::InvalidArgumentError(
          "`mirror_sut_ports_to_control_switch` must be true when "
          "configure_sut_ports_for_expected_entries` is true.");
    }
  }

  // Store the original control switch gNMI interface config before changing
  // it.
  ASSIGN_OR_RETURN(original_sut_interfaces_,
                   pins_test::GetInterfacesAsProto(*sut_api_.gnmi,
                                                   gnmi::GetRequest::CONFIG));
  ASSIGN_OR_RETURN(original_control_interfaces_,
                   pins_test::GetInterfacesAsProto(*control_switch_api_.gnmi,
                                                   gnmi::GetRequest::CONFIG));

  if (params.configure_sut_port_ids_for_expected_entries) {
    // Get P4RT port ids in `used_entries`.
    ASSIGN_OR_RETURN(p4::v1::GetForwardingPipelineConfigResponse response,
                     GetForwardingPipelineConfig(sut_api_.p4rt.get()));
    ASSIGN_OR_RETURN(pdpi::IrP4Info ir_info,
                     pdpi::CreateIrP4Info(response.config().p4info()));
    std::vector<pdpi::IrTableEntry> used_entries_list(
        params.sut_entries_to_expect_after_configuration.value()
            .entries()
            .begin(),
        params.sut_entries_to_expect_after_configuration.value()
            .entries()
            .end());
    ASSIGN_OR_RETURN(absl::btree_set<pins_test::P4rtPortId> used_p4rt_port_ids,
                     pins_test::GetPortsUsed(ir_info, used_entries_list));

    // Clear entities on SUT. This is needed to ensure we can modify the
    // interface configurations.
    RETURN_IF_ERROR(pdpi::ClearEntities(*sut_api_.p4rt));

    // Change interface configurations on SUT to match `used_p4rt_port_ids`.
    RETURN_IF_ERROR(ConfigureSutInterfacesWithGivenP4RtPortIds(
        *sut_api_.gnmi, used_p4rt_port_ids));
  }

  if (params.mirror_sut_ports_ids_to_control_switch) {
    // Clear entities on control switch. This is needed to ensure we can modify
    // the interface configurations.
    RETURN_IF_ERROR(pdpi::ClearEntities(*control_switch_api_.p4rt));

    // Mirror the SUTs OpenConfig interface <-> P4RT port ID mappings to the
    // control switch.
    RETURN_IF_ERROR(
        pins_test::MirrorSutP4rtPortIdConfigToControlSwitch(testbed_));
  }

  // Ensure that all enabled ports are up.
  RETURN_IF_ERROR(pins_test::WaitForEnabledInterfacesToBeUp(testbed_.Sut()))
          .SetPrepend()
      << "expected enabled interfaces on SUT to be up: ";
  RETURN_IF_ERROR(
      pins_test::WaitForEnabledInterfacesToBeUp(testbed_.ControlSwitch()))
          .SetPrepend()
      << "expected enabled interfaces on control switch to be up: ";

  return absl::OkStatus();
}

absl::Status MirrorTestbedConfigurator::RestoreToOriginalConfiguration() {
  // The testbed must have been configured before.
  if (!original_control_interfaces_.has_value() ||
      !original_sut_interfaces_.has_value()) {
    return absl::FailedPreconditionError(
        "The testbed has not been configured for forwarding test before.");
  }

  // Clear table entries on both SUT and control switch. This is needed to
  // ensure we can modify their interface configurations.
  RETURN_IF_ERROR(pdpi::ClearTableEntries(control_switch_api_.p4rt.get()));
  RETURN_IF_ERROR(pdpi::ClearTableEntries(sut_api_.p4rt.get()));

  // Restore the original interface P4RT port id configurations of SUT and
  // control switch.
  RETURN_IF_ERROR(pins_test::SetInterfaceP4rtIds(*sut_api_.gnmi,
                                                 *original_sut_interfaces_));
  RETURN_IF_ERROR(pins_test::SetInterfaceP4rtIds(
      *control_switch_api_.gnmi, *original_control_interfaces_));

  // Remove the kept interfaces.
  original_sut_interfaces_.reset();
  original_control_interfaces_.reset();

  return absl::OkStatus();
}

}  // namespace dvaas
