// Copyright 2022 Google LLC
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

#include "sai_p4/tools/auxiliary_entries_for_v1model_targets.h"

#include <optional>
#include <string>

#include "absl/container/btree_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"
#include "lib/gnmi/gnmi_helper.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.pb.h"
#include "proto/gnmi/gnmi.grpc.pb.h"
#include "sai_p4/fixed/ids.h"
#include "sai_p4/instantiations/google/sai_pd.pb.h"

namespace sai {
namespace {

enum class TaggingMode {
  kTagged,
  kUntagged,
};

absl::StatusOr<pdpi::IrEntity> CreateVlanMembershipEntity(
    absl::string_view vlan_id, absl::string_view port, TaggingMode tagging_mode,
    bool auxiliary_table = false) {
  pdpi::IrEntity aux_ir_entity;
  aux_ir_entity.mutable_table_entry()->set_table_name(
      auxiliary_table ? "v1model_auxiliary_vlan_membership_table"
                      : "vlan_membership_table");
  pdpi::IrMatch& vlan_match =
      *aux_ir_entity.mutable_table_entry()->mutable_matches()->Add();
  vlan_match.set_name("vlan_id");
  vlan_match.mutable_exact()->set_hex_str(vlan_id);
  pdpi::IrMatch& port_match =
      *aux_ir_entity.mutable_table_entry()->mutable_matches()->Add();
  port_match.set_name("port");
  port_match.mutable_exact()->set_str(port);
  if (tagging_mode == TaggingMode::kTagged) {
    aux_ir_entity.mutable_table_entry()->mutable_action()->set_name(
        auxiliary_table ? "v1model_auxiliary_make_tagged_member"
                        : "make_tagged_member");
  } else if (tagging_mode == TaggingMode::kUntagged) {
    aux_ir_entity.mutable_table_entry()->mutable_action()->set_name(
        auxiliary_table ? "v1model_auxiliary_make_untagged_member"
                        : "make_untagged_member");
  } else {
    return absl::InternalError("Unsupported action in vlan_membership_table");
  }
  return aux_ir_entity;
}

absl::StatusOr<pdpi::IrEntities> CreateV1ModelAuxiliaryEntitiesForLoopbackPorts(
    gnmi::gNMI::StubInterface& gnmi_stub) {
  // Get the loopback mode map from the gNMI stub.
  absl::btree_set<std::string> loopback_mode_port_set;
  ASSIGN_OR_RETURN(
      loopback_mode_port_set,
      pins_test::GetP4rtIdOfInterfacesInAsicMacLocalLoopbackMode(gnmi_stub));

  // For each port configured to be in loopback mode in gNMI, add an entry to
  // the loopback table.
  pdpi::IrEntities auxiliary_ir_entities;
  for (const auto& loopback_mode_port : loopback_mode_port_set) {
    pdpi::IrEntity& aux_ir_entity = *auxiliary_ir_entities.add_entities();
    aux_ir_entity.mutable_table_entry()->set_table_name(
        "egress_port_loopback_table");
    pdpi::IrMatch& match =
        *aux_ir_entity.mutable_table_entry()->mutable_matches()->Add();
    match.set_name("out_port");
    match.mutable_exact()->set_str(loopback_mode_port);
    aux_ir_entity.mutable_table_entry()->mutable_action()->set_name(
        "egress_loopback");
  }
  return auxiliary_ir_entities;
}

absl::StatusOr<pdpi::IrEntities>
CreateV1ModelAuxiliaryVlanMembershipTableEntities(
    const pdpi::IrEntities& ir_entities) {
  // For each entry in VLAN membership table, create an entry for v1model
  // auxiliary VLAN membership table.
  pdpi::IrEntities auxiliary_ir_entities;
  for (const auto& ir_entity : ir_entities.entities()) {
    if (ir_entity.table_entry().table_name() != "vlan_membership_table") {
      continue;
    }

    std::optional<absl::string_view> vlan_id;
    std::optional<absl::string_view> port;
    for (const auto& match : ir_entity.table_entry().matches()) {
      if (match.name() == "vlan_id") {
        vlan_id = match.exact().hex_str();
      } else if (match.name() == "port") {
        port = match.exact().str();
      } else {
        return absl::FailedPreconditionError(absl::StrCat(
            "Unexpected match '", match.name(),
            "' in vlan_membership_table, got ", ir_entity.ShortDebugString()));
      }
    }
    if (!vlan_id.has_value()) {
      return absl::FailedPreconditionError(
          absl::StrCat("Expected match on field `vlan_id` in ",
                       ir_entity.table_entry().table_name(), ", but got ",
                       ir_entity.table_entry().ShortDebugString()));
    }
    if (!port.has_value()) {
      return absl::FailedPreconditionError(
          absl::StrCat("Expected match on field `port` in ",
                       ir_entity.table_entry().table_name(), ", but got ",
                       ir_entity.table_entry().ShortDebugString()));
    }

    ASSIGN_OR_RETURN(
        *auxiliary_ir_entities.add_entities(),
        CreateVlanMembershipEntity(
            *vlan_id, *port,
            ir_entity.table_entry().action().name() == "make_tagged_member"
                ? TaggingMode::kTagged
                : TaggingMode::kUntagged,
            /*auxiliary_table=*/true));
  }
  return auxiliary_ir_entities;
}

// TODO: Remove this function once we switch to SUB_PORT RIFS that
// do not manipulate VLAN membership under the hood (b/354263363 for details).
absl::StatusOr<pdpi::IrEntities> CreateV1ModelAuxiliaryEntitiesForSubPortRifs(
    const pdpi::IrEntities& ir_entities) {
  // For each SUB_PORT RIF (i.e. entry in router_interface_table with action
  // set_port_and_src_mac_and_vlan_id with port `p` and vlan `v`), add auxiliary
  // entries to make `p` a tagged member of `v`.
  pdpi::IrEntities auxiliary_ir_entities;
  for (const auto& ir_entity : ir_entities.entities()) {
    if (!(ir_entity.table_entry().table_name() == "router_interface_table" &&
          ir_entity.table_entry().action().name() ==
              "set_port_and_src_mac_and_vlan_id")) {
      continue;
    }
    std::optional<absl::string_view> vlan_id;
    std::optional<absl::string_view> port;

    for (const auto& param : ir_entity.table_entry().action().params()) {
      if (param.name() == "vlan_id") {
        vlan_id = param.value().hex_str();
      } else if (param.name() == "port") {
        port = param.value().str();
      }
    }
    if (!vlan_id.has_value()) {
      return absl::FailedPreconditionError(absl::StrCat(
          "Expected param `vlan_id` in ", ir_entity.table_entry().table_name(),
          ", but got ", ir_entity.table_entry().ShortDebugString()));
    }
    if (!port.has_value()) {
      return absl::FailedPreconditionError(absl::StrCat(
          "Expected param `port` in ", ir_entity.table_entry().table_name(),
          ", but got ", ir_entity.table_entry().ShortDebugString()));
    }

    ASSIGN_OR_RETURN(
        *auxiliary_ir_entities.add_entities(),
        CreateVlanMembershipEntity(*vlan_id, *port, TaggingMode::kTagged,
                                   /*auxiliary_table=*/false));
    ASSIGN_OR_RETURN(
        *auxiliary_ir_entities.add_entities(),
        CreateVlanMembershipEntity(*vlan_id, *port, TaggingMode::kTagged,
                                   /*auxiliary_table=*/true));
  }
  return auxiliary_ir_entities;
}

}  // namespace

p4::v1::Entity MakeV1modelPacketReplicationEngineEntryRequiredForPunts() {
  p4::v1::Entity entity;

  p4::v1::CloneSessionEntry& clone_session =
      *entity.mutable_packet_replication_engine_entry()
           ->mutable_clone_session_entry();
  clone_session.set_session_id(COPY_TO_CPU_SESSION_ID);
  p4::v1::Replica& replica = *clone_session.add_replicas();
  replica.set_egress_port(SAI_P4_CPU_PORT);
  replica.set_instance(SAI_P4_REPLICA_INSTANCE_PACKET_IN);

  return entity;
}

absl::StatusOr<pdpi::IrEntities> CreateV1ModelAuxiliaryEntities(
    const pdpi::IrEntities& ir_entities, gnmi::gNMI::StubInterface& gnmi_stub) {
  pdpi::IrEntities auxiliary_ir_entities;
  ASSIGN_OR_RETURN(pdpi::IrEntities loopback_ports_entities,
                   CreateV1ModelAuxiliaryEntitiesForLoopbackPorts(gnmi_stub));
  auxiliary_ir_entities.MergeFrom(loopback_ports_entities);

  ASSIGN_OR_RETURN(
      pdpi::IrEntities vlan_membership_entities,
      CreateV1ModelAuxiliaryVlanMembershipTableEntities(ir_entities));
  auxiliary_ir_entities.MergeFrom(vlan_membership_entities);

  // TODO: Remove this function once we switch to SUB_PORT RIFS
  // that do not manipulate VLAN membership under the hood (b/354263363 for
  // details).
  ASSIGN_OR_RETURN(pdpi::IrEntities sub_port_rifs_entities,
                   CreateV1ModelAuxiliaryEntitiesForSubPortRifs(ir_entities));
  auxiliary_ir_entities.MergeFrom(sub_port_rifs_entities);
  return auxiliary_ir_entities;
}

}  // namespace sai
