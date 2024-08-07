// Copyright 2020 Google LLC
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
#include "p4rt_app/sonic/app_db_manager.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "glog/logging.h"
#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"
#include "gutil/collections.h"
#include "gutil/status.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.pb.h"
#include "p4rt_app/sonic/app_db_to_pdpi_ir_translator.h"
#include "p4rt_app/sonic/packet_replication_entry_translation.h"
#include "p4rt_app/sonic/redis_connections.h"
#include "p4rt_app/sonic/response_handler.h"
#include "p4rt_app/sonic/vlan_entry_translation.h"
#include "p4rt_app/sonic/vrf_entry_translation.h"
#include "p4rt_app/utils/status_utility.h"
#include "p4rt_app/utils/table_utility.h"
#include "swss/rediscommand.h"
#include "swss/schema.h"
#include "swss/table.h"

namespace p4rt_app {
namespace sonic {
namespace {

absl::Status AppendCounterData(
    pdpi::IrTableEntry& table_entry,
    const std::vector<std::pair<std::string, std::string>>& counter_data) {
  auto field_value_error = [&table_entry](absl::string_view field,
                                          absl::string_view value) {
    return absl::Substitute(
        "Unexpected value '$0' for field '$1' in CountersDB for table entry: "
        "$2",
        value, field, table_entry.ShortDebugString());
  };

  for (const auto& [field, value] : counter_data) {
    uint64_t counter_value = 0;
    if (!absl::SimpleAtoi(value, &counter_value)) {
      LOG(ERROR) << field_value_error(field, value);
      continue;
    }

    // Update counter data if present.
    if (field == "packets") {
      table_entry.mutable_counter_data()->set_packet_count(counter_value);
    } else if (field == "bytes") {
      table_entry.mutable_counter_data()->set_byte_count(counter_value);
    }

    if (!table_entry.has_meter_config()) continue;

    // Update meter counter data if present.
    // Meter color counters are in the form of `color`_packets and
    // `color`_bytes.
    // Example: {red_packets 100}, {red_bytes 1000}.
    if (field == "green_packets") {
      table_entry.mutable_meter_counter_data()
          ->mutable_green()
          ->set_packet_count(counter_value);
    } else if (field == "green_bytes") {
      table_entry.mutable_meter_counter_data()->mutable_green()->set_byte_count(
          counter_value);
    } else if (field == "yellow_packets") {
      table_entry.mutable_meter_counter_data()
          ->mutable_yellow()
          ->set_packet_count(counter_value);
    } else if (field == "yellow_bytes") {
      table_entry.mutable_meter_counter_data()
          ->mutable_yellow()
          ->set_byte_count(counter_value);
    } else if (field == "red_packets") {
      table_entry.mutable_meter_counter_data()->mutable_red()->set_packet_count(
          counter_value);
    } else if (field == "red_bytes") {
      table_entry.mutable_meter_counter_data()->mutable_red()->set_byte_count(
          counter_value);
    }
  }

  return absl::OkStatus();
}

absl::StatusOr<swss::KeyOpFieldsValuesTuple> CreateAppDbP4rtUpdate(
    p4::v1::Update::Type update_type, const pdpi::IrTableEntry& entry,
    const pdpi::IrP4Info& p4_info) {
  swss::KeyOpFieldsValuesTuple update;
  ASSIGN_OR_RETURN(kfvKey(update), GetRedisP4rtTableKey(entry, p4_info));
  switch (update_type) {
    case p4::v1::Update::INSERT:
    case p4::v1::Update::MODIFY: {
      kfvOp(update) = SET_COMMAND;
      ASSIGN_OR_RETURN(kfvFieldsValues(update),
                       IrTableEntryToAppDbValues(entry));
    } break;
    case p4::v1::Update::DELETE:
      kfvOp(update) = DEL_COMMAND;
      break;
    default:
      return gutil::InvalidArgumentErrorBuilder()
             << "[P4RT App] Unsupported update type: "
             << p4::v1::Update::Type_Name(update_type);
  }
  return update;
}

// Executes updates to the P4RT table. Returns an error if there was a problem
// with performing the request. Returns false if the request was processed but
// at least one update failed. Returns true if all updates succeeed.
absl::StatusOr<bool> PerformAppDbP4rtUpdates(
    P4rtTable& p4rt_table,
    const std::vector<swss::KeyOpFieldsValuesTuple>& updates,
    absl::btree_map<std::string, pdpi::IrUpdateStatus*>& results) {
  if (updates.empty()) return true;
  p4rt_table.producer->send(updates);
  return GetAndProcessResponseNotificationWithoutRevertingState(
      *p4rt_table.producer, results);
}

}  // namespace

AppDbTableType GetAppDbTableType(const pdpi::IrEntity& ir_entity) {
  if (ir_entity.table_entry().table_name() == "vrf_table") {
    return sonic::AppDbTableType::VRF_TABLE;
  } else if (ir_entity.table_entry().table_name() == "vlan_table") {
    return sonic::AppDbTableType::VLAN_TABLE;
  } else if (ir_entity.table_entry().table_name() == "vlan_membership_table") {
    return sonic::AppDbTableType::VLAN_MEMBER_TABLE;
  } else {
    return sonic::AppDbTableType::P4RT;
  }
}

absl::StatusOr<AppDbUpdate> CreateAppDbUpdate(p4::v1::Update::Type update_type,
                                              const pdpi::IrEntity& entity,
                                              const pdpi::IrP4Info& p4_info) {
  AppDbUpdate update;
  update.table = GetAppDbTableType(entity);
  switch (GetAppDbTableType(entity)) {
    case AppDbTableType::VRF_TABLE: {
      ASSIGN_OR_RETURN(update.update,
                       CreateAppDbVrfUpdate(update_type, entity.table_entry()));
      return update;
    } break;
    case AppDbTableType::VLAN_TABLE: {
      ASSIGN_OR_RETURN(update.update, CreateAppDbVlanUpdate(
                                          update_type, entity.table_entry()));
      return update;
    } break;
    case AppDbTableType::VLAN_MEMBER_TABLE: {
      ASSIGN_OR_RETURN(update.update, CreateAppDbVlanMemberUpdate(
                                          update_type, entity.table_entry()));
      return update;
    } break;
    case AppDbTableType::P4RT: {
      switch (entity.entity_case()) {
        case pdpi::IrEntity::kTableEntry: {
          ASSIGN_OR_RETURN(update.update,
                           CreateAppDbP4rtUpdate(
                               update_type, entity.table_entry(), p4_info));
          return update;
        }
        case pdpi::IrEntity::kPacketReplicationEngineEntry: {
          ASSIGN_OR_RETURN(
              update.update,
              CreateAppDbPacketReplicationTableUpdate(
                  update_type, entity.packet_replication_engine_entry()));
          return update;
        }
        default:
          break;
      }
    } break;
    default:
      break;
  }
  return gutil::InvalidArgumentErrorBuilder()
         << "[P4RT App] Entity has no AppDb translation.";
}

absl::StatusOr<bool> PerformAppDbUpdates(
    P4rtTable& p4rt_table, VrfTable& vrf_table, VlanTable& vlan_table,
    VlanMemberTable& vlan_member_table,
    const std::vector<std::pair<AppDbUpdate, pdpi::IrUpdateStatus*>>&
        updates_and_results) {
  std::vector<swss::KeyOpFieldsValuesTuple> p4rt_updates;
  absl::btree_map<std::string, pdpi::IrUpdateStatus*> p4rt_results;

  bool failed = false;
  for (const auto& [update, result] : updates_and_results) {
    if (failed) {
      *result = GetIrUpdateStatus(absl::StatusCode::kAborted, "Not attempted");
      continue;
    }

    if (update.table == AppDbTableType::P4RT) {
      p4rt_updates.push_back(update.update);
      p4rt_results[kfvKey(update.update)] = result;
    } else {
      // Flush any P4 updates before attempting the non-P4RT update.
      // This maintains fail-on-first-error behavior where we shouldn't
      // attempt the VRF update if any of the queued P4 updates fails.
      ASSIGN_OR_RETURN(
          bool p4_success,
          PerformAppDbP4rtUpdates(p4rt_table, p4rt_updates, p4rt_results));
      p4rt_updates.clear();
      p4rt_results.clear();
      if (!p4_success) {
        *result =
            GetIrUpdateStatus(absl::StatusCode::kAborted, "Not attempted");
        failed = true;
        continue;
      }

      switch (update.table) {
        case AppDbTableType::VLAN_TABLE: {
          ASSIGN_OR_RETURN(*result,
                           PerformAppDbVlanUpdate(vlan_table, update.update));
          break;
        }
        case AppDbTableType::VLAN_MEMBER_TABLE: {
          ASSIGN_OR_RETURN(*result, PerformAppDbVlanMemberUpdate(
                                        vlan_member_table, update.update));
          break;
        }
        case AppDbTableType::VRF_TABLE: {
          ASSIGN_OR_RETURN(*result,
                           PerformAppDbVrfUpdate(vrf_table, update.update));
          break;
        }
        default: {
          break;
        }
      }
      failed = result->code() != google::rpc::Code::OK;
    }
  }

  if (failed) return false;
  return PerformAppDbP4rtUpdates(p4rt_table, p4rt_updates, p4rt_results);
}

absl::StatusOr<std::string> GetRedisP4rtTableKey(
    const pdpi::IrTableEntry& entry, const pdpi::IrP4Info& p4_info) {
  // Determine the table type.
  const pdpi::IrTableDefinition* ir_table_def =
      gutil::FindOrNull(p4_info.tables_by_name(), entry.table_name());
  if (ir_table_def == nullptr) {
    return gutil::InternalErrorBuilder()
           << "Table name '" << entry.table_name() << "' does not exist";
  }
  ASSIGN_OR_RETURN(auto table_type, GetTableType(*ir_table_def));

  // Determine the AppDb match key.
  ASSIGN_OR_RETURN(const std::string json_key, IrTableEntryToAppDbKey(entry));

  // The final AppDb Key format is: <table_type>_<table_name>:<json_key>
  return absl::StrCat(
      absl::AsciiStrToUpper(absl::Substitute(
          "$0_$1:", table::TypeName(table_type), entry.table_name())),
      json_key);
}

// This function can only be called for keys that point to IrTableEntry in the
// P4RT_TABLE.  IrPacketReplicationEntry keys are handled separately.
absl::StatusOr<pdpi::IrTableEntry> ReadP4TableEntry(
    P4rtTable& p4rt_table, const pdpi::IrP4Info& p4info,
    const std::string& key) {
  VLOG(1) << "Read AppDb entry: " << key;
  ASSIGN_OR_RETURN(pdpi::IrTableEntry table_entry,
                   AppDbKeyAndValuesToIrTableEntry(
                       p4info, key, p4rt_table.app_db->get(key)));

  // Counters should only exist for ACL table entries.
  if (absl::StartsWith(key, table::TypeName(table::Type::kAcl))) {
    // CounterDb entries will include the full AppDb entry key.
    RETURN_IF_ERROR(AppendCounterData(
        table_entry, p4rt_table.counter_db->get(absl::StrCat(
                         p4rt_table.app_db->getTablePrefix(), key))));
  }

  return table_entry;
}

absl::Status AppendCounterDataForTableEntry(pdpi::IrTableEntry& ir_table_entry,
                                            P4rtTable& p4rt_table,
                                            const pdpi::IrP4Info& p4info) {
  ASSIGN_OR_RETURN(std::string key,
                   GetRedisP4rtTableKey(ir_table_entry, p4info));
  return AppendCounterData(ir_table_entry,
                           p4rt_table.counter_db->get(absl::StrCat(
                               p4rt_table.app_db->getTablePrefix(), key)));
}

std::vector<std::string> GetAllP4TableEntryKeys(P4rtTable& p4rt_table) {
  std::vector<std::string> p4rt_keys;

  for (const auto& key : p4rt_table.app_db->keys()) {
    const std::vector<std::string> split = absl::StrSplit(key, ':');

    // The DEFINITION sub-table does not hold any P4RT_TABLE entries, and should
    // be ignored.
    if (split.size() > 1 && split[0] == APP_P4RT_ACL_TABLE_DEFINITION_NAME) {
      continue;
    }
    // Packet replication entries stored in the P4RT_TABLE are handled by
    // packet replication entry translation.
    if (split.size() > 1 &&
        split[0] == APP_P4RT_REPLICATION_IP_MULTICAST_TABLE_NAME) {
      continue;
    }

    p4rt_keys.push_back(key);
  }
  return p4rt_keys;
}

}  // namespace sonic
}  // namespace p4rt_app
