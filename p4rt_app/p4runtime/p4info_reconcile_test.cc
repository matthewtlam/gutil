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

#include "p4rt_app/p4runtime/p4info_reconcile.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "gutil/status_matchers.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4_pdpi/ir.pb.h"
#include "p4rt_app/p4runtime/resource_utilization.h"
#include "p4rt_app/utils/ir_builder.h"
#include "p4rt_app/utils/table_utility.h"

namespace p4rt_app {
namespace {
using ::gutil::EqualsProto;
using ::gutil::IsOkAndHolds;
using ::gutil::StatusIs;
using ::testing::Eq;
using ::testing::ExplainMatchResult;
using ::testing::Field;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Pair;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAreArray;
using ::testing::UnorderedPointwise;

MATCHER_P(TransitionIsImpl, expected, "") {
  bool failed = false;
  *result_listener << "\n";
  if (!ExplainMatchResult(UnorderedElementsAreArray(
                              expected.hashing_packet_field_configs_to_delete),
                          arg.hashing_packet_field_configs_to_delete,
                          result_listener)) {
    *result_listener
        << (failed ? "and " : "where ")
        << "hashing_packet_field_configs_to_delete does not match\n";
    failed = true;
  }
  if (!ExplainMatchResult(UnorderedElementsAreArray(
                              expected.hashing_packet_field_configs_to_set),
                          arg.hashing_packet_field_configs_to_set,
                          result_listener)) {
    *result_listener << (failed ? "and " : "where ")
                     << "hashing_packet_field_configs_to_set does not match\n";
    failed = true;
  }

  if (arg.update_switch_table != expected.update_switch_table) {
    *result_listener << (failed ? "and " : "where ")
                     << "update_switch_table does not match\n";
    failed = true;
  }
  if (!ExplainMatchResult(
          UnorderedElementsAreArray(expected.acl_tables_to_delete),
          arg.acl_tables_to_delete, result_listener)) {
    *result_listener << (failed ? "and " : "where ")
                     << "acl_tables_to_delete does not match\n";
    failed = true;
  }
  if (!ExplainMatchResult(UnorderedElementsAreArray(expected.acl_tables_to_add),
                          arg.acl_tables_to_add, result_listener)) {
    *result_listener << (failed ? "and " : "where ")
                     << "acl_tables_to_add does not match\n";
    failed = true;
  }
  if (!ExplainMatchResult(
          UnorderedElementsAreArray(expected.nonessential_acl_tables_to_modify),
          arg.nonessential_acl_tables_to_modify, result_listener)) {
    *result_listener << (failed ? "and " : "where ")
                     << "nonessential_acl_tables_to_modify does not match\n";
    failed = true;
  }
  if (!ExplainMatchResult(
          UnorderedElementsAreArray(expected.essential_acl_tables_to_modify),
          arg.essential_acl_tables_to_modify, result_listener)) {
    *result_listener << (failed ? "and " : "where ")
                     << "essential_acl_tables_to_modify does not match\n";
    failed = true;
  }
  return !failed;
}

constexpr auto TransitionIs = TransitionIsImpl<P4InfoReconcileTransition>;

MATCHER_P(CapacityIsImpl, expected, "") {
  bool failed = false;
  if (!ExplainMatchResult(Field("action_profile",
                                &ActionProfileResourceCapacity::action_profile,
                                EqualsProto(expected.action_profile)),
                          arg, result_listener)) {
    *result_listener << "\n";
    failed = true;
  }
  if (!ExplainMatchResult(
          Field("current_total_weight",
                &ActionProfileResourceCapacity::current_total_weight,
                Eq(expected.current_total_weight)),
          arg, result_listener)) {
    *result_listener << "\n";
    failed = true;
  }
  return !failed;
}

constexpr auto CapacityIs = CapacityIsImpl<ActionProfileResourceCapacity>;

MATCHER(CapacityEntryEq, "") {
  return ExplainMatchResult(
      Pair(Eq(std::get<1>(arg).first), CapacityIs(std::get<1>(arg).second)),
      std::get<0>(arg), result_listener);
}

const pdpi::IrP4Info& GetIrP4Info() {
  static const auto* const kP4Info = new pdpi::IrP4Info(
      IrP4InfoBuilder()
          .table(IrTableDefinitionBuilder()
                     .name("fixed_table_a")
                     .match_field(R"pb(id: 1 name: "match_field_a")pb",
                                  pdpi::Format::STRING)
                     .match_field(R"pb(id: 2 name: "match_field_b")pb",
                                  pdpi::Format::STRING)
                     .const_default_action(
                         IrActionDefinitionBuilder().name("NoAction"))
                     .size(100))
          .table(IrTableDefinitionBuilder()
                     .name("fixed_table_b")
                     .match_field(R"pb(id: 1 name: "match_field_a")pb",
                                  pdpi::Format::STRING)
                     .match_field(R"pb(id: 2 name: "match_field_b")pb",
                                  pdpi::Format::STRING)
                     .match_field(R"pb(id: 2 name: "match_field_c")pb",
                                  pdpi::Format::STRING)
                     .const_default_action(
                         IrActionDefinitionBuilder().name("NoAction"))
                     .size(200))
          .table(
              IrTableDefinitionBuilder()
                  .preamble(R"pb(alias: "acl_ingress_table_a"
                                 annotations: "@sai_acl(INGRESS)")pb")
                  .match_field(
                      R"pb(id: 1
                           name: "ttl"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_TTL)"
                           bitwidth: 8
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .match_field(
                      R"pb(id: 2
                           name: "ip_protocol"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL)"
                           bitwidth: 8
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .match_field(
                      R"pb(id: 3
                           name: "icmp_type"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE)"
                           bitwidth: 8
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .entry_action(IrActionDefinitionBuilder().preamble(
                      R"pb(alias: "acl_drop"
                           annotations: "@sai_action(SAI_PACKET_ACTION_DROP)")pb"))
                  .const_default_action(
                      IrActionDefinitionBuilder().name("NoAction"))
                  .meter_unit(p4::config::v1::MeterSpec::BYTES)
                  .counter_unit(p4::config::v1::CounterSpec::BOTH)
                  .size(128))
          .table(
              IrTableDefinitionBuilder()
                  .preamble(R"pb(alias: "acl_ingress_table_b"
                                 annotations: "@sai_acl(INGRESS)"
                                 annotations: "@nonessential_for_upgrade"
                  )pb")
                  .match_field(
                      R"pb(id: 1
                           name: "l4_dst_port"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT)"
                           bitwidth: 16
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .match_field(
                      R"pb(id: 2
                           name: "ip_protocol"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL)"
                           bitwidth: 8
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .match_field(
                      R"pb(id: 3
                           name: "icmp_type"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE)"
                           bitwidth: 8
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .entry_action(IrActionDefinitionBuilder().preamble(
                      R"pb(alias: "acl_drop"
                           annotations: "@sai_action(SAI_PACKET_ACTION_DROP)")pb"))
                  .const_default_action(
                      IrActionDefinitionBuilder().name("NoAction"))
                  .meter_unit(p4::config::v1::MeterSpec::BYTES)
                  .counter_unit(p4::config::v1::CounterSpec::BOTH)
                  .size(256))
          .table(
              IrTableDefinitionBuilder()
                  .preamble(R"pb(alias: "acl_ingress_table_c"
                                 annotations: "@sai_acl(INGRESS)"
                                 annotations: "@nonessential_for_upgrade")pb")
                  .match_field(
                      R"pb(id: 1
                           name: "l4_dst_port"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT)"
                           bitwidth: 16
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .match_field(
                      R"pb(id: 2
                           name: "ip_protocol"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL)"
                           bitwidth: 8
                           match_type: TERNARY)pb",
                      pdpi::Format::HEX_STRING)
                  .entry_action(IrActionDefinitionBuilder().preamble(
                      R"pb(alias: "acl_drop"
                           annotations: "@sai_action(SAI_PACKET_ACTION_DROP)")pb"))
                  .const_default_action(
                      IrActionDefinitionBuilder().name("NoAction"))
                  .meter_unit(p4::config::v1::MeterSpec::BYTES)
                  .counter_unit(p4::config::v1::CounterSpec::BOTH)
                  .size(128))
          .table(
              IrTableDefinitionBuilder()
                  .preamble(R"pb(alias: "acl_ingress_table_d"
                                 annotations: "@sai_acl(INGRESS)")pb")
                  .match_field(
                      R"pb(id: 1
                           name: "is_ip"
                           annotations: "@sai_field(SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE / IP)"
                           bitwidth: 1
                           match_type: OPTIONAL)pb",
                      pdpi::Format::HEX_STRING)
                  .entry_action(IrActionDefinitionBuilder().preamble(
                      R"pb(alias: "acl_drop"
                           annotations: "@sai_action(SAI_PACKET_ACTION_DROP)")pb"))
                  .const_default_action(
                      IrActionDefinitionBuilder().name("NoAction"))
                  .meter_unit(p4::config::v1::MeterSpec::BYTES)
                  .counter_unit(p4::config::v1::CounterSpec::BOTH)
                  .size(128))
          .action(IrActionDefinitionBuilder().preamble(
              R"pb(id: 100
                   name: "ingress.hashing.select_ecmp_hash_algorithm"
                   alias: "select_ecmp_hash_algorithm"
                   annotations: "@sai_hash_algorithm(SAI_HASH_ALGORITHM_CRC)"
                   annotations: "@sai_hash_seed(1)"
                   annotations: "@sai_hash_offset(2)")pb"))
          .action(IrActionDefinitionBuilder().preamble(
              R"pb(id: 101
                   name: "ingress.hashing.select_lag_hash_algorithm"
                   alias: "select_lag_hash_algorithm"
                   annotations: "@sai_hash_algorithm(SAI_HASH_ALGORITHM_CRC_32LO)"
                   annotations: "@sai_hash_seed(10)"
                   annotations: "@sai_hash_offset(20)")pb"))
          .action(IrActionDefinitionBuilder().preamble(
              R"pb(id: 102
                   name: "ingress.hashing.compute_ecmp_hash_ipv4"
                   alias: "compute_ecmp_hash_ipv4"
                   annotations: "@sai_ecmp_hash(SAI_SWITCH_ATTR_ECMP_HASH_IPV4)"
                   annotations: "@sai_native_hash_field(SAI_NATIVE_HASH_FIELD_SRC_IPV4)"
                   annotations: "@sai_native_hash_field(SAI_NATIVE_HASH_FIELD_DST_IPV4)")pb"))
          .action(IrActionDefinitionBuilder().preamble(
              R"pb(id: 103
                   name: "ingress.hashing.compute_lag_hash_ipv4"
                   alias: "compute_lag_hash_ipv4"
                   annotations: "@sai_lag_hash(SAI_SWITCH_ATTR_LAG_HASH_IPV4)"
                   annotations: "@sai_native_hash_field(SAI_NATIVE_HASH_FIELD_L4_SRC_PORT)"
                   annotations: "@sai_native_hash_field(SAI_NATIVE_HASH_FIELD_L4_DST_PORT)"
              )pb"))
          .action_profile(
              IrActionProfileDefinitionBuilder()
                  .name("action_profile1")
                  .wcmp_selector_size(/*size=*/20, /*max_group_size=*/5)())
          .action_profile(
              IrActionProfileDefinitionBuilder()
                  .name("action_profile2")
                  .wcmp_selector_size(/*size=*/30, /*max_group_size=*/4)())
          .action_profile(
              IrActionProfileDefinitionBuilder()
                  .name("action_profile3")
                  .wcmp_selector_size(/*size=*/40, /*max_group_size=*/3)())());
  return *kP4Info;
}

const absl::flat_hash_map<std::string, ActionProfileResourceCapacity>&
CapacityMapFromIrP4Info() {
  static const auto* const kCapacityMap = []() {
    auto* capacity_map =
        new absl::flat_hash_map<std::string, ActionProfileResourceCapacity>();
    for (const auto& [name, profile] :
         GetIrP4Info().action_profiles_by_name()) {
      capacity_map->insert({name, GetActionProfileResourceCapacity(profile)});
    }
    return capacity_map;
  }();

  return *kCapacityMap;
}

TEST(CalculateTransition, NoTransitionForSameIrP4Info) {
  ASSERT_OK_AND_ASSIGN(auto transition,
                       CalculateTransition(GetIrP4Info(), GetIrP4Info()));
  EXPECT_THAT(transition, TransitionIs({}));
}

TEST(CalculateTransition, CalculatesHashingPacketFieldModification) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto with_hash_diff = original;
  *with_hash_diff.mutable_actions_by_name()
       ->at("compute_lag_hash_ipv4")
       .mutable_preamble()
       ->mutable_annotations(2) =
      "sai_native_hash_field(SAI_NATIVE_HASH_FIELD_SRC_IPV4)";

  EXPECT_THAT(
      CalculateTransition(original, with_hash_diff),
      IsOkAndHolds(TransitionIs({
          .hashing_packet_field_configs_to_set = {"compute_lag_hash_ipv4"},
          .update_switch_table = true,
      })));

  EXPECT_THAT(
      CalculateTransition(with_hash_diff, original),
      IsOkAndHolds(TransitionIs({
          .hashing_packet_field_configs_to_set = {"compute_lag_hash_ipv4"},
          .update_switch_table = true,
      })));
}

TEST(CalculateTransition, CalculatesHashingPacketFieldDeletion) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto with_hash_diff = original;
  int id = with_hash_diff.actions_by_name()
               .at("compute_lag_hash_ipv4")
               .preamble()
               .id();
  with_hash_diff.mutable_actions_by_name()->erase("compute_lag_hash_ipv4");
  with_hash_diff.mutable_actions_by_id()->erase(id);

  ASSERT_OK_AND_ASSIGN(auto transition,
                       CalculateTransition(original, with_hash_diff));
  EXPECT_THAT(
      transition,
      TransitionIs({
          .hashing_packet_field_configs_to_delete = {"compute_lag_hash_ipv4"},
          .update_switch_table = true,
      }));
}

TEST(CalculateTransition, CalculatesHashingPacketFieldAddition) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto with_hash_diff = original;
  int id = with_hash_diff.actions_by_name()
               .at("compute_lag_hash_ipv4")
               .preamble()
               .id();
  with_hash_diff.mutable_actions_by_name()->erase("compute_lag_hash_ipv4");
  with_hash_diff.mutable_actions_by_id()->erase(id);

  ASSERT_OK_AND_ASSIGN(auto transition,
                       CalculateTransition(with_hash_diff, original));
  EXPECT_THAT(
      transition,
      TransitionIs({
          .hashing_packet_field_configs_to_set = {"compute_lag_hash_ipv4"},
          .update_switch_table = true,
      }));
}

// Erases tables that match the predicate from the IrP4Info. Returns the names
// of the removed tables.
std::vector<std::string> EraseTables(
    pdpi::IrP4Info& ir_p4info,
    absl::AnyInvocable<bool(const pdpi::IrTableDefinition&)> predicate) {
  std::vector<std::string> erased_tables;

  auto& tables_by_id = *ir_p4info.mutable_tables_by_id();
  auto& tables_by_name = *ir_p4info.mutable_tables_by_name();
  for (auto iter = tables_by_id.begin(); iter != tables_by_id.end();) {
    if (predicate(iter->second)) {
      iter = tables_by_id.erase(iter);
    } else {
      ++iter;
    }
  }
  for (auto iter = tables_by_name.begin(); iter != tables_by_name.end();) {
    if (predicate(iter->second)) {
      erased_tables.push_back(iter->first);
      iter = tables_by_name.erase(iter);
    } else {
      ++iter;
    }
  }
  return erased_tables;
}

bool EraseTable(pdpi::IrP4Info& ir_p4info, absl::string_view table_name) {
  return !EraseTables(ir_p4info, [table_name](
                                     const pdpi::IrTableDefinition& table) {
            return table.preamble().alias() == table_name;
          }).empty();
}

bool IsAclTable(const pdpi::IrTableDefinition& table) {
  return *GetTableType(table) == table::Type::kAcl;
}

TEST(CalculateTransition, CalculatesFullAclTableDeletion) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto without_acl_tables = original;
  std::vector<std::string> acl_tables =
      EraseTables(without_acl_tables, IsAclTable);

  EXPECT_THAT(CalculateTransition(original, without_acl_tables),
              IsOkAndHolds(TransitionIs(
                  {.acl_tables_to_delete = std::move(acl_tables)})));
}

TEST(CalculateTransition, CalculatesFullAclTableAddition) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto without_acl_tables = original;
  std::vector<std::string> acl_tables =
      EraseTables(without_acl_tables, IsAclTable);

  EXPECT_THAT(
      CalculateTransition(without_acl_tables, original),
      IsOkAndHolds(TransitionIs({.acl_tables_to_add = std::move(acl_tables)})));
}

TEST(CalculateTransition, CalculatesFullAclTableModification) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto modified_acl_tables = original;
  std::vector<std::string> acl_tables;
  for (auto& [name, table] : *modified_acl_tables.mutable_tables_by_name()) {
    if (!IsAclTable(table)) continue;
    acl_tables.push_back(name);
    if (table.has_meter()) {
      table.clear_meter();
    } else {
      table.mutable_meter()->set_unit(p4::config::v1::MeterSpec::BYTES);
    }
  }

  const P4InfoReconcileTransition expected_transition = {
      .nonessential_acl_tables_to_modify = {"acl_ingress_table_b",
                                            "acl_ingress_table_c"},
      .essential_acl_tables_to_modify = {"acl_ingress_table_a",
                                         "acl_ingress_table_d"},
  };

  EXPECT_THAT(CalculateTransition(original, modified_acl_tables),
              IsOkAndHolds(TransitionIs(expected_transition)));

  EXPECT_THAT(CalculateTransition(modified_acl_tables, original),
              IsOkAndHolds(TransitionIs(expected_transition)));
}

TEST(CalculateTransition, CalculatesPartialAclTableDeletion) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto with_fewer_tables = original;
  std::vector<std::string> removed_tables =
      EraseTables(with_fewer_tables, [](const pdpi::IrTableDefinition& table) {
        return table.preamble().alias() == "acl_ingress_table_a" ||
               table.preamble().alias() == "acl_ingress_table_c";
      });
  ASSERT_THAT(removed_tables, Not(IsEmpty()));

  EXPECT_THAT(CalculateTransition(original, with_fewer_tables),
              IsOkAndHolds(TransitionIs(
                  {.acl_tables_to_delete = std::move(removed_tables)})));
}

TEST(CalculateTransition, CalculatesPartialAclTableAddition) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto with_fewer_tables = original;
  std::vector<std::string> removed_tables =
      EraseTables(with_fewer_tables, [](const pdpi::IrTableDefinition& table) {
        return table.preamble().alias() == "acl_ingress_table_a" ||
               table.preamble().alias() == "acl_ingress_table_c";
      });
  ASSERT_THAT(removed_tables, Not(IsEmpty()));

  EXPECT_THAT(CalculateTransition(with_fewer_tables, original),
              IsOkAndHolds(TransitionIs(
                  {.acl_tables_to_add = std::move(removed_tables)})));
}

TEST(CalculateTransition, CalculatesPartialAclTableModification) {
  const pdpi::IrP4Info original = GetIrP4Info();
  auto modified_acl_tables = original;
  std::vector<std::string> modified_tables;
  for (auto& [name, table] : *modified_acl_tables.mutable_tables_by_name()) {
    if (!IsAclTable(table) ||
        table.preamble().alias() == "acl_ingress_table_b" ||
        table.preamble().alias() == "acl_ingress_table_d") {
      continue;
    }
    modified_tables.push_back(name);
    if (table.has_meter()) {
      table.clear_meter();
    } else {
      table.mutable_meter()->set_unit(p4::config::v1::MeterSpec::BYTES);
    }
  }
  ASSERT_THAT(modified_tables, Not(IsEmpty()));

  P4InfoReconcileTransition expected_transition = {
      .nonessential_acl_tables_to_modify = {"acl_ingress_table_c"},
      .essential_acl_tables_to_modify = {"acl_ingress_table_a"},
  };
  EXPECT_THAT(CalculateTransition(original, modified_acl_tables),
              IsOkAndHolds(TransitionIs(expected_transition)));

  EXPECT_THAT(CalculateTransition(modified_acl_tables, original),
              IsOkAndHolds(TransitionIs(expected_transition)));
}

TEST(CalculateTransition, CanForceTransitionForUnmodifiedAclTable) {
  pdpi::IrP4Info new_p4info = GetIrP4Info();
  new_p4info.mutable_tables_by_name()
      ->at("acl_ingress_table_b")
      .mutable_preamble()
      ->add_annotations("@reinstall_during_upgrade");
  new_p4info.mutable_tables_by_name()
      ->at("acl_ingress_table_d")
      .mutable_preamble()
      ->add_annotations("@reinstall_during_upgrade");

  P4InfoReconcileTransition expected_transition = {
      .nonessential_acl_tables_to_modify = {"acl_ingress_table_b"},
      .essential_acl_tables_to_modify = {"acl_ingress_table_d"},
  };
  EXPECT_THAT(CalculateTransition(GetIrP4Info(), new_p4info),
              IsOkAndHolds(TransitionIs(expected_transition)));
  EXPECT_THAT(CalculateTransition(new_p4info, GetIrP4Info()),
              IsOkAndHolds(TransitionIs({})));
}

TEST(CalculateTransition, IgnoresFixedTableDeletion) {
  const pdpi::IrP4Info original = GetIrP4Info();
  pdpi::IrP4Info without_fixed_tables = original;
  ASSERT_TRUE(EraseTable(without_fixed_tables, "fixed_table_a"));
  ASSERT_TRUE(EraseTable(without_fixed_tables, "fixed_table_b"));
  EXPECT_THAT(CalculateTransition(original, without_fixed_tables),
              IsOkAndHolds(TransitionIs({})));
}

TEST(CalculateTransition, IgnoresFixedTableAddition) {
  const pdpi::IrP4Info original = GetIrP4Info();
  pdpi::IrP4Info without_fixed_tables = original;
  ASSERT_TRUE(EraseTable(without_fixed_tables, "fixed_table_a"));
  ASSERT_TRUE(EraseTable(without_fixed_tables, "fixed_table_b"));
  EXPECT_THAT(CalculateTransition(without_fixed_tables, original),
              IsOkAndHolds(TransitionIs({})));
}

TEST(CalculateTransition, IgnoresFixedTableModification) {
  const pdpi::IrP4Info original = GetIrP4Info();
  pdpi::IrP4Info with_modified_fixed_tables = original;
  auto action = IrActionDefinitionBuilder().name("new_action")();
  *with_modified_fixed_tables.mutable_tables_by_name()
       ->at("fixed_table_a")
       .add_entry_actions()
       ->mutable_action() = action;
  *with_modified_fixed_tables.mutable_tables_by_id()
       ->at(with_modified_fixed_tables.tables_by_name()
                .at("fixed_table_a")
                .preamble()
                .id())
       .add_entry_actions()
       ->mutable_action() = action;

  EXPECT_THAT(CalculateTransition(with_modified_fixed_tables, original),
              IsOkAndHolds(TransitionIs({})));
}

TEST(CalculateTransition, CalculatesComplexTransition) {
  pdpi::IrP4Info original = GetIrP4Info();
  auto modified = original;

  // Erase some tables from the original IrP4Info. These will appear to be added
  // in the modified P4Info.
  ASSERT_TRUE(EraseTable(original, "acl_ingress_table_d"));
  ASSERT_TRUE(EraseTable(original, "fixed_table_a"));

  // Modify modified table.
  ASSERT_TRUE(EraseTable(modified, "acl_ingress_table_a"));
  ASSERT_TRUE(EraseTable(modified, "fixed_table_b"));
  modified.mutable_tables_by_name()
      ->at("acl_ingress_table_b")
      .mutable_entry_actions(0)
      ->mutable_action()
      ->mutable_preamble()
      ->set_alias("I am a different action");
  modified.mutable_tables_by_id()
      ->at(modified.tables_by_name().at("acl_ingress_table_b").preamble().id())
      .mutable_entry_actions(0)
      ->mutable_action()
      ->mutable_preamble()
      ->set_alias("I am a different action");
  modified.mutable_actions_by_id()->erase(
      modified.actions_by_name().at("compute_lag_hash_ipv4").preamble().id());
  modified.mutable_actions_by_name()->erase("compute_lag_hash_ipv4");

  EXPECT_THAT(
      CalculateTransition(original, modified),
      IsOkAndHolds(TransitionIs({
          .hashing_packet_field_configs_to_delete = {"compute_lag_hash_ipv4"},
          .update_switch_table = true,
          .acl_tables_to_delete = {"acl_ingress_table_a"},
          .acl_tables_to_add = {"acl_ingress_table_d"},
          .nonessential_acl_tables_to_modify = {"acl_ingress_table_b"},
      })));

  EXPECT_THAT(
      CalculateTransition(modified, original),
      IsOkAndHolds(TransitionIs({
          .hashing_packet_field_configs_to_set = {"compute_lag_hash_ipv4"},
          .update_switch_table = true,
          .acl_tables_to_delete = {"acl_ingress_table_d"},
          .acl_tables_to_add = {"acl_ingress_table_a"},
          .nonessential_acl_tables_to_modify = {"acl_ingress_table_b"},
      })));
}

TEST(CalculateTransition, ReturnsErrorForBadAclTable) {
  const pdpi::IrP4Info original = GetIrP4Info();
  pdpi::IrP4Info modified = original;
  auto& table = modified.mutable_tables_by_name()->at("acl_ingress_table_a");
  table.clear_match_fields_by_name();
  table.clear_match_fields_by_id();
  table = modified.mutable_tables_by_id()->at(table.preamble().id());
  table.clear_match_fields_by_name();
  table.clear_match_fields_by_id();

  EXPECT_THAT(CalculateTransition(original, modified),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(CalculateTransition(modified, original),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(CalculateTransition, ReturnsErrorForBadHashSetting) {
  const pdpi::IrP4Info original = GetIrP4Info();
  pdpi::IrP4Info modified = original;
  auto& action =
      modified.mutable_actions_by_name()->at("select_ecmp_hash_algorithm");
  action.mutable_preamble()->clear_annotations();
  action.mutable_preamble()->add_annotations("@sai_hash_algorithm(FakeAlg)");
  modified.mutable_actions_by_id()->at(action.preamble().id()) = action;

  EXPECT_THAT(CalculateTransition(original, modified),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(CalculateTransition(modified, original),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(CalculateTransition, ReturnsFailedPreconditionForAclStageTransition) {
  const pdpi::IrP4Info original = GetIrP4Info();
  pdpi::IrP4Info modified = original;
  auto& table = modified.mutable_tables_by_name()->at("acl_ingress_table_a");
  *table.mutable_preamble()->mutable_annotations(0) = "@sai_acl(EGRESS)";

  EXPECT_THAT(CalculateTransition(original, modified),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(CalculateTransition(modified, original),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(GetUpdatedResourceCapacities, ReturnsBasicCapacityWithNoOriginal) {
  const pdpi::IrP4Info& p4_info = GetIrP4Info();
  ASSERT_OK_AND_ASSIGN(auto updated_capacities,
                       GetUpdatedResourceCapacities(p4_info, {}));
  ASSERT_THAT(updated_capacities,
              SizeIs(p4_info.action_profiles_by_id().size()));
  std::vector<std::pair<std::string, ActionProfileResourceCapacity>>
      raw_capacities;
  for (const auto& [profile_name, profile_def] :
       p4_info.action_profiles_by_name()) {
    raw_capacities.push_back(
        {profile_name, GetActionProfileResourceCapacity(profile_def)});
  }
  EXPECT_THAT(updated_capacities,
              UnorderedPointwise(CapacityEntryEq(), raw_capacities));
}

TEST(GetUpdatedResourceCapacities, ReturnsEmptyWithNoActionProfiles) {
  ASSERT_THAT(GetUpdatedResourceCapacities(pdpi::IrP4Info(), {}),
              IsOkAndHolds(IsEmpty()));
}

struct CapacityCreatorEntry {
  pdpi::IrActionProfileDefinition action_profile;
  int current_total_weight;
};

absl::flat_hash_map<std::string, ActionProfileResourceCapacity>
GetNameToCapacityMap(absl::Span<const CapacityCreatorEntry> capacity_entries) {
  absl::flat_hash_map<std::string, ActionProfileResourceCapacity>
      capacity_by_name;
  for (const auto& capacity_entry : capacity_entries) {
    capacity_by_name
        [capacity_entry.action_profile.action_profile().preamble().name()] =
            GetActionProfileResourceCapacity(capacity_entry.action_profile);
    capacity_by_name
        [capacity_entry.action_profile.action_profile().preamble().name()]
            .current_total_weight = capacity_entry.current_total_weight;
  }
  return capacity_by_name;
}

TEST(GetUpdatedResourceCapacities, UpdatesCapacity) {
  absl::flat_hash_map<std::string, ActionProfileResourceCapacity> original =
      GetNameToCapacityMap({
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile1")
                      .wcmp_selector_size(/*size=*/10, /*max_group_size=*/1)(),
          },
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile2")
                      .wcmp_selector_size(/*size=*/20, /*max_group_size=*/2)(),
          },
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile3")
                      .wcmp_selector_size(/*size=*/30, /*max_group_size=*/3)(),
          },
      });
  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              IsOkAndHolds(UnorderedPointwise(CapacityEntryEq(),
                                              CapacityMapFromIrP4Info())));
}

TEST(GetUpdatedResourceCapacities,
     UpdatesCapacityAndMaintainsCurrentResourceCounts) {
  absl::flat_hash_map<std::string, ActionProfileResourceCapacity> original =
      GetNameToCapacityMap({
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile1")
                      .wcmp_selector_size(/*size=*/10, /*max_group_size=*/1)(),
              .current_total_weight = 10,
          },
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile2")
                      .wcmp_selector_size(/*size=*/20, /*max_group_size=*/2)(),
              .current_total_weight = 11,
          },
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile3")
                      .wcmp_selector_size(/*size=*/30, /*max_group_size=*/3)(),
              .current_total_weight = 12,
          },
      });

  absl::flat_hash_map<std::string, ActionProfileResourceCapacity> expected =
      CapacityMapFromIrP4Info();
  for (const auto& [name, capacity] : CapacityMapFromIrP4Info()) {
    expected[name].current_total_weight =
        original.at(name).current_total_weight;
  }

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              IsOkAndHolds(UnorderedPointwise(CapacityEntryEq(), expected)));
}

TEST(GetUpdatedResourceCapacities, DoesNotIncludeRemovedProfiles) {
  auto original = CapacityMapFromIrP4Info();
  original["removed_action_profile4"].action_profile.set_max_group_size(4);
  original["removed_action_profile4"].action_profile.set_size(40);
  original["removed_action_profile5"].action_profile.set_max_group_size(5);
  original["removed_action_profile5"].action_profile.set_size(50);

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              IsOkAndHolds(UnorderedPointwise(CapacityEntryEq(),
                                              CapacityMapFromIrP4Info())));
}

TEST(GetUpdatedResourceCapacities, UsesBaseCapacity0ForAddedProfiles) {
  absl::flat_hash_map<std::string, ActionProfileResourceCapacity> original =
      GetNameToCapacityMap({
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile1")
                      .wcmp_selector_size(/*size=*/10, /*max_group_size=*/1)(),
              .current_total_weight = 10,
          },
          {
              .action_profile =
                  IrActionProfileDefinitionBuilder()
                      .name("action_profile3")
                      .wcmp_selector_size(/*size=*/30, /*max_group_size=*/3)(),
              .current_total_weight = 12,
          },
      });

  auto expected = CapacityMapFromIrP4Info();
  expected.at("action_profile1").current_total_weight = 10;
  expected.at("action_profile2").current_total_weight = 0;
  expected.at("action_profile3").current_total_weight = 12;

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              IsOkAndHolds(UnorderedPointwise(CapacityEntryEq(), expected)));
}

TEST(GetUpdatedResourceCapacities,
     DoesNotAllowShrinkingMaxGroupSizeForProfilesInUse) {
  auto original = CapacityMapFromIrP4Info();
  original.at("action_profile2").current_total_weight = 1;
  original.at("action_profile2")
      .action_profile.set_max_group_size(
          original.at("action_profile2").action_profile.max_group_size() + 1);

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(GetUpdatedResourceCapacities,
     AllowsShrinkingMaxGroupSizeForProfilesNotInUse) {
  auto original = CapacityMapFromIrP4Info();
  original.at("action_profile2")
      .action_profile.set_max_group_size(
          original.at("action_profile2").action_profile.max_group_size() + 1);

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              IsOkAndHolds(UnorderedPointwise(CapacityEntryEq(),
                                              CapacityMapFromIrP4Info())));
}

TEST(GetUpdatedResourceCapacities, DoesNotAllowShrinkingCapacityBelowUsage) {
  auto original = CapacityMapFromIrP4Info();
  original.at("action_profile2").current_total_weight =
      original.at("action_profile2").action_profile.size() + 1;
  original.at("action_profile2")
      .action_profile.set_size(
          original.at("action_profile2").action_profile.size() + 2);

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(GetUpdatedResourceCapacities, DoesAllowShrinkingCapacityToCurrentUsage) {
  auto original = CapacityMapFromIrP4Info();
  for (auto& [_, capacity] : original) {
    capacity.current_total_weight = capacity.action_profile.size();
    capacity.action_profile.set_size(capacity.action_profile.size() + 1);
  }
  auto expected = CapacityMapFromIrP4Info();
  for (auto& [_, capacity] : expected) {
    capacity.current_total_weight = capacity.action_profile.size();
  }

  EXPECT_THAT(GetUpdatedResourceCapacities(GetIrP4Info(), original),
              IsOkAndHolds(UnorderedPointwise(CapacityEntryEq(), expected)));
}

}  // namespace
}  // namespace p4rt_app
