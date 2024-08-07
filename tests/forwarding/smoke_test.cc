// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tests/forwarding/smoke_test.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "google/protobuf/util/message_differencer.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "gutil/status_matchers.h"
#include "gutil/testing.h"
#include "lib/gnmi/gnmi_helper.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/p4_runtime_session_extras.h"
#include "p4_pdpi/pd.h"
#include "sai_p4/instantiations/google/sai_pd.pb.h"
#include "sai_p4/instantiations/google/test_tools/test_entries.h"
#include "tests/forwarding/test_data.h"
#include "tests/lib/p4rt_fixed_table_programming_helper.h"
#include "tests/lib/switch_test_setup_helpers.h"
#include "thinkit/mirror_testbed.h"
#include "thinkit/test_environment.h"

namespace pins_test {
namespace {

using ::gutil::EqualsProto;
using ::gutil::IsOk;
using ::testing::ElementsAre;
using ::testing::Not;

TEST_P(SmokeTestFixture, CanEstablishConnections) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  ASSERT_NE(sut_p4rt_session, nullptr);
  ASSERT_NE(control_switch_p4rt_session, nullptr);
}

TEST_P(SmokeTestFixture, AclTableAddModifyDeleteOk) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  testbed.Environment().SetTestCaseID("3b18d5dc-3881-42a5-b667-d2ca0362ab3a");
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  const sai::WriteRequest pd_insert = gutil::ParseProtoOrDie<sai::WriteRequest>(
      R"pb(
        updates {
          type: INSERT
          table_entry {
            acl_ingress_table_entry {
              match { is_ip { value: "0x1" } }
              priority: 10
              action { acl_copy { qos_queue: "0x1" } }
            }
          }
        }
      )pb");
  ASSERT_OK_AND_ASSIGN(p4::v1::WriteRequest pi_insert,
                       pdpi::PdWriteRequestToPi(ir_p4info, pd_insert));

  const sai::WriteRequest pd_modify = gutil::ParseProtoOrDie<sai::WriteRequest>(
      R"pb(
        updates {
          type: MODIFY
          table_entry {
            acl_ingress_table_entry {
              match { is_ip { value: "0x1" } }
              priority: 10
              action { acl_forward {} }
            }
          }
        }
      )pb");
  ASSERT_OK_AND_ASSIGN(p4::v1::WriteRequest pi_modify,
                       pdpi::PdWriteRequestToPi(ir_p4info, pd_modify));

  const sai::WriteRequest pd_delete = gutil::ParseProtoOrDie<sai::WriteRequest>(
      R"pb(
        updates {
          type: DELETE
          table_entry {
            acl_ingress_table_entry {
              match { is_ip { value: "0x1" } }
              priority: 10
              action { acl_forward {} }
            }
          }
        }
      )pb");
  ASSERT_OK_AND_ASSIGN(p4::v1::WriteRequest pi_delete,
                       pdpi::PdWriteRequestToPi(ir_p4info, pd_delete));

  // Insert works.
  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_insert));

  // ACL table entries are expected to contain counter data. However, it's
  // updated periodically and may not be avaialable immediatly after writing so
  // we poll the entry for a few seconds until we see the data.
  absl::Time timeout = absl::Now() + absl::Seconds(11);
  p4::v1::ReadResponse pi_read_response;
  p4::v1::ReadRequest pi_read_request;
  pi_read_request.add_entities()->mutable_table_entry();
  do {
    ASSERT_OK_AND_ASSIGN(pi_read_response,
                         pdpi::SetMetadataAndSendPiReadRequest(
                             sut_p4rt_session.get(), pi_read_request));
    ASSERT_EQ(pi_read_response.entities_size(), 1);

    if (absl::Now() > timeout) {
      FAIL() << "ACL table entry does not have counter data.";
    }
  } while (!pi_read_response.entities(0).table_entry().has_counter_data());

  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_modify));

  // Delete works.
  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_delete));
}

TEST_P(SmokeTestFixture, FixedTableAddModifyDeleteOk) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  p4::v1::WriteRequest pi_request;
  ASSERT_OK_AND_ASSIGN(
      *pi_request.add_updates(),
      gpins::VrfTableUpdate(ir_p4info, p4::v1::Update::INSERT, "vrf-1"));
  ASSERT_OK_AND_ASSIGN(
      *pi_request.add_updates(),
      gpins::RouterInterfaceTableUpdate(ir_p4info, p4::v1::Update::INSERT,
                                        "router-intf-1", /*port=*/"1",
                                        /*src_mac=*/"00:01:02:03:04:05"));
  ASSERT_OK_AND_ASSIGN(*pi_request.add_updates(),
                       gpins::NeighborTableUpdate(
                           ir_p4info, p4::v1::Update::INSERT, "router-intf-1",
                           /*neighbor_id=*/"fe80::0000:00ff:fe17:5f80",
                           /*dst_mac=*/"00:01:02:03:04:06"));
  ASSERT_OK_AND_ASSIGN(
      *pi_request.add_updates(),
      gpins::NexthopTableUpdate(ir_p4info, p4::v1::Update::INSERT, "nexthop-1",
                                "router-intf-1",
                                /*neighbor_id=*/"fe80::0000:00ff:fe17:5f80"));
  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_request));

  // Add and modify IPV4 table entry with different number of action params.
  pi_request.Clear();
  ASSERT_OK_AND_ASSIGN(
      *pi_request.add_updates(),
      gpins::Ipv4TableUpdate(
          ir_p4info, p4::v1::Update::INSERT,
          gpins::IpTableOptions{
              .vrf_id = "vrf-1",
              .dst_addr_lpm = std::make_pair("20.0.0.1", 32),
              .action = gpins::IpTableOptions::Action::kSetNextHopId,
              .nexthop_id = "nexthop-1",
          }));
  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_request));
  pi_request.Clear();
  ASSERT_OK_AND_ASSIGN(
      *pi_request.add_updates(),
      gpins::Ipv4TableUpdate(ir_p4info, p4::v1::Update::MODIFY,
                             gpins::IpTableOptions{
                                 .vrf_id = "vrf-1",
                                 .dst_addr_lpm = std::make_pair("20.0.0.1", 32),
                                 .action = gpins::IpTableOptions::Action::kDrop,
                             }));
  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_request));

  pi_request.Clear();
  ASSERT_OK_AND_ASSIGN(
      *pi_request.add_updates(),
      gpins::Ipv4TableUpdate(ir_p4info, p4::v1::Update::DELETE,
                             gpins::IpTableOptions{
                                 .vrf_id = "vrf-1",
                                 .dst_addr_lpm = std::make_pair("20.0.0.1", 32),
                                 .action = gpins::IpTableOptions::Action::kDrop,
                             }));
  ASSERT_OK(pdpi::SetMetadataAndSendPiWriteRequest(sut_p4rt_session.get(),
                                                   pi_request));

  // This used to fail with a read error, see b/185508142.
  ASSERT_OK(pdpi::ClearTableEntries(sut_p4rt_session.get()));
}

// TODO: Enable once the bug is fixed.
TEST_P(SmokeTestFixture, DISABLED_Bug181149419) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  testbed.Environment().SetTestCaseID("e6ba12b7-18e0-4681-9562-87e2fc01d429");
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  // Adding 8 mirror sessions should succeed.
  for (int i = 0; i < 8; i++) {
    sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
        R"pb(
          mirror_session_table_entry {
            match { mirror_session_id: "session" }
            action {
              mirror_as_ipv4_erspan {
                port: "1"
                src_ip: "10.206.196.0"
                dst_ip: "172.20.0.202"
                src_mac: "00:02:03:04:05:06"
                dst_mac: "00:1a:11:17:5f:80"
                ttl: "0x40"
                tos: "0x00"
              }
            }
          }
        )pb");
    pd_entry.mutable_mirror_session_table_entry()
        ->mutable_match()
        ->set_mirror_session_id(absl::StrCat("session-", i));

    ASSERT_OK_AND_ASSIGN(
        const p4::v1::TableEntry pi_entry,
        pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));
    EXPECT_OK(pdpi::InstallPiTableEntry(sut_p4rt_session.get(), pi_entry));
  }
  // Adding one entry above the limit will fail.
  {
    sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
        R"pb(
          mirror_session_table_entry {
            match { mirror_session_id: "session-9" }
            action {
              mirror_as_ipv4_erspan {
                port: "1"
                src_ip: "10.206.196.0"
                dst_ip: "172.20.0.202"
                src_mac: "00:02:03:04:05:06"
                dst_mac: "00:1a:11:17:5f:80"
                ttl: "0x40"
                tos: "0x00"
              }
            }
          }
        )pb");

    ASSERT_OK_AND_ASSIGN(
        const p4::v1::TableEntry pi_entry,
        pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));
    EXPECT_FALSE(
        pdpi::InstallPiTableEntry(sut_p4rt_session.get(), pi_entry).ok());
  }
  // Adding ACL entries that use the 8 mirrors should all succeed.
  for (int i = 0; i < 8; i++) {
    sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
        R"pb(
          acl_ingress_table_entry {
            match {
              is_ipv4 { value: "0x1" }
              src_ip { value: "10.0.0.0" mask: "255.255.255.255" }
              dscp { value: "0x1c" mask: "0x3c" }
            }
            action { mirror { mirror_session_id: "session-1" } }
            priority: 2100
          }
        )pb");
    pd_entry.mutable_acl_ingress_table_entry()
        ->mutable_action()
        ->mutable_acl_mirror()
        ->set_mirror_session_id(absl::StrCat("session-", i));
    pd_entry.mutable_acl_ingress_table_entry()
        ->mutable_match()
        ->mutable_src_ip()
        ->set_value(absl::StrCat("10.0.0.", i));

    ASSERT_OK_AND_ASSIGN(
        const p4::v1::TableEntry pi_entry,
        pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));
    ASSERT_OK(pdpi::InstallPiTableEntry(sut_p4rt_session.get(), pi_entry));
  }
}

TEST_P(SmokeTestFixture, InsertTableEntry) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  testbed.Environment().SetTestCaseID("da103fbb-8fd4-4385-b997-34e12a41004b");
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  const sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
      R"pb(
        router_interface_table_entry {
          match { router_interface_id: "router-interface-1" }
          action {
            set_port_and_src_mac { port: "1" src_mac: "02:2a:10:00:00:03" }
          }
        }
      )pb");

  ASSERT_OK_AND_ASSIGN(
      const p4::v1::TableEntry pi_entry,
      pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));
  ASSERT_OK(pdpi::InstallPiTableEntry(sut_p4rt_session.get(), pi_entry));
}

TEST_P(SmokeTestFixture, InsertTableEntryWithRandomCharacterId) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  testbed.Environment().SetTestCaseID("bd22f5fe-4103-4729-91d0-cb2bc8258940");
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
      R"pb(
        router_interface_table_entry {
          match { router_interface_id: "\x01\x33\x00\xff,\":'}(*{+-" }
          action {
            set_port_and_src_mac { port: "1" src_mac: "02:2a:10:00:00:03" }
          }
        }
      )pb");

  ASSERT_OK_AND_ASSIGN(
      const p4::v1::TableEntry pi_entry,
      pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));
  EXPECT_OK(pdpi::InstallPiTableEntry(sut_p4rt_session.get(), pi_entry));

  ASSERT_OK_AND_ASSIGN(auto entries,
                       pdpi::ReadPiTableEntries(sut_p4rt_session.get()));
  EXPECT_THAT(entries, ElementsAre(EqualsProto(pi_entry)));

  // An auxiliary RedisDB tool that takes a snapshot of the database has issues
  // with reading non-UTF-8 compliant characters. This is only used for
  // debugging in testing, so we just clear the SUT table before finishing the
  // test to avoid the problem.
  ASSERT_OK(pdpi::ClearTableEntries(sut_p4rt_session.get()));
}

TEST_P(SmokeTestFixture, InsertAndReadTableEntries) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  testbed.Environment().SetTestCaseID("8bdacde4-b261-4242-b65d-462c828a427d");
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  std::vector<sai::TableEntry> write_pd_entries =
      sai_pd::CreateUpTo255GenericTableEntries(3);

  thinkit::TestEnvironment& test_environment = testbed.Environment();
  std::vector<p4::v1::TableEntry> write_pi_entries;
  p4::v1::ReadResponse expected_read_response;
  write_pi_entries.reserve(write_pd_entries.size());
  for (const auto& pd_entry : write_pd_entries) {
    ASSERT_OK_AND_ASSIGN(
        p4::v1::TableEntry pi_entry,
        pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));

    ASSERT_OK(test_environment.AppendToTestArtifact(
        "pi_entries_written.pb.txt",
        absl::StrCat(pi_entry.DebugString(), "\n")));
    *expected_read_response.add_entities()->mutable_table_entry() = pi_entry;
    write_pi_entries.push_back(std::move(pi_entry));
  }

  ASSERT_OK(pdpi::InstallPiTableEntries(sut_p4rt_session.get(), ir_p4info,
                                        write_pi_entries));

  p4::v1::ReadRequest read_request;
  read_request.add_entities()->mutable_table_entry();
  ASSERT_OK_AND_ASSIGN(p4::v1::ReadResponse read_response,
                       pdpi::SetMetadataAndSendPiReadRequest(
                           sut_p4rt_session.get(), read_request));

  for (const auto& entity : read_response.entities()) {
    ASSERT_OK(test_environment.AppendToTestArtifact(
        "pi_entries_read_back.pb.txt",
        absl::StrCat(entity.table_entry().DebugString(), "\n")));
  }

  // Compare the result in proto format since the fields being compared are
  // nested and out of order. Also ignore any dynamic fields (e.g. counters).
  google::protobuf::util::MessageDifferencer diff;
  diff.set_repeated_field_comparison(
      google::protobuf::util::MessageDifferencer::RepeatedFieldComparison::
          AS_SET);
  diff.IgnoreField(
      p4::v1::TableEntry::descriptor()->FindFieldByName("counter_data"));
  EXPECT_TRUE(diff.Compare(read_response, expected_read_response))
      << "Expected: " << expected_read_response.DebugString()
      << "\nActual: " << read_response.DebugString();
}

// Ensures that both CreateWithP4InfoAndClearTables and ClearTableEntries
// properly clear the table entries of a table.
TEST_P(SmokeTestFixture, EnsureClearTables) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  // The table should be clear after setup.
  ASSERT_OK(pdpi::CheckNoTableEntries(sut_p4rt_session.get()));

  // Sets up an example table entry.
  const sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
      R"pb(
        router_interface_table_entry {
          match { router_interface_id: "router-interface-1" }
          action {
            set_port_and_src_mac { port: "1" src_mac: "02:2a:10:00:00:03" }
          }
        }
      )pb");
  ASSERT_OK_AND_ASSIGN(
      p4::v1::TableEntry pi_entry,
      pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));

  ASSERT_OK(pdpi::InstallPiTableEntries(sut_p4rt_session.get(), ir_p4info,
                                        {pi_entry}));

  ASSERT_OK(pdpi::ClearTableEntries(sut_p4rt_session.get()));
  // The table should be clear after clearing.
  ASSERT_OK(pdpi::CheckNoTableEntries(sut_p4rt_session.get()));

  ASSERT_OK(pdpi::InstallPiTableEntries(sut_p4rt_session.get(), ir_p4info,
                                        {pi_entry}));

  ASSERT_OK_AND_ASSIGN(
      auto session2,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.Sut(), /*gnmi_config=*/std::nullopt, GetParam().p4info));

  // The table should be clear for both sessions after setting up a new session.
  ASSERT_OK(pdpi::CheckNoTableEntries(sut_p4rt_session.get()));
  ASSERT_OK(pdpi::CheckNoTableEntries(session2.get()));
}

// Ensures that a GNMI Config can be pushed even with programmed flows already
// on the switch.
// TODO: Re-enable once pushing a config from the switch, to the
// switch is supported.
TEST_P(SmokeTestFixture, DISABLED_PushGnmiConfigWithFlows) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  // All tables should be clear after setup.
  ASSERT_OK(pdpi::CheckNoTableEntries(sut_p4rt_session.get()));

  // Get a gNMI config from the switch to use for testing.
  ASSERT_OK_AND_ASSIGN(auto sut_gnmi_stub, testbed.Sut().CreateGnmiStub());
  ASSERT_OK_AND_ASSIGN(std::string sut_gnmi_config,
                       pins_test::GetGnmiConfig(*sut_gnmi_stub));

  // Pushing a Gnmi Config is OK when tables are cleared.
  ASSERT_OK(pins_test::PushGnmiConfig(testbed.Sut(), sut_gnmi_config));

  // Sets up an example table entry.
  const sai::TableEntry pd_entry = gutil::ParseProtoOrDie<sai::TableEntry>(
      R"pb(
        router_interface_table_entry {
          match { router_interface_id: "router-interface-1" }
          action {
            set_port_and_src_mac { port: "1" src_mac: "02:2a:10:00:00:03" }
          }
        }
      )pb");
  ASSERT_OK_AND_ASSIGN(
      p4::v1::TableEntry pi_entry,
      pdpi::PartialPdTableEntryToPiTableEntry(ir_p4info, pd_entry));

  ASSERT_OK(pdpi::InstallPiTableEntries(sut_p4rt_session.get(), ir_p4info,
                                        {pi_entry}));

  // Pushing the same Gnmi Config is also OK when entries are programmed.
  ASSERT_OK(pins_test::PushGnmiConfig(testbed.Sut(), sut_gnmi_config));
}

TEST_P(SmokeTestFixture, DeleteReferencedEntryNotOk) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info ir_p4info,
                       pdpi::CreateIrP4Info(GetParam().p4info));

  // Initialize the connection, clear table entries, and push GNMI
  // configuration (if given) for the SUT and Control switch.
  std::unique_ptr<pdpi::P4RuntimeSession> sut_p4rt_session,
      control_switch_p4rt_session;
  ASSERT_OK_AND_ASSIGN(
      std::tie(sut_p4rt_session, control_switch_p4rt_session),
      pins_test::ConfigureSwitchPairAndReturnP4RuntimeSessionPair(
          testbed.Sut(), testbed.ControlSwitch(), GetParam().gnmi_config,
          GetParam().p4info));

  constexpr absl::string_view kRifId = "rif";
  constexpr absl::string_view kNeighborId = "::1";

  ASSERT_OK_AND_ASSIGN(
      p4::v1::Update insert_and_delete_neighbor_update,
      gpins::NeighborTableUpdate(ir_p4info, p4::v1::Update::INSERT, kRifId,
                                 kNeighborId, /*dst_mac=*/"01:02:03:04:05:06"));
  ASSERT_OK_AND_ASSIGN(const p4::v1::Update rif_update,
                       gpins::RouterInterfaceTableUpdate(
                           ir_p4info, p4::v1::Update::INSERT, kRifId,
                           /*port=*/"1", /*src_mac=*/"00:02:03:04:05:06"));

  // Install RIF then Neighbor entries.
  ASSERT_OK(pdpi::SendPiUpdates(
      sut_p4rt_session.get(), {rif_update, insert_and_delete_neighbor_update}));

  // Install either a tunnel or a nexthop depending on if tunnels are supported.
  if (GetParam().does_not_support_gre_tunnels) {
    ASSERT_OK_AND_ASSIGN(
        const p4::v1::Update nexthop_update,
        gpins::NexthopTableUpdate(ir_p4info, p4::v1::Update::INSERT,
                                  /*nexthop_id=*/"nid", kRifId, kNeighborId));
    ASSERT_OK(pdpi::SendPiUpdates(sut_p4rt_session.get(), {nexthop_update}));
  } else {
    ASSERT_OK_AND_ASSIGN(
        const p4::v1::Update tunnel_update,
        gpins::TunnelTableUpdate(
            ir_p4info, p4::v1::Update::INSERT, /*tunnel_id=*/"tid",
            /*encap_dst_ip=*/kNeighborId, /*encap_src_ip=*/"::2", kRifId));
    ASSERT_OK(pdpi::SendPiUpdates(sut_p4rt_session.get(), {tunnel_update}));
  }

  // Cannot delete the neighbor table entry because it is used by the tunnel
  // entry or the nexthop entry.
  insert_and_delete_neighbor_update.set_type(p4::v1::Update::DELETE);
  EXPECT_THAT(pdpi::SendPiUpdates(sut_p4rt_session.get(),
                                  {insert_and_delete_neighbor_update}),
              Not(IsOk()));

  // We should always be able to re-install entries read from the switch.
  // Otherwise, the switch is in a corrupted state.
  ASSERT_OK_AND_ASSIGN(const pdpi::IrTableEntries read_entries,
                       pdpi::ReadIrTableEntries(*sut_p4rt_session));
  ASSERT_OK(pdpi::ClearEntities(*sut_p4rt_session));
  EXPECT_OK(pdpi::InstallIrTableEntries(*sut_p4rt_session, read_entries));
}

// Check that unicast routes with a multicast destination range are accepted by
// the switch. We may disallow this via a p4-constraint in the future, but need
// the capability as a temporary workaround as of 2023-12-08.
TEST_P(SmokeTestFixture, CanInstallIpv4TableEntriesWithMulticastDstIp) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<pdpi::P4RuntimeSession> sut,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.Sut(), GetParam().gnmi_config, GetParam().p4info));
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info p4info, pdpi::GetIrP4Info(*sut));
  ASSERT_OK_AND_ASSIGN(
      std::vector<p4::v1::Entity> pi_entities,
      sai::EntryBuilder().AddVrfEntry("vrf").GetDedupedPiEntities(p4info));
  ASSERT_OK(pdpi::InstallPiEntities(sut.get(), p4info, pi_entities));
  ASSERT_OK(pdpi::InstallPdTableEntries<sai::TableEntries>(*sut, R"pb(
    entries {
      ipv4_table_entry {
        match {
          vrf_id: "vrf"
          ipv4_dst { value: "224.0.0.0" prefix_length: 8 }
        }
        action { drop {} }
      }
    }
    entries {
      ipv4_table_entry {
        match {
          vrf_id: "vrf"
          ipv4_dst { value: "224.2.3.4" prefix_length: 32 }
        }
        action { drop {} }
      }
    }
  )pb"));
}

// Check that unicast routes with a multicast destination range are accepted by
// the switch. We may disallow this via a p4-constraint in the future, but need
// the capability as a temporary workaround as of 2023-12-08.
TEST_P(SmokeTestFixture, CanInstallIpv6TableEntriesWithMulticastDstIp) {
  thinkit::MirrorTestbed& testbed =
      GetParam().mirror_testbed->GetMirrorTestbed();
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<pdpi::P4RuntimeSession> sut,
      pins_test::ConfigureSwitchAndReturnP4RuntimeSession(
          testbed.Sut(), GetParam().gnmi_config, GetParam().p4info));
  ASSERT_OK_AND_ASSIGN(pdpi::IrP4Info p4info, pdpi::GetIrP4Info(*sut));
  ASSERT_OK_AND_ASSIGN(
      std::vector<p4::v1::Entity> pi_entities,
      sai::EntryBuilder().AddVrfEntry("vrf").GetDedupedPiEntities(p4info));
  ASSERT_OK(pdpi::InstallPiEntities(sut.get(), p4info, pi_entities));
  // TODO: Use `sai::EntryBuilder` instead of hard-coding the entries
  // here.
  ASSERT_OK(pdpi::InstallPdTableEntries<sai::TableEntries>(*sut, R"pb(
    entries {
      ipv6_table_entry {
        match {
          vrf_id: "vrf"
          ipv6_dst { value: "ff00::" prefix_length: 8 }
        }
        action { drop {} }
      }
    }
    entries {
      ipv6_table_entry {
        match {
          vrf_id: "vrf"
          ipv6_dst { value: "ff00:1234:5678:9012::" prefix_length: 64 }
        }
        action { drop {} }
      }
    }
    entries {
      ipv6_table_entry {
        match {
          vrf_id: "vrf"
          ipv6_dst { value: "ff00::1234" prefix_length: 128 }
        }
        action { drop {} }
      }
    }
  )pb"));
}

}  // namespace
}  // namespace pins_test
