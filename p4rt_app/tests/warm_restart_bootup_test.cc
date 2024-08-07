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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <thread>  // NOLINT
#include <utility>
#include <vector>

#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "grpcpp/client_context.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "grpcpp/support/status.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/proto_matchers.h"
#include "gutil/status.h"
#include "gutil/status_matchers.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4rt_app/event_monitoring/mock_state_event_monitor.h"
#include "p4rt_app/event_monitoring/state_db_warm_restart_table_events.h"
#include "p4rt_app/p4runtime/p4runtime_impl.h"
#include "p4rt_app/sonic/packetio_interface.h"
#include "p4rt_app/tests/lib/app_db_entry_builder.h"
#include "p4rt_app/tests/lib/p4runtime_grpc_service.h"
#include "p4rt_app/tests/lib/p4runtime_request_helpers.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "sai_p4/instantiations/google/sai_p4info.h"
#include "swss/warm_restart.h"

namespace p4rt_app {
namespace {
using ::gutil::EqualsProto;
using ::gutil::IsOkAndHolds;
using ::gutil::StatusIs;
using ::p4::v1::SetForwardingPipelineConfigRequest;
using ::testing::ElementsAre;
using ::testing::ExplainMatchResult;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::UnorderedElementsAreArray;
using P4RuntimeStream =
    ::grpc::ClientReaderWriter<p4::v1::StreamMessageRequest,
                               p4::v1::StreamMessageResponse>;
constexpr uint64_t kDeviceId = 100500;

// Expects a DB to contain the provided port map.
MATCHER_P2(
    ContainsPortMap, port_name, port_id,
    absl::Substitute("Contains mapping of port_name '$0' to port id '$1'",
                     port_name, port_id)) {
  return ExplainMatchResult(
      IsOkAndHolds(ElementsAre(std::make_pair("id", port_id))),
      arg.ReadTableEntry(port_name), result_listener);
}

// Get a writeable directory where bazel tests can save output files to.
// https://docs.bazel.build/versions/main/test-encyclopedia.html#initial-conditions
absl::StatusOr<std::string> GetTestTmpDir() {
  char* test_tmpdir = std::getenv("TEST_TMPDIR");
  if (test_tmpdir == nullptr) {
    return gutil::InternalErrorBuilder()
           << "Could not find environment variable ${TEST_TMPDIR}. Is this a "
              "bazel test run?";
  }
  return test_tmpdir;
}

p4::v1::Uint128 ElectionId(int value) {
  p4::v1::Uint128 election_id;
  election_id.set_high(value);
  election_id.set_low(value);
  return election_id;
}

absl::StatusOr<p4::v1::StreamMessageResponse> SendStreamRequestAndGetResponse(
    P4RuntimeStream& stream, const p4::v1::StreamMessageRequest& request) {
  if (!stream.Write(request)) {
    return gutil::InternalErrorBuilder()
           << "Stream closed : " << stream.Finish().error_message();
  }

  p4::v1::StreamMessageResponse response;
  if (!stream.Read(&response)) {
    return gutil::InternalErrorBuilder() << "Did not receive stream response: "
                                         << stream.Finish().error_message();
  }
  return response;
}

class WarmRestartTest : public testing::Test {
 protected:
  void SetUp() override {
    // Configure the P4RT session to save the P4Info to a file.
    ASSERT_OK_AND_ASSIGN(std::string test_tmpdir, GetTestTmpDir());
    config_save_path_ = absl::StrCat(test_tmpdir, "/forwarding_config.pb.txt");

    // The config file should not exist before running a test. We expect all
    // tests to cleanup their state.
    ASSERT_NE(GetSavedConfig().status(), absl::OkStatus());

    ASSERT_OK(ResetGrpcServerAndClient(false));

    state_event_monitor_ = std::make_unique<sonic::MockStateEventMonitor>();
  }

  void TearDown() override {
    // If a test created a config file we try to clean it up at teardown.
    if (GetSavedConfig().status().ok() &&
        std::remove(config_save_path_->c_str()) != 0) {
      FAIL() << "Could not remove file: " << *config_save_path_;
    }
  }

  void SetUpControllerRpcStubs() {
    std::string address = absl::StrCat("localhost:", p4rt_service_->GrpcPort());

    auto primary_channel =
        grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
    primary_stub_ = p4::v1::P4Runtime::NewStub(primary_channel);
    LOG(INFO) << "Created primary P4Runtime::Stub for " << address << ".";

    auto backup_channel =
        grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
    backup_stub_ = p4::v1::P4Runtime::NewStub(backup_channel);
    LOG(INFO) << "Created backup P4Runtime::Stub for " << address << ".";
  }

  // Opens a P4RT stream, and verifies that it is the primary connection. Note
  // that the stream can still become a backup if a test updates the election
  // ID, or opens a new connection.
  absl::StatusOr<std::unique_ptr<P4RuntimeStream>> CreatePrimaryConnection(
      grpc::ClientContext& context, uint64_t device_id,
      const p4::v1::Uint128 election_id) {
    context.set_deadline(absl::ToChronoTime(absl::Now() + absl::Seconds(10)));
    context.set_wait_for_ready(true);
    auto stream = primary_stub_->StreamChannel(&context);

    // Verify that connection is the primary.
    p4::v1::StreamMessageRequest request;
    request.mutable_arbitration()->set_device_id(device_id);
    *request.mutable_arbitration()->mutable_election_id() = election_id;
    ASSIGN_OR_RETURN(p4::v1::StreamMessageResponse response,
                     SendStreamRequestAndGetResponse(*stream, request));
    if (response.arbitration().status().code() != grpc::StatusCode::OK) {
      return gutil::UnknownErrorBuilder()
             << "could not become primary. "
             << response.arbitration().status().ShortDebugString();
    }

    return stream;
  }

  // Opens a P4RT stream without an election ID so it is forced to be a backup.
  absl::StatusOr<std::unique_ptr<P4RuntimeStream>> CreateBackupConnection(
      grpc::ClientContext& context, uint64_t device_id) {
    // No test should take more than 10 seconds.
    context.set_deadline(absl::ToChronoTime(absl::Now() + absl::Seconds(10)));
    context.set_wait_for_ready(true);
    auto stream = backup_stub_->StreamChannel(&context);

    // Verify that connection is a backup.
    p4::v1::StreamMessageRequest request;
    request.mutable_arbitration()->set_device_id(device_id);
    ASSIGN_OR_RETURN(p4::v1::StreamMessageResponse response,
                     SendStreamRequestAndGetResponse(*stream, request));
    if (response.arbitration().status().code() == grpc::StatusCode::OK) {
      return gutil::UnknownErrorBuilder()
             << "could not become backup. "
             << response.arbitration().status().ShortDebugString();
    }

    return stream;
  }

  absl::Status ResetGrpcServerAndClient(bool is_freeze_mode) {
    // The P4RT service will wait for the client to close before stopping.
    // Therefore, we need to close the client connection first if it exists.
    if (p4rt_session_ != nullptr) RETURN_IF_ERROR(p4rt_session_->Finish());

    if (p4rt_service_ != nullptr) {
      // Copy existing DB tables and rebuild P4RT server.
      auto p4runtime_impl = p4rt_service_->BuildP4rtServer(P4RuntimeImplOptions{
          .translate_port_ids = true,
          .is_freeze_mode = true,
          .forwarding_config_full_path = config_save_path_,
      });
      SetUpControllerRpcStubs();
      p4rt_service_->ResetP4rtServer(std::move(p4runtime_impl));
    } else {
      // Restart a new P4RT service.
      p4rt_service_ =
          std::make_unique<test_lib::P4RuntimeGrpcService>(P4RuntimeImplOptions{
              .translate_port_ids = true,
              .is_freeze_mode = is_freeze_mode,
              .forwarding_config_full_path = config_save_path_,
          });
      SetUpControllerRpcStubs();
    }
    RETURN_IF_ERROR(p4rt_service_->GetP4rtServer().UpdateDeviceId(kDeviceId));

    // Reset the P4RT client.
    std::string address = absl::StrCat("localhost:", p4rt_service_->GrpcPort());
    LOG(INFO) << "Opening P4RT connection to " << address << ".";
    auto stub =
        pdpi::CreateP4RuntimeStub(address, grpc::InsecureChannelCredentials());

    if (is_freeze_mode) {
      EXPECT_THAT(pdpi::P4RuntimeSession::Create(std::move(stub), kDeviceId),
                  StatusIs(absl::StatusCode::kUnavailable));
    } else {
      ASSIGN_OR_RETURN(p4rt_session_, pdpi::P4RuntimeSession::Create(
                                          std::move(stub), kDeviceId));
    }

    return absl::OkStatus();
  }

  absl::Status SaveConfigFile(const p4::v1::ForwardingPipelineConfig& config) {
    if (!config_save_path_.has_value()) {
      return gutil::FailedPreconditionErrorBuilder()
             << "Save path is not set for the config.";
    }
    return gutil::SaveProtoToFile(*config_save_path_, config);
  }

  absl::StatusOr<p4::v1::ForwardingPipelineConfig> GetSavedConfig() {
    if (!config_save_path_.has_value()) {
      return gutil::FailedPreconditionErrorBuilder()
             << "Save path is not set for the config.";
    }

    p4::v1::ForwardingPipelineConfig config;
    RETURN_IF_ERROR(gutil::ReadProtoFromFile(*config_save_path_, &config));
    return config;
  }

  // SetForwardingPipelineConfig will reject any flow that doesn't have an
  // expected 'device ID', 'role', or 'election ID'. Since this information is
  // irrelevant to these test we use a helper function to simplify setup.
  SetForwardingPipelineConfigRequest GetBasicForwardingRequest() {
    SetForwardingPipelineConfigRequest request;
    request.set_device_id(p4rt_session_->DeviceId());
    request.set_role(p4rt_session_->Role());
    *request.mutable_election_id() = p4rt_session_->ElectionId();
    return request;
  }

  // LINT.IfChange(bootup)
  void WarmRestartSwitchUpOperations(
      bool wait_for_unfreeze, swss::WarmStart::WarmStartState oa_wb_state,
      const std::vector<std::pair<std::string, std::string>>& port_ids = {},
      const std::vector<std::pair<std::string, std::string>>& cpu_queue_ids =
          {},
      const std::vector<std::pair<std::string, std::string>>&
          front_panel_queue_ids = {},
      int device_id = kDeviceId, const std::vector<std::string>& ports = {}) {
    // Reset P4RT server
    EXPECT_OK(ResetGrpcServerAndClient(/*is_freeze_mode=*/true));
    p4rt_service_->GetP4rtServer().GrabLockAndUpdateWarmBootState(
        swss::WarmStart::INITIALIZED);
    EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
              swss::WarmStart::INITIALIZED);
    auto p4rt_recon_status =
        p4rt_service_->GetP4rtServer().RebuildSwStateAfterWarmboot(
            port_ids, cpu_queue_ids, front_panel_queue_ids, kDeviceId, ports);
    if (p4rt_recon_status.ok()) {
      p4rt_service_->GetP4rtServer().GrabLockAndUpdateWarmBootState(
          swss::WarmStart::RECONCILED);
      EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
                swss::WarmStart::RECONCILED);
    } else {
      LOG(ERROR) << "Failed to reconcile P4RT: "
                 << p4rt_service_->GetP4rtServer()
                        .GrabLockAndEnterCriticalState(
                            p4rt_recon_status.message())
                        .error_message();
      p4rt_service_->GetP4rtServer().GrabLockAndUpdateWarmBootState(
          swss::WarmStart::FAILED);
      p4rt_service_->GetP4rtServer().GrabLockAndUpdateWarmBootStageEndOnFailure(
          swss::WarmStart::STAGE_RECONCILIATION);
      EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
                swss::WarmStart::FAILED);
      EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootStage(),
                swss::WarmStart::STAGE_RECONCILIATION);
      EXPECT_TRUE(p4rt_service_->GetWarmBootStateAdapter()
                      ->GetWarmBootStageFailureFlag());
    }

    p4rt_service_->GetWarmBootStateAdapterForUtilOnly()->SetWaitForUnfreeze(
        /*wait_for_unfreeze=*/wait_for_unfreeze);
    p4rt_service_->GetWarmBootStateAdapterForUtilOnly()
        ->SetOrchAgentWarmBootState(
            /*orch_agent_warm_boot_state=*/oa_wb_state);
    p4rt_service_->GetWarmBootStateAdapter()->SetWaitForUnfreeze(
        /*wait_for_unfreeze=*/wait_for_unfreeze);
    p4rt_service_->GetWarmBootStateAdapter()->SetOrchAgentWarmBootState(
        /*orch_agent_warm_boot_state=*/oa_wb_state);
    EXPECT_EQ(
        p4rt_service_->GetWarmBootStateAdapterForUtilOnly()->WaitForUnfreeze(),
        wait_for_unfreeze);
    EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapterForUtilOnly()
                  ->GetOrchAgentWarmBootState(),
              oa_wb_state);

    if (p4rt_recon_status.ok() &&
        !p4rt_service_->GetWarmRestartUtil().ShouldWaitForGlobalUnfreeze()) {
      EXPECT_CALL(*state_event_monitor_, RegisterTableHandler)
          .WillOnce(Return(absl::OkStatus()));

      EXPECT_CALL(*state_event_monitor_, WaitForNextEventAndHandle)
          .WillRepeatedly([this](void) {
            auto oa_state = p4rt_service_->GetWarmBootStateAdapterForUtilOnly()
                                ->GetOrchAgentWarmBootState();
            if (oa_state == swss::WarmStart::RECONCILED) {
              this->oa_reconciled_ = true;
            } else if (oa_state == swss::WarmStart::FAILED) {
              this->monitor_oa_reconcile_events_ = false;
            }
            return absl::OkStatus();
          });

      // Spawn the thread, and wait for it to do work before finishing the test.
      oa_reconcile_listener_thread_ = std::thread(absl::bind_front(
          &p4rt_app::WaitForOrchAgentReconcileToUnfreezeP4rt,
          state_event_monitor_.get(), &p4rt_service_->GetP4rtServer(),
          &monitor_oa_reconcile_events_, &oa_reconciled_));
    }
  }
  // LINT.ThenChange()

  void VerifyP4rtServerResponseInFreezeMode() {
    // Grpc requests are rejected in freeze mode.
    p4::v1::ReadRequest read_request;
    read_request.set_device_id(p4rt_session_->DeviceId());
    read_request.set_role(p4rt_session_->Role());
    EXPECT_THAT(p4rt_session_->Read(read_request),
                StatusIs(absl::StatusCode::kUnavailable,
                         "P4RT is performing warm reboot."));

    // Internal requests are processed in freeze mode.
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPacketIoPort("Ethernet1/1/0"));
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet1/1/0",
                                                                "0"));
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPacketIoPort("Ethernet1/1/1"));
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet1/1/1",
                                                                "1"));

    // Packet-in events are ignored in freeze mode.
    EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().PushPacketIn(
        "Ethernet1_1_0", "Ethernet1_1_1", "test packet1"));
    EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().PushPacketIn(
        "Ethernet1_1_1", "Ethernet1_1_0", "test packet2"));

    sonic::PacketIoCounters counters =
        p4rt_service_->GetP4rtServer().GetPacketIoCounters();
    EXPECT_EQ(counters.packet_in_received, 0);
    EXPECT_EQ(counters.packet_in_errors, 0);
  }

  void VerifyP4rtServerResponseInUnfreezeMode() {
    // Grpc requests are processed as P4RT is unfreezed.
    const p4::v1::Uint128 election_id = ElectionId(11);

    grpc::ClientContext primary_stream_context;
    std::unique_ptr<P4RuntimeStream> primary_stream;
    grpc::ClientContext backup_stream_context;
    std::unique_ptr<P4RuntimeStream> backup_stream;
    ASSERT_OK(p4rt_service_->GetP4rtServer().UpdateDeviceId(kDeviceId));

    ASSERT_OK_AND_ASSIGN(primary_stream,
                         CreatePrimaryConnection(primary_stream_context,
                                                 kDeviceId, election_id));
    ASSERT_OK_AND_ASSIGN(backup_stream, CreateBackupConnection(
                                            backup_stream_context, kDeviceId));

    p4::v1::ReadRequest read_request;
    read_request.set_device_id(kDeviceId);
    read_request.set_role(p4rt_session_->Role());
    EXPECT_OK(p4rt_session_->Read(read_request));

    // Internal requests are processed in unfreeze mode.
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPacketIoPort("Ethernet1/1/0"));
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet1/1/0",
                                                                "0"));
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPacketIoPort("Ethernet1/1/1"));
    EXPECT_OK(p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet1/1/1",
                                                                "1"));

    // Packet-in events are processed as P4RT is unfreezed.
    EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().PushPacketIn(
        "Ethernet1_1_0", "Ethernet1_1_1", "test packet1"));
    EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().PushPacketIn(
        "Ethernet1_1_1", "Ethernet1_1_0", "test packet2"));

    sonic::PacketIoCounters counters =
        p4rt_service_->GetP4rtServer().GetPacketIoCounters();
    EXPECT_EQ(counters.packet_in_received, 2);
    EXPECT_EQ(counters.packet_in_errors, 0);
  }

  // File path for where the forwarding config is saved.
  std::optional<std::string> config_save_path_;

  // A fake P4RT gRPC service to run tests against.
  std::unique_ptr<test_lib::P4RuntimeGrpcService> p4rt_service_;

  // A gRPC client session to send and receive gRPC calls.
  std::unique_ptr<pdpi::P4RuntimeSession> p4rt_session_;

  std::unique_ptr<p4::v1::P4Runtime::Stub> primary_stub_;
  std::unique_ptr<p4::v1::P4Runtime::Stub> backup_stub_;
  std::unique_ptr<sonic::MockStateEventMonitor> state_event_monitor_;
  std::thread oa_reconcile_listener_thread_;
  bool monitor_oa_reconcile_events_ = true;
  bool oa_reconciled_ = false;
};

TEST_F(WarmRestartTest, OrchAgentReconciliationListenerThread) {
  EXPECT_CALL(*state_event_monitor_, RegisterTableHandler)
      .WillOnce(Return(absl::OkStatus()));

  bool oa_reconciled = false;
  bool monitor_oa_reconcile_events = true;
  // We expect the wait call to be made at least once, but could be called again
  // while waiting for the thread to be stopped.
  EXPECT_CALL(*state_event_monitor_, WaitForNextEventAndHandle)
      .WillOnce([&oa_reconciled](void) {
        oa_reconciled = true;
        return absl::OkStatus();
      })
      .WillRepeatedly(Return(absl::OkStatus()));

  P4RuntimeImpl* p4rt_server = &p4rt_service_->GetP4rtServer();
  // Spawn the thread, and wait for it to do work before finishing the test.
  auto listener_thread = std::thread(
      absl::bind_front(&p4rt_app::WaitForOrchAgentReconcileToUnfreezeP4rt,
                       state_event_monitor_.get(), p4rt_server,
                       &monitor_oa_reconcile_events, &oa_reconciled));

  listener_thread.join();
}

TEST_F(WarmRestartTest, ReconciliationSucceeds) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest request = GetBasicForwardingRequest();
  request.set_action(SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);

  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(request));

  EXPECT_THAT(GetSavedConfig(), IsOkAndHolds(EqualsProto(request.config())));

  // Set port name to id mapping
  ASSERT_OK(
      p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet0", "1"));
  ASSERT_OK(
      p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet4", "2"));
  EXPECT_THAT(p4rt_service_->GetPortAppDbTable(),
              ContainsPortMap("Ethernet0", "1"));
  EXPECT_THAT(p4rt_service_->GetPortAppDbTable(),
              ContainsPortMap("Ethernet4", "2"));

  // Set CPU queue id mapping
  ASSERT_OK_AND_ASSIGN(auto translator, QueueTranslator::Create(
                                            {{"CONTROLLER_PRIORITY_1", "32"},
                                             {"CONTROLLER_PRIORITY_2", "33"}}));
  p4rt_service_->GetP4rtServer().AssignQueueTranslator(QueueType::kCpu,
                                                       std::move(translator));

  // Reset P4RT server
  EXPECT_OK(ResetGrpcServerAndClient(/*is_freeze_mode=*/true));
  // Perform reconciliation
  EXPECT_OK(p4rt_service_->GetP4rtServer().RebuildSwStateAfterWarmboot(
      {{"Ethernet0", "1"}, {"Ethernet4", "2"}},
      {{"CONTROLLER_PRIORITY_1", "32"}, {"CONTROLLER_PRIORITY_2", "33"}},
      {{"FRONT_PANEL_1", "1"}, {"FRONT_PANEL_2", "2"}}, kDeviceId,
      {"Ethernet0", "Ethernet4", "SEND_TO_INGRESS"}));
  // State Verification
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));
  // Presence of HOST_STATS|CONFIG entry in STATE DB indicates that P4Info was
  // pushed before warm reboot and has been restored during warm bootup.
  EXPECT_OK(p4rt_service_->GetHostStatsStateDbTable().ReadTableEntry("CONFIG"));

  // Verify that the ports are added by AddPacketIoPort during reconciliation.
  EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().SendPacketOut(
      "Ethernet0", "test packet"));
  EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().SendPacketOut(
      "Ethernet4", "test packet"));
  EXPECT_OK(p4rt_service_->GetFakePacketIoInterface().SendPacketOut(
      "SEND_TO_INGRESS", "test packet"));

  // Unfreeze p4runtime server
  p4rt_service_->GetP4rtServer().SetFreezeMode(false);

  // Verify that UpdateDeviceId() succeded during reconciliation.
  const p4::v1::Uint128 election_id = ElectionId(11);
  grpc::ClientContext primary_stream_context;
  std::unique_ptr<P4RuntimeStream> primary_stream;
  ASSERT_OK_AND_ASSIGN(
      primary_stream,
      CreatePrimaryConnection(primary_stream_context, kDeviceId, election_id));
}

TEST_F(WarmRestartTest, ReconciliationSucceedsWithAclEntries) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest pipeline_request =
      GetBasicForwardingRequest();
  pipeline_request.set_action(
      SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *pipeline_request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);
  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(pipeline_request));
  EXPECT_THAT(GetSavedConfig(),
              IsOkAndHolds(EqualsProto(pipeline_request.config())));

  ASSERT_OK_AND_ASSIGN(p4::v1::WriteRequest request,
                       test_lib::PdWriteRequestToPi(
                           R"pb(
                             updates {
                               type: INSERT
                               table_entry {
                                 acl_pre_ingress_table_entry {
                                   match { is_ip { value: "0x1" } }
                                   priority: 10
                                   action { set_vrf { vrf_id: "vrf-1" } }
                                 }
                               }
                             }
                           )pb",
                           sai::GetIrP4Info(sai::Instantiation::kTor)));

  // Expected P4RT AppDb entries.
  auto acl_entry = test_lib::AppDbEntryBuilder{}
                       .SetTableName("ACL_ACL_PRE_INGRESS_TABLE")
                       .SetPriority(10)
                       .AddMatchField("is_ip", "0x1")
                       .SetAction("set_vrf")
                       .AddActionParam("vrf_id", "vrf-1");
  EXPECT_OK(
      pdpi::SetMetadataAndSendPiWriteRequest(p4rt_session_.get(), request));
  EXPECT_THAT(
      p4rt_service_->GetP4rtAppDbTable().ReadTableEntry(acl_entry.GetKey()),
      IsOkAndHolds(UnorderedElementsAreArray(acl_entry.GetValueMap())));

  // Reset P4RT server
  EXPECT_OK(ResetGrpcServerAndClient(/*is_freeze_mode=*/true));
  // Perform reconciliation
  EXPECT_OK(p4rt_service_->GetP4rtServer().RebuildSwStateAfterWarmboot(
      {{"Ethernet4", "2"}}, {}, {}, kDeviceId,
      {"Ethernet4", "SEND_TO_INGRESS"}));
  // State Verification
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));
  // Presence of HOST_STATS|CONFIG entry in STATE DB indicates that P4Info was
  // pushed before warm reboot and has been restored during warm bootup.
  EXPECT_OK(p4rt_service_->GetHostStatsStateDbTable().ReadTableEntry("CONFIG"));
}

TEST_F(WarmRestartTest, ReconciliationSucceedsWithFixedL3Entries) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest pipeline_request =
      GetBasicForwardingRequest();
  pipeline_request.set_action(
      SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *pipeline_request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);
  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(pipeline_request));
  EXPECT_THAT(GetSavedConfig(),
              IsOkAndHolds(EqualsProto(pipeline_request.config())));

  ASSERT_OK(
      p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet4", "2"));
  // P4 write request for fixed l3 table
  ASSERT_OK_AND_ASSIGN(p4::v1::WriteRequest request,
                       test_lib::PdWriteRequestToPi(
                           R"pb(
                             updates {
                               type: INSERT
                               table_entry {
                                 router_interface_table_entry {
                                   match { router_interface_id: "16" }
                                   action {
                                     set_port_and_src_mac {
                                       port: "2"
                                       src_mac: "00:02:03:04:05:06"
                                     }
                                   }
                                 }
                               }
                             }
                           )pb",
                           sai::GetIrP4Info(sai::Instantiation::kTor)));

  // Expected P4RT AppDb entry.
  auto expected_entry = test_lib::AppDbEntryBuilder{}
                            .SetTableName("FIXED_ROUTER_INTERFACE_TABLE")
                            .AddMatchField("router_interface_id", "16")
                            .SetAction("set_port_and_src_mac")
                            .AddActionParam("port", "Ethernet4")
                            .AddActionParam("src_mac", "00:02:03:04:05:06");

  EXPECT_OK(
      pdpi::SetMetadataAndSendPiWriteRequest(p4rt_session_.get(), request));
  EXPECT_THAT(
      p4rt_service_->GetP4rtAppDbTable().ReadTableEntry(
          expected_entry.GetKey()),
      IsOkAndHolds(UnorderedElementsAreArray(expected_entry.GetValueMap())));

  // Reset P4RT server
  EXPECT_OK(ResetGrpcServerAndClient(/*is_freeze_mode=*/true));
  // Perform reconciliation
  EXPECT_OK(p4rt_service_->GetP4rtServer().RebuildSwStateAfterWarmboot(
      {{"Ethernet4", "2"}}, {}, {}, kDeviceId,
      {"Ethernet4", "SEND_TO_INGRESS"}));
  // State Verification
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));
  // Presence of HOST_STATS|CONFIG entry in STATE DB indicates that P4Info was
  // pushed before warm reboot and has been restored during warm bootup.
  EXPECT_OK(p4rt_service_->GetHostStatsStateDbTable().ReadTableEntry("CONFIG"));
}

TEST_F(WarmRestartTest, ReconciliationFailsP4infoNotFoundAndPushed) {
  // The presence of HOST_STATS|CONFIG entry in STATE DB indicates that P4Info
  // was pushed before warm reboot.
  p4rt_service_->GetHostStatsStateDbTable().InsertTableEntry(
      "CONFIG", {{"last-configuration-timestamp",
                  absl::StrCat(absl::ToUnixNanos(absl::Now()))}});
  // Reconciliation fails since P4Info is not saved in the file system.
  EXPECT_THAT(p4rt_service_->GetP4rtServer().RebuildSwStateAfterWarmboot(
                  {}, {}, {}, 1, {}),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Fails since P4Info file path is not set.
  auto p4runtime_impl = p4rt_service_->BuildP4rtServer(P4RuntimeImplOptions{
      .translate_port_ids = true,
  });
  EXPECT_THAT(p4runtime_impl->RebuildSwStateAfterWarmboot({}, {}, {}, kDeviceId,
                                                          {"SEND_TO_INGRESS"}),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(WarmRestartTest, ReconciliationSucceedsP4infoNotFoundAndNotPushed) {
  // The absence of HOST_STATS|CONFIG entry in STATE DB indicates that P4Info
  // wasn't pushed before warm reboot.
  EXPECT_THAT(
      p4rt_service_->GetHostStatsStateDbTable().ReadTableEntry("CONFIG"),
      StatusIs(absl::StatusCode::kNotFound));
  // P4Info reconciliation should succeed when P4Info wasn't pushed before warm
  // reboot, and thus it isn't present after warm reboot.
  EXPECT_OK(p4rt_service_->GetP4rtServer().RebuildSwStateAfterWarmboot(
      {{"Ethernet4", "2"}}, {}, {}, kDeviceId,
      {"Ethernet4", "SEND_TO_INGRESS"}));
}

TEST_F(WarmRestartTest, ReconciliationFailsWhenDbEntryInvalid) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest pipeline_request =
      GetBasicForwardingRequest();
  pipeline_request.set_action(
      SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *pipeline_request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);
  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(pipeline_request));
  EXPECT_THAT(GetSavedConfig(),
              IsOkAndHolds(EqualsProto(pipeline_request.config())));
  EXPECT_OK(p4rt_service_->GetP4rtServer().AddPacketIoPort("Ethernet1/1/0"));
  EXPECT_OK(
      p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet1/1/0", "0"));
  EXPECT_OK(p4rt_service_->GetP4rtServer().AddPacketIoPort("Ethernet1/1/1"));
  EXPECT_OK(
      p4rt_service_->GetP4rtServer().AddPortTranslation("Ethernet1/1/1", "1"));

  // Insert invalid L3 entries
  p4rt_service_->GetP4rtAppDbTable().InsertTableEntry(
      "P4RT:FIXED_ROUTER_INTERFACE_TABLE:invalid", {});

  // If waitForUnfreeze == false in DB and OA succeeded to reconcile, but P4RT
  // failed to reconcile, then P4RT WarmState state is FAILED and P4RT still in
  // freeze mode.
  WarmRestartSwitchUpOperations(
      /*wait_for_unfreeze=*/false,
      /*oa_wb_state=*/swss::WarmStart::RECONCILED,
      /*port_ids=*/{{"Ethernet1/1/0", "0"}, {"Ethernet1/1/1", "1"}});
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::FAILED);

  // State Verification fails
  EXPECT_THAT(p4rt_service_->GetP4rtServer().VerifyState(true),
              StatusIs(absl::StatusCode::kUnknown,
                       HasSubstr("EntityCache is missing key: "
                                 "P4RT:FIXED_ROUTER_INTERFACE_TABLE:invalid")));
  SCOPED_TRACE("Failed to stay frozen after reconcile error");
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootStage(),
            swss::WarmStart::STAGE_RECONCILIATION);
  EXPECT_TRUE(
      p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootStageFailureFlag());
  VerifyP4rtServerResponseInFreezeMode();
}

TEST_F(WarmRestartTest, WarmBootUpWaitForUnfreeze) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest request = GetBasicForwardingRequest();
  request.set_action(SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);

  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(request));
  EXPECT_THAT(GetSavedConfig(), IsOkAndHolds(EqualsProto(request.config())));

  // If waitForUnfreeze == true in DB and OA failed to reconcile, then P4RT warm
  // boot state is RECONCILED, and p4rt server is still FROZEN.
  WarmRestartSwitchUpOperations(
      /*wait_for_unfreeze=*/true,
      /*oa_wb_state=*/swss::WarmStart::FAILED,
      /*port_ids=*/{{"Ethernet1/1/0", "0"}, {"Ethernet1/1/1", "1"}});
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::RECONCILED);
  {
    SCOPED_TRACE("Expected switch to stay frozen until unfreeze");
    VerifyP4rtServerResponseInFreezeMode();
  }

  // If waitForUnfreeze == true in DB and OA succeeded to reconcile, then P4RT
  // warm boot state is RECONCILED, and p4rt server is still FROZEN.
  WarmRestartSwitchUpOperations(
      /*wait_for_unfreeze=*/true,
      /*oa_wb_state=*/swss::WarmStart::RECONCILED,
      /*port_ids=*/{{"Ethernet1/1/0", "0"}, {"Ethernet1/1/1", "1"}});
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::RECONCILED);

  // State Verification
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));

  {
    SCOPED_TRACE("Expected switch to stay frozen until unfreeze");
    VerifyP4rtServerResponseInFreezeMode();
  }

  // Unfreeze P4RT
  EXPECT_OK(p4rt_service_->GetP4rtServer().HandleWarmBootNotification(
      swss::WarmStart::WarmBootNotification::kUnfreeze));
  // Verify the warm boot state is COMPLETED.
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::WarmStartState::COMPLETED);
  // Verify the warm boot stage is STAGE_UNFREEZE.
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootStage(),
            swss::WarmStart::STAGE_UNFREEZE);
  EXPECT_FALSE(
      p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootStageFailureFlag());
  // State Verification
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));
  {
    SCOPED_TRACE(
        "Expected switch to unfreeze after receiving unfreeze notification");
    VerifyP4rtServerResponseInUnfreezeMode();
  }
}

TEST_F(WarmRestartTest, WarmBootUpNoWaitForUnfreeze) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest request = GetBasicForwardingRequest();
  request.set_action(SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);

  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(request));
  EXPECT_THAT(GetSavedConfig(), IsOkAndHolds(EqualsProto(request.config())));

  // If waitForUnfreeze == false in DB and OA is not reconciled yet, then P4RT
  // warm boot state keeps RECONCILED, and p4rt server is still FROZEN.
  WarmRestartSwitchUpOperations(
      /*wait_for_unfreeze=*/false,
      /*oa_wb_state=*/swss::WarmStart::INITIALIZED,
      /*port_ids=*/{{"Ethernet1/1/0", "0"}, {"Ethernet1/1/1", "1"}});
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::RECONCILED);
  {
    SCOPED_TRACE(
        "Expected switch to stay frozen until OrchAgent is reconciled");
    VerifyP4rtServerResponseInFreezeMode();
  }

  // If waitForUnfreeze == false in DB and OA succeeded to reconcile, then P4RT
  // warm boot state is RECONCILED, and p4rt server is UNFREEZED.
  p4rt_service_->GetWarmBootStateAdapterForUtilOnly()
      ->SetOrchAgentWarmBootState(swss::WarmStart::RECONCILED);
  p4rt_service_->GetWarmBootStateAdapter()->SetOrchAgentWarmBootState(
      swss::WarmStart::RECONCILED);

  oa_reconcile_listener_thread_.join();
  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::RECONCILED);

  {
    SCOPED_TRACE(
        "Expected switch to unfreeze since OrchAgent is reconciled and no need "
        "to wait for unfreeze notification.");
    VerifyP4rtServerResponseInUnfreezeMode();
  }
  // State Verification(For testing only)
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));
}

TEST_F(WarmRestartTest, WarmBootUpNoWaitForUnfreezeAndOAFailedToReconcile) {
  // Set forwarding config and save P4Info file
  SetForwardingPipelineConfigRequest request = GetBasicForwardingRequest();
  request.set_action(SetForwardingPipelineConfigRequest::RECONCILE_AND_COMMIT);
  *request.mutable_config()->mutable_p4info() =
      sai::GetP4Info(sai::Instantiation::kTor);

  ASSERT_OK(p4rt_session_->SetForwardingPipelineConfig(request));
  EXPECT_THAT(GetSavedConfig(), IsOkAndHolds(EqualsProto(request.config())));

  // If waitForUnfreeze == false in DB and OA failed to reconcile, then P4RT
  // warm boot state keeps RECONCILED, and p4rt server is still FROZEN.
  WarmRestartSwitchUpOperations(
      /*wait_for_unfreeze=*/false,
      /*oa_wb_state=*/swss::WarmStart::FAILED,
      /*port_ids=*/{{"Ethernet1/1/0", "0"}, {"Ethernet1/1/1", "1"}});

  EXPECT_EQ(p4rt_service_->GetWarmBootStateAdapter()->GetWarmBootState(),
            swss::WarmStart::RECONCILED);

  {
    SCOPED_TRACE(
        "Expected switch to stay frozen since OrchAgent failed to reconcile");
    VerifyP4rtServerResponseInFreezeMode();
  }
  // State Verification(For testing only)
  EXPECT_OK(p4rt_service_->GetP4rtServer().VerifyState(true));

  monitor_oa_reconcile_events_ = false;
  oa_reconcile_listener_thread_.join();
}

}  // namespace
}  // namespace p4rt_app
