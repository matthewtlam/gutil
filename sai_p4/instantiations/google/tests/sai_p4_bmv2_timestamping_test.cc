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
#include <optional>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto.h"
#include "gutil/status.h"
#include "gutil/testing.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_pdpi/ir.h"
#include "p4_pdpi/ir.pb.h"
#include "p4_pdpi/p4_runtime_session.h"
#include "p4_pdpi/packetlib/packetlib.h"
#include "p4_pdpi/packetlib/packetlib.pb.h"
#include "platforms/networking/p4/p4_infra/bmv2/bmv2.h"
#include "sai_p4/instantiations/google/instantiations.h"
#include "sai_p4/instantiations/google/sai_p4info.h"
#include "sai_p4/instantiations/google/test_tools/set_up_bmv2.h"

namespace pins {
namespace {

absl::StatusOr<packetlib::Packet> GenericPspPacket() {
  auto packet = gutil::ParseProtoOrDie<packetlib::Packet>(R"pb(
    headers {
      ethernet_header {
        ethernet_destination: "00:ee:dd:cc:bb:aa"
        ethernet_source: "00:44:33:22:11:00"
        ethertype: "0x86dd"
      }
    }
    headers {
      ipv6_header {
        version: "0x6"
        dscp: "0x00"
        ecn: "0x0"
        flow_label: "0x12345"
        payload_length: "0x0034"
        next_header: "0x11"  # UDP
        hop_limit: "0x42"
        ipv6_source: "2607:f8b0:11::"
        ipv6_destination: "2607:f8b0:12::"
      }
    }
    headers {
      udp_header {
        source_port: "0x08ae"
        destination_port: "0x03e8"  # 1000
        length: "0x0034"
        checksum: "0x0000"
      }
    }
    headers {
      psp_header {
        next_header: "0x11"  # UDP
        header_ext_length: "0x00"
        reserved0: "0x0"
        crypt_offset: "0x02"
        sample_bit: "0x0"
        drop_bit: "0x0"
        version: "0x0"
        virtualization_cookie_present: "0x0"
        reserved1: "0x1"
        security_parameters_index: "0x00000000"
        initialization_vector: "0x0000000000000000"
      }
    }
    headers {
      udp_header {
        source_port: "0xbeef"
        destination_port: "0xabcd"
        length: "0x001c"
        checksum: "0xfe85"
      }
    }
  )pb");

  RETURN_IF_ERROR(packetlib::PadPacketToMinimumSize(packet).status());
  RETURN_IF_ERROR(packetlib::UpdateMissingComputedFields(packet).status());
  return packet;
}

class TimestampingTest : public testing::TestWithParam<sai::Instantiation> {
 protected:
  void SetUp() override {
    instantiation_ = GetParam();
    ir_p4info_ = sai::GetIrP4Info(instantiation_);
    ASSERT_OK_AND_ASSIGN(bmv2_switch_, sai::SetUpBmv2ForSaiP4(instantiation_));
  }

  bool InstantiationMatches(
      const absl::flat_hash_set<sai::Instantiation>& valid_instantations) {
    return valid_instantations.contains(instantiation_);
  }

  absl::Status InsertEntity(const pdpi::IrEntity& ir_entity) {
    pdpi::IrUpdate ir_update;
    ir_update.set_type(p4::v1::Update::INSERT);
    *ir_update.mutable_entity() = ir_entity;

    p4::v1::WriteRequest p4_write;
    ASSIGN_OR_RETURN(*p4_write.add_updates(),
                     pdpi::IrUpdateToPi(ir_p4info_, ir_update));
    return pdpi::SetMetadataAndSendPiWriteRequest(
        &bmv2_switch_->P4RuntimeSession(), p4_write);
  }

  sai::Instantiation instantiation_;
  pdpi::IrP4Info ir_p4info_;
  std::optional<orion::p4::test::Bmv2> bmv2_switch_;
};

TEST_P(TimestampingTest, MatchingOnPspFieldsInTheAclIngressTable) {
  if (!InstantiationMatches({sai::Instantiation::kMiddleblock})) {
    GTEST_SKIP();
  }
  ASSERT_OK_AND_ASSIGN(packetlib::Packet psp_packet, GenericPspPacket());

  pdpi::IrEntity ir_entity;
  ASSERT_OK(gutil::ReadProtoFromString(
      absl::Substitute(
          R"pb(
            table_entry {
              table_name: "acl_ingress_table"
              priority: 1
              matches {
                name: "ip_protocol"
                ternary {
                  value { hex_str: "0x11" }
                  mask { hex_str: "0xff" }
                }
              }
              matches {
                name: "l4_dst_port"
                ternary {
                  value { hex_str: "0x03e8" }
                  mask { hex_str: "0xffff" }
                }
              }
              matches {
                name: "psp_info"
                ternary {
                  value { hex_str: "0x01" }
                  mask { hex_str: "0xff" }
                }
              }
              matches {
                name: "psp_next_header"
                ternary {
                  value { hex_str: "0x11" }
                  mask { hex_str: "0xff" }
                }
              }
              matches {
                name: "inner_psp_udp_dst"
                ternary {
                  value { hex_str: "$0" }
                  mask { hex_str: "0xffff" }
                }
              }
              action {
                name: "acl_trap"
                params {
                  name: "qos_queue"
                  value { str: "0x1" }
                }
              }
            }
          )pb",
          psp_packet.headers(4).udp_header().destination_port()),
      &ir_entity));
  ASSERT_OK(InsertEntity(ir_entity));

  ASSERT_OK(bmv2_switch_->SendPacket(/*ingress_port=*/1, psp_packet));
  ASSERT_OK_AND_ASSIGN(p4::v1::StreamMessageResponse stream_response,
                       bmv2_switch_->P4RuntimeSession().GetNextStreamMessage(
                           /*timeout=*/absl::Seconds(3)));
}

INSTANTIATE_TEST_SUITE_P(
    TimestampingTest, TimestampingTest,
    testing::ValuesIn(sai::AllSaiInstantiations()),
    [&](const testing::TestParamInfo<sai::Instantiation>& info) {
      return InstantiationToString(info.param);
    });

}  // namespace
}  // namespace pins
