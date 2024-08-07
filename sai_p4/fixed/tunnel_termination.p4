// Tunnel termination aka decap, modeled after `saitunnel.h`,

// Copyright 2023 Google LLC
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

#ifndef SAI_TUNNEL_TERMINATION_P4_
#define SAI_TUNNEL_TERMINATION_P4_

#include <v1model.p4>
#include "drop_martians.p4"
#include "headers.p4"
#include "ids.h"
#include "metadata.p4"
#include "minimum_guaranteed_sizes.h"

// Should be applied at the end of the pre-ingress stage.
control tunnel_termination(inout headers_t headers,
                                  inout local_metadata_t local_metadata) {
  bool marked_for_ip_in_ipv6_decap = false;

  @id(TUNNEL_DECAP_ACTION_ID)
  action tunnel_decap() {
    local_metadata.tunnel_termination_table_hit = true;
  }

  // Models SAI_TUNNEL_TERM_TABLE.
  // Currently, we only model IPv6 decap of IP-in-IP packets
  @p4runtime_role(P4RUNTIME_ROLE_ROUTING)
  @id(IPV6_TUNNEL_TERMINATION_TABLE_ID)
  table ipv6_tunnel_termination_table {
    key = {
      // Sets `SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP[_MASK]`.
      headers.ipv6.dst_addr : ternary
        @id(1) @name("dst_ipv6") @format(IPV6_ADDRESS);
      // Sets `SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP[_MASK]`.
      headers.ipv6.src_addr : ternary
        @id(2) @name("src_ipv6") @format(IPV6_ADDRESS);
    }
    actions = {
      @proto_id(1) tunnel_decap;
    }
    size = IPV6_TUNNEL_TERMINATION_TABLE_MINIMUM_GUARANTEED_SIZE;
  }

  apply {
    // Currently, we only model tunnel termination of IP-in-IPv6 packets
    // (SAI_TUNNEL_TYPE_IPINIP).
    // See go/tunneldecap_and_multicast_verification for tunnel lookup
    // conditions.
    if (IS_UNICAST_MAC(headers.ethernet.dst_addr) &&
        headers.ipv6.isValid() &&
        headers.ipv6.hop_limit != 0 &&
        headers.ipv6.src_addr != 0 &&
        headers.ipv6.src_addr != headers.ipv6.dst_addr &&
        !IS_LOOPBACK_IPV6(headers.ipv6.src_addr) &&
        !IS_MULTICAST_IPV6(headers.ipv6.src_addr)) {
      // IP-in-IP encapsulation: 4in6 or 6in6.
      if (headers.ipv6.next_header == IP_PROTOCOL_IPV4 ||
          headers.ipv6.next_header == IP_PROTOCOL_IPV6) {
        ipv6_tunnel_termination_table.apply();
      }
    }

    // Decap the packet only if BOTH tunnel termination and l3 admit tables
    // were hit (see b/329146949 for details).
    if(local_metadata.tunnel_termination_table_hit &&
       local_metadata.admit_to_l3) {
      // Currently, this should only ever be set for IP-in-IPv6 packets.
      // TODO: Remove guard once p4-symbolic suports assertions.
#ifndef PLATFORM_P4SYMBOLIC
      assert(headers.ipv6.isValid());
      assert((headers.inner_ipv4.isValid() && !headers.inner_ipv6.isValid()) ||
             (!headers.inner_ipv4.isValid() && headers.inner_ipv6.isValid()));
#endif

      // Decap: strip outer header and replace with inner header.
      headers.ipv6.setInvalid();
      if (headers.inner_ipv4.isValid()) {
        headers.ethernet.ether_type = ETHERTYPE_IPV4;
        // In case of multicast inner header, the DMAC will be rewritten to a
        // multicast address drived from the destination IP address.
        if (IS_MULTICAST_IPV4(headers.inner_ipv4.dst_addr)){
          // MAC Address for IPv4 multicast is 01:00:5E:xx:xx:xx where the 24th
          // LSB is 0 and the 23 LSBs are the 23 LSBs of IPv4 dst address.
          // https://en.wikipedia.org/wiki/Multicast_address#Ethernet
          local_metadata.enable_dst_mac_rewrite = true;
          local_metadata.packet_rewrites.dst_mac =
              (bit<24>)0x01005E++(bit<1>)0++headers.inner_ipv4.dst_addr[22:0];
        }
        // SAI_TUNNEL_ATTR_DECAP_DSCP_MODE is not configured, so it defaults to
        // SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL which means we preserve outer DSCP
        // and discard inner DSCP.
        // Behavior discussed in b/354283299.
        headers.inner_ipv4.dscp = headers.ipv6.dscp;
        headers.ipv4 = headers.inner_ipv4;
        headers.inner_ipv4.setInvalid();
      }
      if (headers.inner_ipv6.isValid()) {
        headers.ethernet.ether_type = ETHERTYPE_IPV6;
        // In case of multicast inner header, the DMAC will be rewritten to a
        // multicast address drived from the destination IP address.
        if (IS_MULTICAST_IPV6(headers.inner_ipv6.dst_addr)){
          // MAC Address for IPv6 multicast is 33:33:xx:xx:xx:xx where the 32
          // LSBs are the 32 LSBs of the IPv6 dst address.
          // https://en.wikipedia.org/wiki/Multicast_address#Ethernet
          local_metadata.enable_dst_mac_rewrite = true;
          local_metadata.packet_rewrites.dst_mac =
              (bit<16>)0x3333++headers.inner_ipv6.dst_addr[31:0];
        }
        // SAI_TUNNEL_ATTR_DECAP_DSCP_MODE is not configured, so it defaults to
        // SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL which means we preserve outer DSCP
        // and discard inner DSCP.
        // Behavior discussed in b/354283299.
        headers.inner_ipv6.dscp = headers.ipv6.dscp;
        headers.ipv6 = headers.inner_ipv6;
        headers.inner_ipv6.setInvalid();
      }
    }
  }
}

#endif  // SAI_TUNNEL_TERMINATION_P4_
