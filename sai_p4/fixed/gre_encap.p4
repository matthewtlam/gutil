#ifndef SAI_GRE_ENCAP_P4_
#define SAI_GRE_ENCAP_P4_

#include <v1model.p4>
#include "headers.p4"
#include "metadata.p4"

// To be applied in the egress stage, after the L3 packet rewrite.
control gre_tunnel_encap(inout headers_t headers,
                        in local_metadata_t local_metadata,
                        in standard_metadata_t standard_metadata) {
  apply {
    if (local_metadata.apply_tunnel_encap_at_egress) {
      // Encapsulate packet by adding outer IPv6 and GRE headers as follows:
      //
      // +-----+------+           +-----+------+-----+------+
      // | ETH | IPvX | ...  -->  | ETH | IPv6 | GRE | IPvX | ...
      // +-----+------+           +-----+------+-----+------+
      //

      // Add GRE header.
      headers.tunnel_encap_gre.setValid();
      headers.tunnel_encap_gre.checksum_present = 0;
      headers.tunnel_encap_gre.routing_present = 0;
      headers.tunnel_encap_gre.key_present = 0;
      headers.tunnel_encap_gre.sequence_present = 0;
      headers.tunnel_encap_gre.strict_source_route = 0;
      headers.tunnel_encap_gre.recursion_control = 0;
      headers.tunnel_encap_gre.flags = 0;
      headers.tunnel_encap_gre.version = 0;
      headers.tunnel_encap_gre.protocol = headers.ethernet.ether_type;

      // Add outer IPv6 header.
      headers.ethernet.ether_type = ETHERTYPE_IPV6;
      headers.tunnel_encap_ipv6.setValid();
      headers.tunnel_encap_ipv6.version = 4w6;
      headers.tunnel_encap_ipv6.src_addr = local_metadata.tunnel_encap_src_ipv6;
      headers.tunnel_encap_ipv6.dst_addr = local_metadata.tunnel_encap_dst_ipv6;
      headers.tunnel_encap_ipv6.payload_length =
          (bit<16>)standard_metadata.packet_length
          + GRE_HEADER_BYTES
          - ETHERNET_HEADER_BYTES;
      headers.tunnel_encap_ipv6.next_header = IP_PROTOCOLS_GRE;
      // Copy relevant fields from inner to outer IP header.
      if (headers.ipv4.isValid()) {
        headers.tunnel_encap_ipv6.dscp = headers.ipv4.dscp;
        headers.tunnel_encap_ipv6.ecn = headers.ipv4.ecn;
        headers.tunnel_encap_ipv6.hop_limit = headers.ipv4.ttl;
      } else if (headers.ipv6.isValid()) {
        headers.tunnel_encap_ipv6.dscp = headers.ipv6.dscp;
        headers.tunnel_encap_ipv6.ecn = headers.ipv6.ecn;
        headers.tunnel_encap_ipv6.hop_limit = headers.ipv6.hop_limit;
      }
    }
  }
}  // gre tunnel encap changes

#endif  // SAI_GRE_ENCAP_P4_
