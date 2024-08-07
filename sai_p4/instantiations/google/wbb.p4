#define SAI_INSTANTIATION_WBB

#include <v1model.p4>

// These headers have to come first, to override their fixed counterparts.
#include "roles.h"
#include "bitwidths.p4"
#include "minimum_guaranteed_sizes.h"

#include "../../fixed/headers.p4"
#include "../../fixed/metadata.p4"
#include "../../fixed/roles.h"
#include "acl_wbb_ingress.p4"

control ingress(inout headers_t headers,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
  apply {
    acl_wbb_ingress.apply(headers, local_metadata, standard_metadata);
  }
}

control egress(inout headers_t headers,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {
  apply {}
}

parser packet_parser(packet_in packet, out headers_t headers,
                     inout local_metadata_t local_metadata,
                     inout standard_metadata_t standard_metadata) {
  state start {
    transition accept;
  }
}

control packet_deparser(packet_out packet, in headers_t headers) {
  apply {}
}

control verify_ipv4_checksum(inout headers_t headers,
                             inout local_metadata_t local_metadata) {
  apply {}
}

control compute_ipv4_checksum(inout headers_t headers,
                              inout local_metadata_t local_metadata) {
  apply {}
}

@pkginfo(
    name = "wbb.p4",
    organization = "Google",
    // We provide a version number for consistency with our other programs only.
    // We use a sperate version number for WBB (instead of using
    // `SAI_P4_PKGINFO_VERSION_LATEST`) to avoid unnecessary churn in WBB's
    // P4Info, which changes very rarely compared to our SAI P4 P4Infos.
    version = "0.0.0"
)
V1Switch(packet_parser(), verify_ipv4_checksum(), ingress(), egress(),
         compute_ipv4_checksum(), packet_deparser()) main;
