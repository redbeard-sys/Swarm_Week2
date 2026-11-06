/* shim.p4 -- week 2 pheromone shim on BMv2 (v1model).
 *
 * Every port has a role, set by the control plane (see s1.txt, s2.txt, s3.txt):
 *
 *   HOST    an untrusted, host-facing port.
 *           ingress: a frame that already carries a shim is a forgery, so it is
 *                    stripped and counted. Then a fresh shim is inserted with the
 *                    port's placeholder values.
 *           egress:  the shim is stripped and the original EtherType restored.
 *   FABRIC  a link to another participating node.
 *           ingress: a carried shim is updated, path_score += hop_incr (saturating).
 *           egress:  the shim stays.
 *   PLAIN   behaves like a non-programmable switch: no insert, no update, no strip.
 *           A port with no table entry is PLAIN.
 *
 * Forwarding is a fixed port-to-port table: each switch here has two ports.
 */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_SHIM = 0x88B5;   /* IEEE 802 local experimental */
const bit<4>  SHIM_VERSION   = 1;

const bit<2> ROLE_PLAIN  = 0;
const bit<2> ROLE_HOST   = 1;
const bit<2> ROLE_FABRIC = 2;

/* stats register slots */
const bit<32> ST_INSERTED = 0;
const bit<32> ST_UPDATED  = 1;
const bit<32> ST_STRIPPED = 2;
const bit<32> ST_FORGED   = 3;

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

/* 8 bytes, between Ethernet and IP. Field order is the wire order. */
header shim_t {
    bit<4>  version;
    bit<1>  m;          /* already mirrored */
    bit<1>  t;          /* tagged */
    bit<2>  rsvd;
    bit<8>  path_score;
    bit<16> bitmap;     /* contributor bitmap for key_hint */
    bit<16> key_hint;
    bit<16> next_type;  /* original EtherType, restored on strip */
}

struct headers_t {
    ethernet_t eth;
    shim_t     shim;
}

struct metadata_t {
    bit<2>  in_role;
    bit<2>  out_role;
    bit<8>  hop_incr;
    bit<8>  init_score;
    bit<16> init_bitmap;
    bit<16> init_key;
}

parser ShimParser(packet_in pkt, out headers_t hdr,
                  inout metadata_t meta, inout standard_metadata_t sm) {
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.ether_type) {
            ETHERTYPE_SHIM: parse_shim;
            default: accept;
        }
    }
    state parse_shim {
        pkt.extract(hdr.shim);
        transition accept;   /* week 2 never looks past the shim */
    }
}

control ShimVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control ShimIngress(inout headers_t hdr, inout metadata_t meta,
                    inout standard_metadata_t sm) {

    register<bit<32>>(4)  shim_stats;      /* inserted, updated, stripped, forged */
    register<bit<32>>(16) forged_by_port;  /* forged frames seen per ingress port */

    action drop() { mark_to_drop(sm); }
    action set_egress(bit<9> port) { sm.egress_spec = port; }

    table forward {
        key = { sm.ingress_port: exact; }
        actions = { set_egress; drop; }
        default_action = drop();
    }

    action in_host(bit<8> score, bit<16> bitmap, bit<16> key_hint) {
        meta.in_role     = ROLE_HOST;
        meta.init_score  = score;
        meta.init_bitmap = bitmap;
        meta.init_key    = key_hint;
    }
    action in_fabric(bit<8> hop_incr) {
        meta.in_role  = ROLE_FABRIC;
        meta.hop_incr = hop_incr;
    }
    action in_plain() { meta.in_role = ROLE_PLAIN; }

    table ingress_role {
        key = { sm.ingress_port: exact; }
        actions = { in_host; in_fabric; in_plain; }
        default_action = in_plain();
    }

    action out_host()   { meta.out_role = ROLE_HOST; }
    action out_fabric() { meta.out_role = ROLE_FABRIC; }
    action out_plain()  { meta.out_role = ROLE_PLAIN; }

    table egress_role {
        key = { sm.egress_spec: exact; }
        actions = { out_host; out_fabric; out_plain; }
        default_action = out_plain();
    }

    action bump(bit<32> slot) {
        bit<32> c;
        shim_stats.read(c, slot);
        shim_stats.write(slot, c + 1);
    }

    apply {
        forward.apply();
        if (sm.egress_spec == 511) { return; }   /* dropped by forward */
        ingress_role.apply();
        egress_role.apply();

        if (meta.in_role == ROLE_HOST) {
            if (hdr.shim.isValid()) {
                /* Forgery: hosts never write the shim. Strip it and count. */
                hdr.eth.ether_type = hdr.shim.next_type;
                hdr.shim.setInvalid();
                bump(ST_FORGED);
                bit<32> f;
                forged_by_port.read(f, (bit<32>)sm.ingress_port);
                forged_by_port.write((bit<32>)sm.ingress_port, f + 1);
            }
            /* Insert with this port's placeholder values. */
            hdr.shim.setValid();
            hdr.shim.version    = SHIM_VERSION;
            hdr.shim.m          = 0;
            hdr.shim.t          = 0;
            hdr.shim.rsvd       = 0;
            hdr.shim.path_score = meta.init_score;
            hdr.shim.bitmap     = meta.init_bitmap;
            hdr.shim.key_hint   = meta.init_key;
            hdr.shim.next_type  = hdr.eth.ether_type;
            hdr.eth.ether_type  = ETHERTYPE_SHIM;
            bump(ST_INSERTED);
        } else if (meta.in_role == ROLE_FABRIC && hdr.shim.isValid()) {
            /* Per-hop update: saturating add. */
            if (hdr.shim.path_score > 255 - meta.hop_incr) {
                hdr.shim.path_score = 255;
            } else {
                hdr.shim.path_score = hdr.shim.path_score + meta.hop_incr;
            }
            bump(ST_UPDATED);
        }

        if (meta.out_role == ROLE_HOST && hdr.shim.isValid()) {
            /* Leaving the fabric toward a host: restore the original frame. */
            hdr.eth.ether_type = hdr.shim.next_type;
            hdr.shim.setInvalid();
            bump(ST_STRIPPED);
        }
    }
}

control ShimEgress(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t sm) {
    apply { }
}

control ShimComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }   /* the shim sits below IP: no checksum changes */
}

control ShimDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.shim);   /* emitted only when valid */
    }
}

V1Switch(ShimParser(), ShimVerifyChecksum(), ShimIngress(),
         ShimEgress(), ShimComputeChecksum(), ShimDeparser()) main;
