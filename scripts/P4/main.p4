#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  reserved;
    bit<8>  flags; // TCP flags
    bit<16> windowSize;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    icmp_t icmp;
}

struct metadata { }

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4; // IPv4 EtherType
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;   // TCP
            1: parse_icmp;  // ICMP
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1024) pkt_count; // Packet counter per source IP
    register<bit<32>>(1024) syn_count; // SYN packet counter for TCP

    // Increment the packet count for the source IP
    action increment_count() {
        bit<32> count;
        pkt_count.read(count, hdr.ipv4.srcAddr);
        count = count + 1;
        pkt_count.write(hdr.ipv4.srcAddr, count);
    }

    // Increment the SYN count for the source IP
    action increment_syn_count() {
        bit<32> count;
        syn_count.read(count, hdr.ipv4.srcAddr);
        count = count + 1;
        syn_count.write(hdr.ipv4.srcAddr, count);
    }

    // Drop packet action
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    table dos_mitigation {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            increment_count;
            increment_syn_count;
            drop_packet;
        }
        size = 1024;
        default_action = increment_count();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // Check for TCP SYN flood
            if (hdr.ipv4.protocol == 6 && hdr.tcp.flags == 2) { // TCP SYN flag = 2
                increment_syn_count();
            }

            // Check for ICMP flood
            if (hdr.ipv4.protocol == 1 && hdr.icmp.type == 8) { // ICMP Echo Request
                increment_count();
            }

            // Apply DoS mitigation
            dos_mitigation.apply();

            // Threshold values
            bit<32> pkt_threshold = 1000;
            bit<32> syn_threshold = 500;

            // Read packet counts
            bit<32> pkt_count_val;
            bit<32> syn_count_val;
            pkt_count.read(pkt_count_val, hdr.ipv4.srcAddr);
            syn_count.read(syn_count_val, hdr.ipv4.srcAddr);

            // Drop packets exceeding thresholds
            if (pkt_count_val > pkt_threshold || syn_count_val > syn_threshold) {
                drop_packet();
            }
        }
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);  // Emits TCP only if valid
        packet.emit(hdr.icmp); // Emits ICMP only if valid
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;