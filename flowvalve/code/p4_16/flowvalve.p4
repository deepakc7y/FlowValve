#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> IPPROTO_UDP  = 17;
const bit<16> IPPROTO_TCP  = 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header eth_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    bit<48> srcHwAddr;
    bit<32> srcProtoAddr;
    bit<48> dstHwAddr;
    bit<32> dstProtoAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16>    srcPort;
    bit<16>    dstPort;
    bit<32>    seqNo;
    bit<32>   ackNo;
    bit<4>   dataOffset;
    bit<4>    res;
    bit<8>   flags;
    bit<16>    window;
    bit<16>    checksum;
    bit<16>   urgentPtr;
}

header ext_meta_t {
    bit<2> meter_color;
    // each label is 5 bit length, at most 8 layers
    bit<4> idxNum;
    bit<40> flowIdx;
    // bitmap help index
    bit<8> subNum;
    bit<32> flowSub;
}

struct headers {
    eth_t eth;
    arp_t arp;
    ipv4_t  ipv4;
    udp_t udp;
    tcp_t tcp;
}

struct metadata {
    ext_meta_t ext_meta;
}

extern void fv_schedule();

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_eth;
    }

    state parse_eth {
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP: parse_udp;
            IPPROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        default: accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        default: accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        default: accept;
    }

    // state parse_ext_meta {
    //     default:accept;
    // }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action act_flow(inum, idx, sub, snum) {
        modify_field(ext_meta.idxNum, inum);
        modify_field(ext_meta.flowIdx, idx);
        modify_field(ext_meta.flowSub, sub);
        modify_field(ext_meta.subNum, snum);
    }
    
    action act_schedule() {
        fv_schedule();
    }
    
    action act_forward(port) {
        modify_field(standard_metadata.egress_spec, port);
    }
        
    action act_drop() {
        mark_to_drop();
    }

    table ip_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            act_forward;
            act_drop;
        }
        size = 1024;
        default_action = act_drop();
        // default_action = NoAction();
    }

    table arp_forward {
        key = {
            hdr.arp.dstProtoAddr: exact;
        }
        actions = {
            act_forward;
            act_drop;
        }
        size = 1024;
        default_action = act_drop();
    }

    table port_forward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            act_forward;
            act_drop;
        }
        size = 1024;
        default_action = act_drop();
    }

    // table tbl_ingress_meter {
    //     key = {
    //         standard_metadata.ingress_port: exact;
    //         hdr.tcp.srcPort: exact;
    //         hdr.tcp.dstPort: exact;
    //         hdr.udp.srcPort: exact;
    //         hdr.udp.dstPort: exact;
    //     }
    //     actions = {
    //         act_meter;
    //     }
    // }

    // table tbl_egress_meter {
    //     key = {
    //         standard_metadata.egress_port: exact;
    //         hdr.tcp.srcPort: exact;
    //         hdr.tcp.dstPort: exact;
    //         hdr.udp.srcPort: exact;
    //         hdr.udp.dstPort: exact;
    //     }
    //     actions = {
    //         act_meter;
    //     }
    // }

    table tbl_flow {
        key = {
            hdr.tcp.dstPort: exact;
        }
        actions = {
            act_flow;
        }
        size = 1024;
        default_action = act_drop();
    }

    table tbl_schedule {
        key = { }
        actions = {
            act_schedule;
        }
        size = 1024;
        default_action = act_drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            port_forward.apply();
            ip_forward.apply();
        }
        else if (hdr.arp.isValid()) {
            arp_forward.apply();
        }
        // tbl_flow.apply();
        // tbl_schedule.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        // packet.emit(hdr.ext_meta); Do not emit a packet header that has not been parsed
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) 
main;