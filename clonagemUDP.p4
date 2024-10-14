/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_MQTT = 0x75B; 
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> tcpAddr_t;
header ethernet_t {
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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
    bit<96> opt;

}

header mqtt_t { 
   bit<4> messageType; // Este campo armazena os 4 bits que identificam o tipo de mensagem MQTT.
    bit<4> flags;       // Flags para o controle de qualidade, retenção, etc.
    bit<8> len;         // Tamanho da mensagem
    bit<16> tlen;       // Tamanho do tópico
    bit<56> topic;      // Tópico da mensagem
    bit<16> msg;  
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<1> is_clone;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t  tcp;
    mqtt_t mqtt;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){

            TYPE_IPV4: parse_ipv4;
            default: accept;

        }

    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }
    state tcp {
       packet.extract(hdr.tcp);
       transition select(hdr.tcp.dstPort) {
            TYPE_MQTT: parse_mqtt; 
            default: accept;
        }
    }

    state parse_mqtt {
        packet.extract(hdr.mqtt);
        
        transition accept;
    }
     state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

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
bit<16> extracted_topic;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action mirrorman() {
        clone(CloneType.I2E, 700);   
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
          if (hdr.ipv4.ttl > 1) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        } 
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {

        //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
        
        
           if (hdr.ipv4.isValid()){    
             
                   //if (hdr.mqtt.topic == 0x73656E736F7231)
                     
                    if (hdr.ipv4.dstAddr == 0x0a000102) {
                  
                       ipv4_forward(0x000000000102,1);
                    }
                    if (hdr.ipv4.dstAddr == 0x0a000202) {
                         clone(CloneType.I2E, 700);
                          meta.is_clone = 1;
                       ipv4_forward(0x000000000202,2);
                    }
                    if (hdr.ipv4.dstAddr == 0x0a000302) {
                  
                       ipv4_forward(0x000000000302,3);
                    }
                    if (hdr.ipv4.dstAddr == 0x0a000402) {
                  
                       ipv4_forward(0x000000000402,4);
                    }
                    
                    if (hdr.ipv4.dstAddr == 0x0a000502) {
                  
                       ipv4_forward(0x000000000502,5);
                    }
                    if (hdr.ipv4.dstAddr == 0x0a000602) {
                  
                       ipv4_forward(0x000000000602,6);
                    }
               
                    if (hdr.ipv4.dstAddr == 0x0a000702) {
                            
                           
                        
                        ipv4_forward(0x000000000702,7);
                    }
                 
              
            
              
            ipv4_lpm.apply();
          
           }
     
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                      action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
          if (hdr.ipv4.ttl > 1) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        } 
    }

    action convert_tcp_to_udp(egressSpec_t port) {
        // Remover o cabeçalho TCP
       
        
        // Adicionar o cabeçalho UDP
        hdr.udp.setValid();
        hdr.udp.srcPort = hdr.tcp.srcPort;  // Mantém a porta de origem
        hdr.udp.dstPort = hdr.tcp.dstPort;  // Mantém a porta de destino
        hdr.udp.length = hdr.ipv4.totalLen - 20;  // Comprimento do UDP excluindo o cabeçalho IP
        hdr.udp.checksum = 0;  // O checksum UDP pode ser opcional, aqui deixamos zero
        hdr.tcp.setInvalid();
        // Atualizar o cabeçalho IPv4 para indicar UDP
        hdr.ipv4.protocol = 17;  // Protocolo UDP
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;  // Decrementar TTL

        // Encaminhar para a porta
        standard_metadata.egress_spec = port;
    }
    apply { 

    	 if (meta.is_clone == 1) {
            // Pacote clonado: altere o endereço de destino
            
            log_msg("Pacote clonado");
            convert_tcp_to_udp(3); 
            hdr.ipv4.dstAddr = 0x0a000302;  
              ipv4_forward(0x000000000302,3);
        } else {
            // Pacote original: mantem inalterado
            log_msg("Pacote Original");
            
             // Destino original (10.0.2.2 em hex)
               ipv4_forward(0x000000000202,2);
        }
    	

     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
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


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
         packet.emit(hdr.tcp);  // Emitir o cabeçalho TCP
        packet.emit(hdr.mqtt); // Emitir o cabeçalho MQTT
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
