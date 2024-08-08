/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022
    
    Implemented By:     Chingiz Rajabli
                        Ryan Setzer
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"
#include <math.h>

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
FILE       *pcapOutput =  NULL ;        // The output PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header
bool        microSec ;  // is the time stamp in Sec+microSec ?  or is it Sec+nanoSec
double      baseTime ;  // capturing time of the very 1st packet in this file
bool        baseTimeSet = false ;
int         packetNumber = 1 ;
arpmap_t myARPmap[MAXARPMAP]; // List of my IPs, their MACs
int mapSize = 0; // Number of mapping pairs read into above



/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers
    
    Returns:  0 on success
             -1 on failure  */
int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
    pcapInput = fopen( fname, "r" ) ;
    if ( pcapInput == NULL )  errorExit( "Failed to open the PCAP file" ) ;
    fread(p, sizeof(pcap_hdr_t), 1, pcapInput) ;
    if ( p == NULL )  errorExit( "Failed to read the global header from the PCAP file" ) ;

    // Determine the capturer's byte ordering
    // Issue: majic_number could also be 0xa1b23c4D to indicate nano-second 
    // resolution instead of microseconds. This affects the interpretation
    // of the ts_usec field in each packet's header.

    switch ( p->magic_number)
    {
        case 0xa1b2c3d4 : bytesOK = true ;  microSec = true ;  break ;
        case 0xd4c3b2a1 : bytesOK = false;  microSec = true ;  break ;
        case 0xa1b23c4d : bytesOK = true ;  microSec = false;  break ;
        case 0x4d3cb2a1 : bytesOK = false;  microSec = false;  break ;
    }

    if ( ! bytesOK )  // reorder the bytes of the fields in this header
    {
        p->version_major = ntohs( p->version_major ) ;
        p->version_minor = ntohs( p->version_minor ) ;
        p->thiszone      = ntohl( p->thiszone      ) ;
        p->sigfigs       = ntohl( p->sigfigs       ) ;
        p->snaplen       = ntohl( p->snaplen       ) ;
        p->network       = ntohl( p->network       ) ;
    }

    return 0 ;
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n"  , p->magic_number  ) ;
    printf("major version %d\n", p->version_major ) ;
    printf("minor version %d\n", p->version_minor ) ;
    printf("GMT to local correction %d seconds\n", p->thiszone ) ;
    printf("accuracy of timestamps %d\n", p->sigfigs ) ;
    printf("Cut-off max length of captured packets %d\n", p->snaplen) ;
    printf("data link type %d\n", p->network ) ;

}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[] )
{
    if (fread(p, sizeof(packetHdr_t), 1, pcapInput) != 1)
    {
        return false; // End of file reached
    }

    // Did the capturer use a different 
    // byte-ordering than mine (as determined by the magic number)?
     if( ! bytesOK )   
    {
        p->ts_sec   = ntohl( p->ts_sec   ) ;
        p->ts_usec  = ntohl( p->ts_usec  ) ;
        p->incl_len = ntohl( p->incl_len ) ;
        p->orig_len = ntohl( p->orig_len ) ;
    }
    
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    // Make sure all 'incl_len' bytes are read, otherise return false.
    if (p->incl_len > MAXFRAMESZ)
    {
        fread(ethFrame, MAXFRAMESZ, 1, pcapInput);
        fseek(pcapInput, p->incl_len - MAXFRAMESZ, SEEK_CUR);
    }
    else
        fread(ethFrame, p->incl_len, 1, pcapInput);

    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    // time precision (instead of micro seconds )
    if ( ! baseTimeSet )
    {
        baseTime = p->ts_sec + p->ts_usec * 0.000001 ;
        baseTimeSet = true ;
    }
    
    return true ;
}


/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
   
void printPacketMetaData( const packetHdr_t *p )
{
    double timeStamp = p->ts_sec + p->ts_usec * 0.000001 - baseTime ;
    printf("%6d   %12.6f %5u / %5u " , packetNumber, timeStamp, p->orig_len , p->incl_len ) ;
    packetNumber++ ;
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void printPacket( const etherHdr_t *frPtr )
{
    uint16_t    ethType;
    ethType = ntohs( frPtr -> eth_type ) ;

    char srcMac[MAXMACADDRLEN] , dstMac[MAXMACADDRLEN] ;
    macToStr( frPtr->eth_srcMAC , srcMac , MAXMACADDRLEN ) ;
    macToStr( frPtr->eth_dstMAC , dstMac , MAXMACADDRLEN ) ;
    char * belong = myMAC((uint8_t *)(frPtr -> eth_dstMAC)) ? "mine" : "NOT mine" ;
    printf("%s is %s", dstMac, belong);

    

    // Missing Code Here
    // If this is an IPv4 packet, print Source/Destination IP addresses
    // Otherwise, print Source/Destination MAC addresses

    switch( ethType )
    {
        case PROTO_ARP:     // Print ARP message
            //printf("%-20s %-20s " , srcMac , dstMac);
            //printARPinfo( (arpMsg_t *)(frPtr+1) ) ;
            return ;
        case PROTO_IPv4:    // Print IP datagram and upper protocols
            //printIPinfo( (ipv4Hdr_t *)(frPtr+1) ) ;
            return ;
        default:
            //printf("%-20s %-20s " , srcMac , dstMac);    
            //printf( "%s" , "Protocol 86dd Not Supported Yet" ) ; 
            return ;
    }
}

/*-------------------------------------------------------------------------*/
/* Print ARP messages   
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void printARPinfo(const arpMsg_t * p) {
  // Source and Destination IPs to Strings
  char src_mac[24];
  char dst_mac[24];
  char src_ip[18];
  char dst_ip[18];
  macToStr(p -> arp_sha, src_mac, sizeof(src_mac));
  macToStr(p -> arp_tha, dst_mac, sizeof(dst_mac));
  ipToStr(p -> arp_spa, src_ip);
  ipToStr(p -> arp_tpa, dst_ip);

  printf("%-8s ", "ARP");
  switch (ntohs(p -> arp_oper)) {
    case ARPREQUEST:
      printf("Who has %s ? ", dst_ip);
      printf("Tell %s", src_ip);
      break;
    case ARPREPLY:
      printf("%s is at %-18s", src_ip, src_mac);
      break;
    default:
      printf("Invalid ARP Operation %4x", p -> arp_oper);
      break;
  }
}

/*-------------------------------------------------------------------------*/
/* Print IP datagram and upper protocols  
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void    printIPinfo ( const ipv4Hdr_t *q )
{

    void       *nextHdr ;
    icmpHdr_t  *ic ;
    udpHdr_t   *ud ;
    tcpHdr_t   *tc ;
    unsigned   ipHdrLen, ipPayLen , dataLen=0 ;
    char       srcIP[MAXIPv4ADDRLEN] , dstIP[MAXIPv4ADDRLEN] ;

    // 'dataLen' is the number of bytes in the payload of the encapsulated
    // protocol without its header. For example, it could be the number of bytes
    // in the payload of the encapsulated ICMP message

    ipHdrLen = (q->ip_verHlen & 0x0F) * 4 ;
    ipPayLen = ntohs(q->ip_totLen) - ipHdrLen ;
    nextHdr = (char *)q + ipHdrLen;

    ipToStr( q->ip_srcIP , srcIP ) ;
    ipToStr( q->ip_dstIP , dstIP ) ;

    //printf("%-20s %-20s " , srcIP , dstIP);

     
    switch ( q->ip_proto )
    {
        case PROTO_ICMP: 
            printf( "%-8s " , "ICMP" ) ; 
            // Print IP header length and numBytes of the options
            // Print the details of the ICMP message by calling printICMPinfo( ic ) 
            // Compute 'dataLen' : the length of the data section inside the ICMP message
            printf("IPhdr=%2u (Options %d bytes)", ipHdrLen, ipHdrLen - 20);

            ic = (icmpHdr_t *)nextHdr;
            dataLen = ipPayLen - sizeof(icmpHdr_t);
            printICMPinfo(ic);
            break ;
        case PROTO_TCP: 
            printf( "%-8s " , "TCP" ) ;
            printf("IPhdr=%2u (Options %d bytes) ", ipHdrLen, ipHdrLen - 20);
            tc = (tcpHdr_t *)nextHdr;
            dataLen = ipPayLen - printTCPinfo(tc);
            break ;
        case PROTO_UDP: 
            printf( "%-8s " , "UDP" ) ; 
            printf("IPhdr=%2u (Options %d bytes) ", ipHdrLen, ipHdrLen - 20);
            ud = (udpHdr_t *)nextHdr;
            dataLen = ipPayLen - sizeof(udpHdr_t);
            printUDPinfo(ud);            
            break ;
        default:    
            printf( "%s" ,  "Protocol Not Supported Yet" ) ;
            // Print IP header length and numBytes of the options
            printf("IPhdr=%2u (Options %d bytes)", ipHdrLen, ipHdrLen - 20);
            return ;
    }

    printf(" AppData=%5u" , dataLen ) ;

}

/*-------------------------------------------------------------------------*/
/* Print the ICMP info.  
   Recall that all multi-byte data is in Network-Byte-Ordering
   Returns length of the ICMP header in bytes  
*/

unsigned printICMPinfo( const icmpHdr_t *p ) 
{
    unsigned icmpHdrLen = sizeof( icmpHdr_t ) ;
    uint16_t    *id , *seqNum ;

    // Missing Code Here
    id = (uint16_t *)p->icmp_line2;
    seqNum = (uint16_t *)(p->icmp_line2 + 2);
    
    switch ( p->icmp_type )
    {
        case ICMP_ECHO_REPLY:       
            // Verify code == 0, 
            if (p->icmp_code != 0)
            {
                printf("Invalid Echo Reply Code: %3d", p->icmp_code);
                break;
            }
            printf("Echo Reply   id(BE)=0x%04x, seq(BE)=%5u", ntohs(*id), ntohs(*seqNum));
            break ;
    
        case ICMP_ECHO_REQUEST: 
            // Verify code == 0, 
            if (p->icmp_code != 0)
            {
                printf("Invalid Echo Reply Code: %3d", p->icmp_code);
                break;
            }
            printf("Echo Request id(BE)=0x%04x, seq(BE)=%5u", ntohs(*id), ntohs(*seqNum));
            // Missing Code Here
            break ;
    
        default:
            printf("ICMP Type  %3d (code %3d) not yet supported." , p->icmp_type , p->icmp_code );
    }

    printf(" ICMPhdr=%4u" , icmpHdrLen );
    return icmpHdrLen ;
}

unsigned printTCPinfo ( const tcpHdr_t *p )
{
    uint16_t    srcPort, dstPort;
    uint32_t    seqNum, ackNum;
    uint8_t     hdrLen, flags;
    uint16_t    winSize;
    char flagString[32];
    struct servent *service;

    srcPort = ntohs(p->tcp_srcPort);
    dstPort = ntohs(p->tcp_dstPort);
    seqNum = ntohl(p->tcp_seqNum);
    ackNum = ntohl(p->tcp_ackNum);
    hdrLen = ((p->tcp_hdrLen >> 4) & 0x0F) * 4;
    flags = p->tcp_flags;
    winSize = ntohs(p->tcp_winSize);

    printf("TCPhdr=%2u (Options %2u bytes) ", hdrLen , hdrLen - 20);
    
    service = getservbyport(p->tcp_srcPort, NULL);
    printf("Port %5u ", srcPort);
    printPortName(service);

    service = getservbyport(p->tcp_dstPort, NULL);
    printf("-> %5u ", dstPort);
    printPortName(service);

    
    snprintf(flagString, sizeof(flagString), "[%s%s%s%s%s]",
         (flags & 0x02) ? "SYN " : "    ",  // SYN flag
         (flags & 0x08) ? "PSH " : "    ",  // PSH flag
         (flags & 0x10) ? "ACK " : "    ",  // ACK flag
         (flags & 0x01) ? "FIN " : "    ",  // FIN flag
         (flags & 0x04) ? "RST " : "    ");  // RST flag

    printf("%s ", flagString);

    printf("Seq=%10u ", seqNum);
    if (flags & 0x10) // ACK
    {
        printf("Ack=%10u ", ackNum);
    } 
    else
    {
        printf("               ");
    }
    printf("Rwnd=%5hu", winSize);

    return hdrLen;
}

unsigned printUDPinfo ( const udpHdr_t *p )
{
    unsigned    udpHdrLen = sizeof( udpHdr_t );
    uint16_t    srcPort, dstPort;
    uint16_t    udpLen;
    struct servent *service;

    srcPort = htons(p->udp_srcPort);
    dstPort = htons(p->udp_dstPort);
    udpLen = ntohs(p->udp_len);

    printf("UDP %5u Bytes. ", udpLen);

    service = getservbyport(p->udp_srcPort, NULL);
    printf("Port %5u ", srcPort);
    printPortName(service);

    service = getservbyport(p->udp_dstPort, NULL);
    printf("-> %5u ", dstPort);
    printPortName(service);

    return udpHdrLen;
}


int readARPmap (char *arpDB) {
    printf("Here is the listing of my ARP mapping database:\n");

    FILE * fp = fopen(arpDB, "r");
    if (fp == NULL) return -1;

    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    
    // Reads each line of arpDB file
    while ((read = getline(&line, &len, fp)) != -1) {
      arpmap_t mapping;

      // Seperate MAC and IPv4
      char * token = strtok_r(line, " ", &line);

      // Splitting and Converting IP Bytes
      char * ipTok;
      for (int i = 0; i < 4; i++) {
        ipTok = strtok_r(NULL, ".", &token);
        mapping.arpmap_ip.byte[i] = atoi(ipTok);
      }

      // Splitting and Converting MAC Bytes
      token = strtok_r(NULL, "\n", &line);
      char * macTok;
      for (int i = 0; i < 6; i++) {
        macTok = strtok_r(NULL, ":", &token);
        mapping.arpmap_mac[i] = strtol(macTok, NULL, 16); 
      }
      // Appends current mapping to Global Array and Increments
      myARPmap[mapSize] = mapping; 
      
      // Prints database entry
      char ip[18], mac[24];
      printf("%d:%20s%24s\n", mapSize,
                              ipToStr(mapping.arpmap_ip, ip),
                              macToStr(mapping.arpmap_mac, mac, sizeof(mac)));
      mapSize++;  
    }

    fclose(fp);
    return mapSize;
}


uint16_t inet_checksum(void * data, uint16_t lenbytes) {
    uint32_t sum = 0;
    int type = -1;
    ipv4Hdr_t * ipv4;
    icmpHdr_t * icmp;
    
    if (lenbytes == sizeof(ipv4Hdr_t)) {
        type = PROTO_IPv4;
        ipv4 = (ipv4Hdr_t *) data;
    } else {
        type = PROTO_ICMP;
        icmp = (icmpHdr_t *) data;
    }

    if (type == PROTO_IPv4) {
        sum += (ipv4 -> ip_verHlen << 8) + ipv4 -> ip_dscpEcn;
        sum += htons(ipv4 -> ip_totLen);
        sum += htons(ipv4 -> ip_id);
        sum += htons(ipv4 -> ip_flagsFrag);
        sum += (ipv4 -> ip_ttl << 8) + ipv4 -> ip_proto;
        sum += (ipv4 -> ip_srcIP.byte[0] << 8) + ipv4 -> ip_srcIP.byte[1];
        sum += (ipv4 -> ip_srcIP.byte[2] << 8) + ipv4 -> ip_srcIP.byte[3];
        sum += (ipv4 -> ip_dstIP.byte[0] << 8) + ipv4 -> ip_dstIP.byte[1];
        sum += (ipv4 -> ip_dstIP.byte[2] << 8) + ipv4 -> ip_dstIP.byte[3];
        sum = (sum >> 16) + (sum & 0xffff);
    } else if (type == PROTO_ICMP) {
        sum += (icmp -> icmp_type << 8) + icmp -> icmp_code;
        sum += (icmp -> icmp_line2[0] << 8) + icmp -> icmp_line2[1];
        sum += (icmp -> icmp_line2[2] << 8) + icmp -> icmp_line2[3];
        for (int i = 0; i < lenbytes; i += 2) {
            sum += (icmp -> data[i] << 8) + icmp -> data[i + 1];
        }
        sum = (sum >> 16) + (sum & 0xffff);
    }    

    return ~sum;


}

bool myMAC (uint8_t someMAC[]) {
    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // Iterating through all current mappings
    // in myARPmap and comparing to someMAC[]
    for (int i = 0; i < mapSize; i++) {
      if (memcmp(
               &myARPmap[i].arpmap_mac[0],
               &someMAC[0],
               6 * sizeof(uint8_t)) == 0) {
         return true;
       } else if (memcmp(
               &broadcast[0],
               &someMAC[0],
               6 * sizeof(uint8_t)) == 0) {
         return true;
       }
    }
   return false;    
}

bool myIP(IPv4addr someIP, uint8_t **ptr) {
    // Iterating through all current mappings
    // in myARPmap and comparing to someIP, if
    // found, sets *ptr to point at the corresponding MAC
    for (int i = 0; i < mapSize; i++) {
        if (memcmp(&myARPmap[i].arpmap_ip, &someIP, sizeof(IPv4addr)) == 0) {
            if (ptr != NULL) {
                 *ptr = myARPmap[i].arpmap_mac;
            }
            return true;
        }
    }
    *ptr = NULL;
    return false;
}

int writePCAPhdr (char * fname, pcap_hdr_t * p) {
    pcapOutput = fopen(fname, "w");
    if (!pcapOutput)
       return -1;
    if (fwrite(p, sizeof(pcap_hdr_t), 1, pcapOutput) != 1)
       return -1;
    return 0;
}

void processRequestPacket(packetHdr_t * pktHdr, uint8_t ethFrame[]) {
    etherHdr_t * frPtr = (etherHdr_t *) ethFrame;
    unsigned ipHdrLen;
    void * nextHdr;
    uint8_t * mac;

    char dstMac[MAXMACADDRLEN];
    macToStr( frPtr -> eth_dstMAC , dstMac , MAXMACADDRLEN ) ;
    bool belong = myMAC((uint8_t *)(frPtr -> eth_dstMAC));
    char * belongStr = belong ? "mine" : "NOT mine";
    printf("%s is %s\n", dstMac, belongStr);

    if (!belong)
       return;


    int packet_type;
    uint16_t ethtype = ntohs(frPtr -> eth_type);

    switch (ethtype) {
       case PROTO_ARP:

           arpMsg_t * arp = (arpMsg_t *) (&frPtr -> eth_type + 1);
           if (htons(arp -> arp_oper) == 2) // Arp Reply
             return;
           // Checking if packet is to our machine
           if (myIP(arp -> arp_tpa, &mac)) {
                // Write Originial Packet
                fwrite(pktHdr, sizeof(packetHdr_t), 1, pcapOutput);
                fwrite(ethFrame, pktHdr -> incl_len, 1, pcapOutput);
           } else {
              return;
           }

           etherHdr_t * ethPtr = (etherHdr_t *) ethFrame;
           
           // Altering new packet
           arp -> arp_oper = htons(2);
           ipv4Hdr_t * origIP;

           // Swaping fields of ARP packet
           memcpy(&origIP, &arp -> arp_tpa, sizeof(ipv4Hdr_t));
           memcpy(&arp -> arp_tha, &arp -> arp_sha, 6 * sizeof(uint8_t));
           memcpy(&arp -> arp_tpa, &arp -> arp_spa, 4 * sizeof(uint8_t));
           memcpy(&arp -> arp_sha, mac, 6 * sizeof(uint8_t));
           memcpy(&arp -> arp_spa, &origIP, 4 * sizeof(uint8_t));
           // Altering "new" packet header
           pktHdr -> ts_usec + 30;
           if (pktHdr -> ts_usec > 1000) {
             pktHdr -> ts_usec -= 1000;
             pktHdr -> ts_sec += 1;
           }
           // Altering "new" ethernet frame header
           memcpy(ethPtr -> eth_dstMAC, ethPtr -> eth_srcMAC, 6 * sizeof(uint8_t));
           memcpy(ethPtr -> eth_srcMAC, mac,  6 * sizeof(uint8_t));
           // Write new ARP packet
           fwrite(pktHdr, sizeof(packetHdr_t), 1, pcapOutput);
           fwrite(ethFrame, pktHdr -> incl_len, 1, pcapOutput);
           
           break;
       case PROTO_IPv4:
           ipv4Hdr_t * ipv4 = (ipv4Hdr_t *) (&frPtr -> eth_type + 1);
           ipHdrLen = (ipv4 -> ip_verHlen & 0x0F) * 4;
           nextHdr = (char *) ipv4 + ipHdrLen;

           if (ipv4 -> ip_proto != PROTO_ICMP)
             return;
           icmpHdr_t * icmp = (icmpHdr_t *) nextHdr;
	   if (myIP(ipv4 -> ip_dstIP, &mac) &&
               icmp -> icmp_type == ICMP_ECHO_REQUEST) {
              // Write Originial Packet
	      printf("Echo Request [%d] Found!\n", ((icmpHdr_t *) nextHdr) -> icmp_type);
	      fwrite(pktHdr, sizeof(packetHdr_t), 1, pcapOutput);
	      fwrite(ethFrame, pktHdr -> incl_len, 1, pcapOutput);
	   } else {
	      return; // not ours or is echo reply
	   }

           // Altering "new" icmp packet
           icmp -> icmp_type = ICMP_ECHO_REPLY; 
           icmp -> icmp_check = 0;
           icmp -> icmp_check = inet_checksum(icmp, sizeof(icmpHdr_t)); 

           // Altering "new" ipv4 packet
           ipv4 -> ip_id = 1000;
           //ipv4 -> ip_flagsFrag = 0x4000;
           //IPv4addr tempIP = ipv4 -> ip_srcIP;
           //ipv4 -> ip_srcIP = ipv4 -> ip_dstIP;
           //ipv4 -> ip_dstIP = tempIP;

           // Write new ARP packet
           fwrite(pktHdr, sizeof(packetHdr_t), 1, pcapOutput);
           fwrite(ethFrame, pktHdr -> incl_len, 1, pcapOutput);
           
	   break;
	 default:
	   break;
    }
}

/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/

/* Convert IPv4 address 'ip' into a dotted-decimal string in 'ipBuf'. 
   Returns 'ipBuf'  */
 
char * ipToStr( const IPv4addr ip , char *ipBuf )
{
    // Missing Code Here
    snprintf(ipBuf, MAXIPv4ADDRLEN, "%u.%u.%u.%u",
     ip.byte[0], ip.byte[1], ip.byte[2], ip.byte[3]) ;
    return ipBuf;
}

/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Do not overflow this buffer
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf , int size )
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf ;
}

void printPortName(struct servent *service) {
    if (service == NULL) {
        printf("(   *** ) ");
    } else {
        printf("(%7s) ", service->s_name);
    }
}




