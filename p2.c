/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022
    
    Implemented By:     Chingiz Rajabli
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-------------------------------------------------------------------------*/
void usage(char *cmd)
{
    printf("Usage: %s fileName\n" , cmd);
}

/*-------------------------------------------------------------------------*/

#define MAXBUF  10000           /* num Bytes in largest ethenet frame */

int main( int argc  , char *argv[] )
{
    char        *pcapIn ;
    char        *pcapOut ;
    char        *pcapPairs ;
    uint8_t     data[MAXBUF] ;
    pcap_hdr_t  pcapHdr ;
    packetHdr_t pktHdr  ;
    uint8_t     ethFrame[MAXFRAMESZ] ;
    etherHdr_t  *frameHdrPtr = (etherHdr_t  *) ethFrame ;
    
    if ( argc < 4 )
    {
        usage( argv[0] ) ;
        exit ( EXIT_FAILURE ) ;
    }

    pcapIn = argv[1] ;
    pcapOut = argv[2] ;
    pcapPairs = argv[3] ;
    // Read the global header of the pcapInput file
    // By calling readPCAPhdr(). 
    // If error occur, call errorExit("Failed to read global header from the PCAP file "  )
    if (readPCAPhdr(pcapIn, &pcapHdr) != 0)
        errorExit("Failed to read global header from the PCAP file\n");

    if (writePCAPhdr(pcapOut, &pcapHdr) == -1)
       errorExit("Failed to write global header to output file\n");

    int numMappings = readARPmap(pcapPairs);
    //printPCAPhdr(&pcapHdr);

    // Print the global header of the pcap filer
    // using printPCAPhdr()

    // Print labels before any packets are printed
    puts("") ;
    //printf("%6s %14s %11s %-20s %-20s %8s %s\n" ,
    //       "PktNum" , "Time Stamp" , "Org Len/Cap'd"  , 
    //       "Source" , "Destination" , "Protocol" , "info");
    printf("%s  %s\n", "Frame #", "Its Destination MAC");
    // Read one packet at a time
    int count = 1;
    while (getNextPacket( &pktHdr , ethFrame ))
    {

        // Make sure the base time (logical time 0) is set

        // Use packetMetaDataPrint() to print the packet header data;
        // Use packetPrint( ) to print the actual content of the packet starting at the 
        // ethernet level and up

        //printPacketMetaData(&pktHdr);
        printf("%5d )  ", count);
        //printPacket(frameHdrPtr);
        processRequestPacket(&pktHdr, ethFrame);
        count++;
    }
    
    printf("\nReached end of PCAP file '%s' %d packets processed\n" , pcapIn, count - 1) ;
    cleanUp() ;    
}

