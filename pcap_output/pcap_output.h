/*
** COPYRIGHT NOTIFICATION (c) 2019 HMS Industrial Networks AB
**
** This code is the property of HMS Industrial Networks AB.
** The source code may not be reproduced, distributed, or used without
** permission.
**
** THE CODE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. HMS DOES NOT
** WARRANT THAT THE FUNCTIONS OF THE CODE WILL MEET YOUR REQUIREMENTS, OR
** THAT THE OPERATION OF THE CODE WILL BE UNINTERRUPTED OR ERROR-FREE, OR
** THAT DEFECTS IN IT CAN BE CORRECTED.
*/

/*############################################################################*/
/*
** Header for PCAP_OUTPUT.C
*/

#ifndef PCAP_OUTPUT_H_
#define PCAP_OUTPUT_H_

/*############################################################################*/
/*
** Public constants.
*/

#define ETHERNET_MACID_SIZE         6
#define ETHERNET_MAX_DATA_SIZE      9000 /* Max size for a common jumbo frame. */

#define ETHERNET_ETHERTYPE_EXPERIMENTAL1     0x88B5
#define ETHERNET_ETHERTYPE_EXPERIMENTAL2     0x88B6

/*############################################################################*/
/*
** Public macros.
*/

/*############################################################################*/
/*
** Public tag and type definitions.
*/

PACKED_DATA_ON
struct pcap_file_header_tag {
   uint32_t       magic;
   uint16_t       major;
   uint16_t       minor;
   int32_t        thiszone;
   uint32_t       sigfigs;
   uint32_t       snaplen;
   uint32_t       network;
} PACKED_DATA;
PACKED_DATA_OFF

PACKED_DATA_ON
struct pcap_record_tag {
   struct pcap_record_header_tag {
      uint32_t       sec;
      uint32_t       usec;
      uint32_t       incl_len;
      uint32_t       orig_len;
   } record_header;
   struct {
      uint8_t        dstmac[ ETHERNET_MACID_SIZE ];
      uint8_t        srcmac[ ETHERNET_MACID_SIZE ];
      uint16_t       type;
   } ether_header;
   uint8_t           data[ ETHERNET_MAX_DATA_SIZE ];
} PACKED_DATA;
PACKED_DATA_OFF

/*############################################################################*/
/*
** Public globals.
*/

/*############################################################################*/
/*
** Public functions.
*/

/*
**-----------------------------------------------------------------------------
** pcap_write_file_header()
**
** Generates and writes a PCAP file header to a stream.
**
** Inputs:
**    file              Stream to write to.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
extern bool pcap_write_file_header( FILE* file );

/*
**-----------------------------------------------------------------------------
** pcap_init_record()
**
** Initialises a PCAP record with the given values. 
**
** Inputs:
**    ptr               Pointer to PCAP record.
**    dstmac            Ethernet destination MACID.
**    srcmac            Ethernet source MACID.
**    ethertype         Ethertype value.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
extern void pcap_init_record( struct pcap_record_tag* ptr, uint8_t* dstmac, uint8_t* srcmac, uint16_t ethertype );

/*
**-----------------------------------------------------------------------------
** pcap_set_record_size()
**
** Updates the size values of a record. Will pad the data field to the minimum
** size first if needed.
**
** Inputs:
**    ptr               Pointer to PCAP record.
**    size              Payload size.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
extern bool pcap_set_record_size( struct pcap_record_tag* ptr, uint32_t size );

/*
**-----------------------------------------------------------------------------
** pcap_write_record()
**
** Writes a PCAP record to a stream.
**
** Inputs:
**    ptr               Pointer to PCAP record.
**    file              Stream to write to.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
extern bool pcap_write_record( struct pcap_record_tag* ptr, FILE* file );

/*
**-----------------------------------------------------------------------------
** pcap_set_present_time()
**
** Updates a PCAP record timestamp to the present time.
**
** Inputs:
**    ptr               Pointer to PCAP record.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
bool pcap_set_present_time( struct pcap_record_tag* ptr );

#endif
/*############################################################################*/
/*
** End of "pcap_output.h"
*/
