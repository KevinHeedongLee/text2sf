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
** PCAP_OUTPUT.C - Simple generator to make Ethernet-style PCAP files.
*/

/*############################################################################*/
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <inttypes.h>
#include <stdbool.h>

#include <stdio.h>
#include <string.h>

#include "useful_macros.h"
#include "pcap_output.h"


/*############################################################################*/
/*
** Local constants.
*/

#define PCAP_MAGIC_COOKIE           0xA1B2C3D4
#define PCAP_MAJOR                  2
#define PCAP_MINOR                  4
#define PCAP_SIGFIGS                0
#define PCAP_LINKTYPE_ETHERNET      1

#define ETHERNET_ETHERTYPE_SIZE     2

#define ETHERNET_MIN_DATA_SIZE      60

#define UNIX_TIME_START    0x019DB1DED53E8000 /* January 1, 1970 (start of Unix epoch) in system ticks. */
#define TICKS_PER_SECOND   10000000 /* One tick is 100ns. */

/*############################################################################*/
/*
** Local macros.
*/

/*############################################################################*/
/*
** Local tag and type definitions.
*/

/*############################################################################*/
/*
** Local globals.
*/

/*############################################################################*/
/*
** Public globals.
*/

/*############################################################################*/
/*
** Local forward declarations.
*/

/*############################################################################*/
/*
** Local functions.
*/

/*
**-----------------------------------------------------------------------------
** write_blob()
**
** Write a memory block to a stream. 
**
** Inputs:
**    file              Stream to write to.
**    ptr               Pointer to data.
**    size              Number of bytes to write.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/

bool write_blob( FILE* file, uint8_t* ptr, int size )
{
   if( file == NULL ) {
      return( false );
   }
   if( ptr == NULL ) {
      return( false );
   }
   if( size == 0 ) {
      return( false );
   }

   while( size ) {
      if( fputc( *ptr, file ) == EOF ) {
         return( false );
      }
      ptr++;
      size--;
   }

   return( true );
}

/*############################################################################*/
/*
** Public functions.
*/

/*
**-----------------------------------------------------------------------------
** pcap_write_file_header()
**
** See PCAP_OUTPUT.H for information.
**-----------------------------------------------------------------------------
*/
bool pcap_write_file_header( FILE* file )
{
   struct pcap_file_header_tag   pcap_file_header;

   if( file == NULL ) {
      return( false );
   }

   pcap_file_header.magic = PCAP_MAGIC_COOKIE;
   pcap_file_header.major = PCAP_MAJOR;
   pcap_file_header.minor = PCAP_MINOR;
   pcap_file_header.thiszone = 0;
   pcap_file_header.sigfigs = PCAP_SIGFIGS;
   pcap_file_header.snaplen = sizeof( struct pcap_record_tag );
   pcap_file_header.network = PCAP_LINKTYPE_ETHERNET;

   return( write_blob( file, (uint8_t*)&pcap_file_header, sizeof( pcap_file_header ) ) );
}

/*
**-----------------------------------------------------------------------------
** pcap_init_record()
**
** See PCAP_OUTPUT.H for information.
**-----------------------------------------------------------------------------
*/
void pcap_init_record( struct pcap_record_tag* ptr, uint8_t* dstmac, uint8_t* srcmac, uint16_t ethertype )
{
   if( ptr == NULL ) {
      return;
   }

   ptr->record_header.sec = 0;
   ptr->record_header.usec = 0;
   ptr->record_header.incl_len = 0;
   ptr->record_header.orig_len = 0;
   
   memcpy( ptr->ether_header.dstmac, dstmac, ETHERNET_MACID_SIZE );
   memcpy( ptr->ether_header.srcmac, srcmac, ETHERNET_MACID_SIZE );

   ptr->ether_header.type = iTOiBe( ethertype );

   return;
}

/*
**-----------------------------------------------------------------------------
** pcap_set_record_size()
**
** See PCAP_OUTPUT.H for information.
**-----------------------------------------------------------------------------
*/
bool pcap_set_record_size( struct pcap_record_tag* ptr, uint32_t size )
{
   if( ptr == NULL ) {
      return( false );
   }
   if( size > ETHERNET_MAX_DATA_SIZE ) {
      return( false );
   }

   ptr->record_header.incl_len = 2 * ETHERNET_MACID_SIZE + ETHERNET_ETHERTYPE_SIZE + size;
   if( ptr->record_header.incl_len < ETHERNET_MIN_DATA_SIZE ) {
      memset( ptr->data + size, 0xFF, ETHERNET_MIN_DATA_SIZE - ptr->record_header.incl_len );
      ptr->record_header.incl_len = ETHERNET_MIN_DATA_SIZE;
   }
   ptr->record_header.orig_len = ptr->record_header.incl_len;

   return( true );
}

/*
**-----------------------------------------------------------------------------
** pcap_write_record()
**
** See PCAP_OUTPUT.H for information.
**-----------------------------------------------------------------------------
*/
bool pcap_write_record( struct pcap_record_tag* ptr, FILE* file )
{
   if( ptr == NULL ) {
      return( false );
   }
   if( file == NULL ) {
      return( false );
   }

   return( write_blob( file, (uint8_t*)ptr, sizeof( struct pcap_record_header_tag ) + ptr->record_header.incl_len ) );
}

/*
**-----------------------------------------------------------------------------
** pcap_write_record()
**
** See PCAP_OUTPUT.H for information.
**-----------------------------------------------------------------------------
*/
bool pcap_set_present_time( struct pcap_record_tag* ptr )
{
   FILETIME       timestamp;
   LARGE_INTEGER  largeint;

   if( ptr == NULL ) {
      return( false );
   }
   
   GetSystemTimeAsFileTime( &timestamp );
   largeint.LowPart = timestamp.dwLowDateTime;
   largeint.HighPart = timestamp.dwHighDateTime;

   /* Adjust to UNIX epoch time. */
   largeint.QuadPart -= UNIX_TIME_START;
   ptr->record_header.sec = (DWORD)( largeint.QuadPart / TICKS_PER_SECOND );
   largeint.QuadPart -= ( ptr->record_header.sec * TICKS_PER_SECOND );

   /* Truncate the timestamp at the us level. */
   largeint.QuadPart /= 10;   /* 100ns -> 1us */

   ptr->record_header.usec = (DWORD) largeint.QuadPart;

   return( true );
}

/*############################################################################*/
/*
** End of "pcap_output.c"
*/
