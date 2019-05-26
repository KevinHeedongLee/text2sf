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

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <inttypes.h>
#include <stdbool.h>

#include <stdio.h>
#include <string.h>

#include "useful_macros.h" 

#define PACKED_STRUCT PACKED_DATA         /* So that abp.h will use the PACKED... from useful_macros.h */
#define ABCC_SYS_PACK_ON PACKED_DATA_ON   /* So that abp.h will use the PACKED... from useful_macros.h */
#define ABCC_SYS_PACK_OFF PACKED_DATA_OFF /* So that abp.h will use the PACKED... from useful_macros.h */
#include "abcc_td.h"        
#include "abp.h"

#include "pcap_output.h"
#include "sf_common.h"
#include "sf_build_functions.h"

/*############################################################################*/
/*
** Local constants.
*/

#define LINE_FEED                   ( 0xA )
#define CARRIAGE_RETURN             ( 0xD )

/*
** 8kbyte. ("[ " + 1524 * "0x00 " + " ]" = 7624 byte should be enough for a
** hex dump of a full-size ABCC msg data field though.)
*/
#define LINE_BUFFER_SIZE            ( 8 * 1024 )

/*----------------------------------------------------------------------------*/

/*############################################################################*/
/*
** Local macros.
*/

/*############################################################################*/
/*
** Local tag and type definitions.
*/

struct parse_list_tag {
   char*    pattern;
   char*    name;
   char*    format;
   void*    dst;
};

/*############################################################################*/
/*
** Local globals.
*/

static char* state_strings[ 8 ] = {
   "ABP_ANB_STATE_SETUP",
   "ABP_ANB_STATE_NW_INIT",
   "ABP_ANB_STATE_WAIT_PROCESS",
   "ABP_ANB_STATE_IDLE",
   "ABP_ANB_STATE_PROCESS_ACTIVE",
   "ABP_ANB_STATE_ERROR",
   "(reserved)",
   "ABP_ANB_STATE_EXCEPTION"
};

static uint8_t dstmac[ ETHERNET_MACID_SIZE ] = {
   0x02, /* "Locally administered address" */
   's', 'f', 'o', 'o', 'd'
};

static uint8_t srcmac[ ETHERNET_MACID_SIZE ] = {
   0x02, /* "Locally administered address" */
   't', 'x', 't', 'l', 'g'
};

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
** file_read_line()
**
** Reads one line of text from a file, i.e. to the next CR or LF. Blank lines
** are ignored.
**
** Inputs:
**    file              Stream to read from.
**    buffer_ptr        String to write to.
**    buffer_size       Max size of string.
** Outputs:
**    -
** Returns:
**    Number of read characters, or EOF.
**-----------------------------------------------------------------------------
*/
static int file_read_line( FILE* file_ptr, char* buffer_ptr, int buffer_size )
{
	int	index;
	int	tmp;

	/* Sanity checks. */
   if( file_ptr == NULL ) {
		return( 0 );
	}
   if( buffer_ptr == NULL ) {
		return( 0 );
	}
   if( buffer_size < 1 ) {
		return( 0 );
	}
   if( feof( file_ptr ) ) {
		return( EOF );
	}

   index = 0;
   buffer_ptr[ 0 ] = 0;

   while( true ) {
   tmp = fgetc( file_ptr );

   /* The EOF indication is not data, check for that before we do anything else. */
   if( tmp == EOF ) {
      if( index > 0 ) {
         return( index );
      } else {
         return( EOF );
      }
   }

   /* If the data is something other than CR/LF... */
   if( ( tmp != CARRIAGE_RETURN ) && ( tmp != LINE_FEED ) ) {
       /* ...then add it to the buffer... */
      if( index < ( buffer_size - 1 ) ) {
         buffer_ptr[ index ] = ( char )tmp;
         index++;
         /* ...and make sure the buffer is properly terminated. */
         buffer_ptr[ index ] = 0;
      }
   } else {
         if( index > 0 ) {
         /* CR/LF was seen, return whatever data we ended up with. */
         return( index );
         } else {
             /* CR/LF with no buffered data, i.e. blank line. Ignore. */
         }
   }

   };

	return( EOF );
}

/*
**-----------------------------------------------------------------------------
** delete_char_from_string()
**
** Removes all occurences of character 'c' from string.
**
** Inputs:
**    string            String to modify.
**    c                 Character to remove.
** Outputs:
**    -
** Returns:
**    New length of string.
**-----------------------------------------------------------------------------
*/
static int delete_char_from_string( char* string, char c )
{
   int      count;
   char*    src;
   char*    dst;

	/* Sanity checks. */
   if( string == NULL ) {
      return( 0 );
   }

   count = 0;
   src = string;
   dst = string;

   while( *src != 0 ) {
      if( *src != c ) {
         *dst = *src;
         src++;
         dst++;
         count++;
      } else {
         src++;
      }
   }
   *dst = 0; /* ...and make sure that the destination string is terminated. */

   return( count );
}

/*
**-----------------------------------------------------------------------------
** parse_abcc_msg_header()
**
** Parses a 7075+7077-style hex dump of an ABCC message header.
**
** Inputs:
**    string            String to read from.
** Outputs:
**    ptr               Pointer to an ABP_MsgHeaderType struct.
** Returns:
**    New length of string.
**-----------------------------------------------------------------------------
*/
static bool parse_abcc_msg_header( char* string, ABP_MsgType8* ptr )
{
   ABP_MsgHeaderType    tmp_header;
   
   /* Pattern to search for, names, scanf() format string, and storage. */
   struct parse_list_tag   parse_list[] = {
      { "Size:0x",      "Size",        "%4x",   &tmp_header.iDataSize },
      { "SrcId:0x",     "Source ID",   "%2x",   &tmp_header.bSourceId },
      { "DestObj:0x",   "Object",      "%2x",   &tmp_header.bDestObj },
      { "Inst:0x",      "Instance",    "%4x",   &tmp_header.iInstance },
      { "Cmd:0x",       "Command",     "%2x",   &tmp_header.bCmd },
      { "CmdExt0:0x",   "Ext 0",       "%2x",   &tmp_header.bCmdExt0 },
      { "CmdExt1:0x",   "Ext 1",       "%2x",   &tmp_header.bCmdExt1 },
      { NULL,           NULL,          NULL,    NULL }
   };

   char*    char_ptr;
   int      i;
   int      value;

	/* Sanity checks. */
   if( string == NULL ) {
      return( false );
   }
   if( ptr == NULL ) {
      return( false );
   }

   i = 0;
   while( parse_list[ i ].pattern != NULL ) {

      /* Check where/if pattern is present. */
      char_ptr = strstr( string, parse_list[ i ].pattern );
      if( char_ptr == NULL ) {
         fprintf( stderr, "ERROR: '%s' not found!\n", parse_list[ i ].name );
         return( false );
      }
      char_ptr += strlen( parse_list[ i ].pattern );
      
      /* Call scanf() to parse the hex text. */
      if( sscanf( char_ptr, parse_list[ i ].format, &value ) != 1 ) {
         fprintf( stderr, "ERROR: Could not parse '%s' value!\n", parse_list[ i ].name );
         return( false );
      }

      /* Write data to target using appropriate cast. */
      if( strstr( parse_list[ i ].format, "2" ) != NULL ) {
         *(uint8_t*)(parse_list[ i ].dst) = (uint8_t)value;
      } else if( strstr( parse_list[ i ].format, "4" ) != NULL ) {
         *(uint16_t*)(parse_list[ i ].dst) = (uint16_t)value;
      } else {
         fprintf( stderr, "ERROR: WTF?\n" );
         return( false );
      }

      i++;
   }

   /* ...and copy the data to the target structure. */
   ptr->sHeader.iDataSize = tmp_header.iDataSize;
   ptr->sHeader.bSourceId = tmp_header.bSourceId;
   ptr->sHeader.bDestObj = tmp_header.bDestObj;
   ptr->sHeader.iInstance = tmp_header.iInstance;
   ptr->sHeader.bCmd = tmp_header.bCmd;
   ptr->sHeader.bCmdExt0 = tmp_header.bCmdExt0;
   ptr->sHeader.bCmdExt1 = tmp_header.bCmdExt1;
     
   return( true );
};

/*############################################################################*/
/*
** Public functions.
*/

int main( int argc, char* argv[] )
{
   FILE*       input_file;
   FILE*       output_file;
   char*       char_ptr;
   int         tmp;
   int         i;
   int         value;

   uint8_t     line_buffer[ LINE_BUFFER_SIZE ];

   uint8_t                 msg_direction_mask;
   ABP_MsgType8            abcc_msg_buffer;
   struct pcap_record_tag  pcap_record;

   /*
   ** TODO in some suitable way:
   ** assert( FIELD_SIZEOF( struct pcap_record_tag, data ) > sizeof( struct sharkfood_record_tag ) )
   */

   if( argc != 3 ) {
      printf( "Converts ABCC 'stdout' debug printouts to a Sharkfood file.\n" );
      printf( "Use:\text2sf TEXTLOGFILENAME PCAPFILENAME\n" );
      return( -1 );
   }

   input_file = fopen( argv[ 1 ], "rb" );
   if( input_file == NULL ) {
      fprintf( stderr, "Could not open input file!\n" );
      return( -1 );
   }

   output_file = fopen( argv[ 2 ], "wb" );
   if( output_file == NULL ) {
      fprintf( stderr, "Could not open input file!\n" );
      fclose( input_file );
      return( -1 );
   }

   memset( &abcc_msg_buffer, 0, sizeof( abcc_msg_buffer ) );
   memset( &pcap_record, 0, sizeof( pcap_record ) );
   pcap_init_record( &pcap_record, dstmac, srcmac, ETHERNET_ETHERTYPE_EXPERIMENTAL1 );

   pcap_write_file_header( output_file );

   while( true ) {

      /* Fetch next non-blank line. */
      if( file_read_line( input_file, line_buffer, sizeof( line_buffer ) ) == EOF ) {;
         break;
      }

      /*
      ** ABCC state indication?
      ** (Note: the SUP bit is ignored, it is not printed by the default
      ** debug printouts.)
      */
      if( strstr( line_buffer, "ANB_STATUS" ) != NULL ) {

         tmp = 0;
         for( i = 0 ; i < 8 ; i++ ) {
            if( strstr( line_buffer, state_strings[ i ] ) != NULL ) {

               sf_build_abccstate_msg( (struct sharkfood_record_tag*)pcap_record.data, i );
               pcap_set_record_size( &pcap_record, SHARKFOOD_HEADER_SIZE + 1 );
               pcap_set_present_time( &pcap_record );
               pcap_write_record( &pcap_record, output_file );
               sf_inc_seq_cnt( (struct sharkfood_record_tag*)pcap_record.data );
               
               tmp = 1;
               break; /* "for( i = ... )" */
            }
         }
         if( tmp == 0 ) {
            fprintf( stderr, "ERROR: Unkown state name detected!\n" );
            fprintf( stderr, "%s\n", line_buffer );
         }
      }

      /* ABCC message? */
      if( strstr( line_buffer, "Msg " ) != NULL ) {
         /* "do/while" because we can easily break that in case of errors. */
         do {

            /* Which direction? */
            if( strstr( line_buffer, "Msg sent:" ) != NULL ) {
               msg_direction_mask = SHARKFOOD_SRC_APPL;
            } else if( strstr( line_buffer, "Msg received:" ) != NULL ) {
               msg_direction_mask = SHARKFOOD_SRC_ABCC;
            } else {
               fprintf( stderr, "ERROR: Unkown msg direction!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }

            /*
            ** Get the header. Usually two lines, starts with [ and ends with ].
            ** 
            ** [ MsgBuf:0x20005c80 Size:0x0000 SrcId  :0x01 DestObj:0x03
            ** Inst  :0x0001     Cmd :0x41   CmdExt0:0x03 CmdExt1:0x00 ]
            */

            tmp = file_read_line( input_file, line_buffer, sizeof( line_buffer ) );
            if( ( tmp == EOF ) || ( tmp = 0 ) ) {
               fprintf( stderr, "ERROR: EOF or no data when fetching msg header string!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }
            if( strchr( line_buffer, '[' ) == NULL ) {
               fprintf( stderr, "ERROR: No [ found in msg header string!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }
            char_ptr = line_buffer + strlen( line_buffer );
            while( true ) {
               if( strchr( line_buffer, ']' ) != NULL ) break;
               tmp = file_read_line( input_file, char_ptr, sizeof( line_buffer ) - strlen( line_buffer ) - 1 );
               if( ( tmp == 0 ) || ( tmp == EOF ) ) break;
               char_ptr = line_buffer + strlen( line_buffer );
            }
            if( strchr( line_buffer, ']' ) == NULL ) {
               fprintf( stderr, "ERROR: No ] found in msg header string!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }

            delete_char_from_string( line_buffer, ' ' );

            /* Parse the header fields. */

            if( !parse_abcc_msg_header( line_buffer, &abcc_msg_buffer ) )
            {
               fprintf( stderr, "ERROR: Could not parse header!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;  
            };

            /*
            ** Get the message data. Several lines, starts with [ and ends with ].
            ** 
            ** [ 0x11 0x22 0x33 ... 0xff ]
            */

            tmp = file_read_line( input_file, line_buffer, sizeof( line_buffer ) );
            if( ( tmp == EOF ) || ( tmp = 0 ) ) {
               fprintf( stderr, "ERROR: EOF or no data when fetching msg data string!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }
            if( strchr( line_buffer, '[' ) == NULL ) {
               fprintf( stderr, "ERROR: No [ found in msg data string!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }
            char_ptr = line_buffer + strlen( line_buffer );
            while( true ) {
               if( strchr( line_buffer, ']' ) != NULL ) break;
               tmp = file_read_line( input_file, char_ptr, sizeof( line_buffer ) - strlen( line_buffer ) - 1 );
               if( ( tmp == 0 ) || ( tmp == EOF ) ) break;
               char_ptr = line_buffer + strlen( line_buffer );
            }
            if( strchr( line_buffer, ']' ) == NULL ) {
               fprintf( stderr, "ERROR: No ] found in msg data string!\n" );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }

            delete_char_from_string( line_buffer, ' ' );
            
            /* Parse the data field. */

            char_ptr = line_buffer + 1; /* Skip initial [ */
            i = 0;
            while( *char_ptr != ']' ) {
               char_ptr += 2; /* Skip "0x" */
               tmp = sscanf( char_ptr, "%2x", &value );
               if( tmp != 1 ) {
                  fprintf( stderr, "ERROR: Could not parse byte %d in msg data string!\n", i );
                  fprintf( stderr, "%s\n", line_buffer );
                  break;
               }
               abcc_msg_buffer.abData[ i ] = (uint8_t)value;
               char_ptr += 2;
               i++;
            }
            if( i != abcc_msg_buffer.sHeader.iDataSize ) {
               fprintf( stderr, "ERROR: Header size (%d) does not match actual data size (%d)!\n", abcc_msg_buffer.sHeader.iDataSize, i );
               fprintf( stderr, "%s\n", line_buffer );
               break;
            }

            sf_build_abccmsg_msg( (struct sharkfood_record_tag*)pcap_record.data, msg_direction_mask, &abcc_msg_buffer );
            pcap_set_record_size( &pcap_record, SHARKFOOD_HEADER_SIZE + 12 + abcc_msg_buffer.sHeader.iDataSize );
            pcap_set_present_time( &pcap_record );
            pcap_write_record( &pcap_record, output_file );
            sf_inc_seq_cnt( (struct sharkfood_record_tag*)pcap_record.data );

         } while( false );

      } /* End of "ABCC Message?" */

   } /* End of "while( ... != EOF )" */
   fclose( input_file );
   fclose( output_file );

	return( 0 );
}
