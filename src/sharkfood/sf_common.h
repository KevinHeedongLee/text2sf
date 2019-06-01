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
** Common constants and types for Sharkfood.
*/

#ifndef SF_COMMON_H_
#define SF_COMMON_H_

/*############################################################################*/
/*
** Public constants.
*/

#define SHARKFOOD_HEADER_SIZE    ( 4 * sizeof( uint8_t ) )

/* 'Data source', i.e. the party that generated or produced the data. */
#define SHARKFOOD_SRC_APPL       0x80
#define SHARKFOOD_SRC_ABCC       0x40
#define SHARKFOOD_SRC_DRV        0xC0

/* 'Content type', i.e. the meaning of the data after the header. */
#define SHARKFOOD_CONT_RESET     0x01
#define SHARKFOOD_CONT_STATE     0x02
#define SHARKFOOD_CONT_MEM       0x03
#define SHARKFOOD_CONT_UART      0x04
#define SHARKFOOD_CONT_SPI       0x05
#define SHARKFOOD_CONT_PD        0x06
#define SHARKFOOD_CONT_MSG       0x07
#define SHARKFOOD_CONT_TEXT      0x08
#define SHARKFOOD_CONT_ERROR     0x09

/*
** Present maximum payload size is assumed to be a 4kbyte 'memory access'
** operation against the PD areas, i.e. 2 + 2 + 4096 bytes.
*/
#define SHARKFOOD_MAX_PAYLOAD_SIZE     ( 2 + 2 + 4096 )

/*############################################################################*/
/*
** Public macros.
*/

/*############################################################################*/
/*
** Public tag and type definitions.
*/

PACKED_DATA_ON
struct sharkfood_record_tag {
   struct sharkfood_header_tag {
      uint8_t     src_cont;      /* Data source + content */
      uint8_t     seq;           /* Sequence number, increment *after* each successful 'build' call. */
      uint16_t    size;          /* Payload size in bytes. */
   } header;
   uint8_t        data[ SHARKFOOD_MAX_PAYLOAD_SIZE ];
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

#endif
/*############################################################################*/
/*
** End of "sf_common.h"
*/
