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
** SF_BUILD_FUNCTIONS.C - Functions to generate Sharkfood data.
*/

/*############################################################################*/
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <inttypes.h>
#include <stdbool.h>

#include "useful_macros.h"

#define PACKED_STRUCT PACKED_DATA         /* So that abp.h will use the PACKED... from useful_macros.h */
#define ABCC_SYS_PACK_ON PACKED_DATA_ON   /* So that abp.h will use the PACKED... from useful_macros.h */
#define ABCC_SYS_PACK_OFF PACKED_DATA_OFF /* So that abp.h will use the PACKED... from useful_macros.h */
#include "abcc_td.h"        
#include "abp.h"

#include "sf_common.h"
#include "sf_build_functions.h"

/*############################################################################*/
/*
** Local constants.
*/

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

/*############################################################################*/
/*
** Public functions.
*/

/*
**-----------------------------------------------------------------------------
** sf_inc_seq_cnt()
**
** See SF_BUILD_FUNCTIONS.H for information.
**-----------------------------------------------------------------------------
*/
bool sf_inc_seq_cnt( struct sharkfood_record_tag* ptr )
{
   if( ptr == NULL ) {
      return( false );
   }

   ptr->header.seq++;

   return( true );
}

/*
**-----------------------------------------------------------------------------
** sf_inc_seq_cnt()
**
** See SF_BUILD_FUNCTIONS.H for information.
**-----------------------------------------------------------------------------
*/
bool sf_build_abccstate_msg( struct sharkfood_record_tag* ptr, ABP_AnbStateType state )
{
   if( ptr == NULL ) {
      return( false );
   }
   
   ptr->header.src_cont = SHARKFOOD_SRC_ABCC | SHARKFOOD_CONT_STATE;
   ptr->header.size = iTOiLe( sizeof( uint8_t ) );

   ptr->data[ 0 ] = (uint8_t)state;

   return( true );   
}

/*
**-----------------------------------------------------------------------------
** sf_inc_seq_cnt()
**
** See SF_BUILD_FUNCTIONS.H for information.
**-----------------------------------------------------------------------------
*/
bool sf_build_abccmsg_msg( struct sharkfood_record_tag* sf_ptr, uint8_t source, ABP_MsgType8* msg_ptr )
{
   uint8_t*                      dst;

   if( sf_ptr == NULL ) {
      return( false );
   }
   if( source == 0 ) {
      return( false );
   }
   if( msg_ptr == NULL ) {
      return( false );
   }
// Message layout header : 12 bytes
   sf_ptr->header.src_cont = source | SHARKFOOD_CONT_MSG;
   sf_ptr->header.size = iTOiLe( 12 + msg_ptr->sHeader.iDataSize );
   
   dst = sf_ptr->data;

   *(uint16_t*)dst = iTOiLe( msg_ptr->sHeader.iDataSize );
   dst += sizeof( uint16_t );

   *(uint16_t*)dst = iTOiLe( msg_ptr->sHeader.iReserved );
   dst += sizeof( uint16_t );

   *dst = msg_ptr->sHeader.bSourceId;
   dst += sizeof( uint8_t );

   *dst = msg_ptr->sHeader.bDestObj;
   dst += sizeof( uint8_t );

   *(uint16_t*)dst = iTOiLe( msg_ptr->sHeader.iInstance );
   dst += sizeof( uint16_t );

   *dst = msg_ptr->sHeader.bCmd;
   dst += sizeof( uint8_t );

   *dst = msg_ptr->sHeader.bReserved;
   dst += sizeof( uint8_t );

   *dst = msg_ptr->sHeader.bCmdExt0;
   dst += sizeof( uint8_t );

   *dst = msg_ptr->sHeader.bCmdExt1;
   dst += sizeof( uint8_t );

   memcpy( dst, msg_ptr->abData, msg_ptr->sHeader.iDataSize );

   return( true );
}

/*############################################################################*/
/*
** End of "sf_build_functions.c"
*/
