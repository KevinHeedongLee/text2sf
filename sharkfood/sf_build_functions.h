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

#ifndef SF_BUILD_FUNCTIONS_H_
#define SF_BUILD_FUNCTIONS_H_

/*############################################################################*/
/*
** Public constants.
*/

/*############################################################################*/
/*
** Public macros.
*/

/*############################################################################*/
/*
** Public tag and type definitions.
*/

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
** sf_inc_seq_cnt()
**
** Increment the sequence number in the Sharkfood header.
**
** Inputs:
**    ptr               Pointer to Sharkfood record.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
extern bool sf_inc_seq_cnt( struct sharkfood_record_tag* ptr );

/*
**-----------------------------------------------------------------------------
** sf_build_abccstate_msg()
**
** Build a Sharkfood message containing the 'ABCC state'.
**
** Inputs:
**    ptr               Pointer to Sharkfood record.
** Outputs:
**    -
** Returns:
**    TRUE on success, FALSE otherwise.
**-----------------------------------------------------------------------------
*/
extern bool sf_build_abccstate_msg( struct sharkfood_record_tag* ptr, ABP_AnbStateType state );
extern bool sf_build_abccmsg_msg( struct sharkfood_record_tag* sf_ptr, uint8_t source, ABP_MsgType8* msg_ptr );

#endif
/*############################################################################*/
/*
** End of "sf_common.h"
*/
