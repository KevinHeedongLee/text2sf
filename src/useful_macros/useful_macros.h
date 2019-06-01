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
** Useful macros.
*/

#ifndef USEFUL_MACROS_H_
#define USEFUL_MACROS_H_

/*############################################################################*/
/*
** Public constants.
*/

/*############################################################################*/
/*
** Public macros.
*/

/*
** Compiler-specific packing directives.
*/
#if defined __GNUC__
#define PACKED_DATA_ON
#define PACKED_DATA_OFF
#define PACKED_DATA __attribute__((packed))
#elif defined _MSC_VER
#define PACKED_DATA_ON __pragma(pack(push,BYTEALIGN,1))
#define PACKED_DATA_OFF __pragma(pack(pop,BYTEALIGN))
#define PACKED_DATA
#endif

/*
** Min/Max of two values.
*/
#define MINOF(a,b)      ((a)<(b)?(a):(b))
#define MAXOF(a,b)      ((a)>(b)?(a):(b))

/*
** Change the state of a BOOL.
*/
#define BOOL_FLIP(arg)  (arg)=!(arg)

/*
** Endian conversion macros. Tweak detection functions when needed.
**
** TODO - replace this with functions that can be inlined.
*/
#if defined ENDIANNESS
#error ENDIANNESS already defined!
#endif
#if defined __GNUC__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ENDIANNESS 'L'
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ENDIANNESS 'B'
#endif
#elif defined _MSC_VER
#if defined _WIN32 || defined _WIN64
/* All present Win32 and Win64 platforms are L.E. ? */
#define ENDIANNESS 'L'
#endif
#endif
#if ENDIANNESS == 'B'
#define iBeTOi( iBeFoo )    (uint16_t)( iBeFoo )
#define iTOiBe( iFoo )      (uint16_t)( iFoo )
#define iLeTOi( iLeFoo )    (uint16_t)( ( ( ( iLeFoo ) & 0x00FF ) << 8 ) | ( ( ( iLeFoo ) & 0xFF00 ) >> 8 ) )
#define iTOiLe( iFoo )      (uint16_t)( ( ( ( iFoo )   & 0x00FF ) << 8 ) | ( ( ( iFoo )   & 0xFF00 ) >> 8 ) )
#define lBeTOl( lBeFoo )    (uint32_t)( lBeFoo )
#define lTOlBe( lFoo )      (uint32_t)( lFoo )
#define lLeTOl( lLeFoo )    (uint32_t)(  (((lLeFoo) & 0x000000FFL) << 24) | (((lLeFoo) & 0xFF000000L) >> 24)  | (((lLeFoo) & 0x0000FF00L) << 8)  | (((lLeFoo) & 0x00FF0000L) >> 8)  )
#define lTOlLe( lFoo )      (uint32_t)(  (((lFoo) & 0x000000FFL) << 24) | (((lFoo) & 0xFF000000L) >> 24)  | (((lFoo) & 0x0000FF00L) << 8)  | (((lFoo) & 0x00FF0000L) >> 8)  )
#define lBeTOl64( lBeFoo )  (uint64_t)( lBeFoo )
#define lTOlBe64( lFoo )    (uint64_t)( lFoo )
#define lLeTOl64( lLeFoo )  (uint64_t)( ( (uint64_t)lLeTOl( (uint32_t)( lLeFoo & 0x00000000FFFFFFFFLL ) ) << 32 ) | (uint64_t)lLeTOl( (uint32_t)( ( lLeFoo & 0xFFFFFFFF00000000LL ) >> 32 ) ) )
#define lTOlLe64( lFoo )    (uint64_t)( ( (uint64_t)lTOlLe( (uint32_t)( lFoo   & 0x00000000FFFFFFFFLL ) ) << 32 ) | (uint64_t)lTOlLe( (uint32_t)( ( lFoo   & 0xFFFFFFFF00000000LL ) >> 32 ) ) )
#elif ENDIANNESS == 'L'
#define iBeTOi( iBeFoo )    (uint16_t)( ( ( ( iBeFoo ) & 0x00FF ) << 8 ) | ( ( ( iBeFoo ) & 0xFF00 ) >> 8 ) )
#define iTOiBe( iFoo )      (uint16_t)( ( ( ( iFoo )   & 0x00FF ) << 8 ) | ( ( ( iFoo )   & 0xFF00 ) >> 8 ) )
#define iLeTOi( iLeFoo )    (uint16_t)( iLeFoo )
#define iTOiLe( iFoo )      (uint16_t)( iFoo )
#define lBeTOl( lBeFoo )    (uint32_t)( (((lBeFoo) & 0x000000FFL) << 24) | (((lBeFoo) & 0xFF000000L) >> 24)  | (((lBeFoo) & 0x0000FF00L) << 8)  | (((lBeFoo) & 0x00FF0000L) >> 8) )
#define lTOlBe( lFoo )      (uint32_t)( (((lFoo) & 0x000000FFL) << 24) | (((lFoo) & 0xFF000000L) >> 24)  | (((lFoo) & 0x0000FF00L) << 8)  | (((lFoo) & 0x00FF0000L) >> 8)  )
#define lLeTOl( lLeFoo )    (uint32_t)( lLeFoo )
#define lTOlLe( lFoo )      (uint32_t)( lFoo )
#define lBeTOl64( lBeFoo )  (uint64_t)( ( (uint64_t)lBeTOl( (uint32_t)( lBeFoo & 0x00000000FFFFFFFFLL ) ) << 32 ) | (uint64_t)lBeTOl( (uint32_t)( ( lBeFoo & 0xFFFFFFFF00000000LL ) >> 32 ) ) )
#define lTOlBe64( lFoo )    (uint64_t)( ( (uint64_t)lTOlBe( (uint32_t)( lFoo   & 0x00000000FFFFFFFFLL ) ) << 32 ) | (uint64_t)lTOlBe( (uint32_t)( ( lFoo   & 0xFFFFFFFF00000000LL ) >> 32 ) ) )
#define lLeTOl64( lLeFoo )  (uint64_t)( lLeFoo )
#define lTOlLe64( lFoo )    (uint64_t)( lFoo )
#else
#error Unknown compiler, endianness could not be set automatically!
#endif
#undef ENDIANNESS

/*
** 'Ceiling' for division of positive integers.
*/
#define DIV_CEILING(x,y)   (1+(((x)-1)/(y)))

/*
** 'sizeof' for struct fields.
*/
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

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

#endif
/*############################################################################*/
/*
** End of "useful_macros.h"
*/
