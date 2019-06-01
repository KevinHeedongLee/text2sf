#ifndef STDBOOL_H
#define STDBOOL_H

#ifdef _MSC_VER
   #if _MSC_VER >= 1800
      #include <stdbool.h>
   #else
      #ifdef __cplusplus
         /* Some kind of 'bool' should already be defined... */
      #else
         #define bool int
         #define false 0
         #define true (!false)
      #endif
   #endif
#else
   #include <stdbool.h>
#endif

#endif /* stdbool.h */