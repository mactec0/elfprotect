#include <stdlib.h>
#include <time.h>
#include "sdk.h"

#ifdef ENABLE_PROTECTION
__attribute__((sysv_abi))
void destroy_code(int32_t len) {
    static bool first_run = true;
    static uint32_t seed = 0;

    if (first_run) {
        first_run = false;
        seed = time(0);
    }

    uint8_t* code = __builtin_extract_return_addr(__builtin_return_address(0));
    code -= 15;

    while (len-- > 0)
        *(code--) = (uint8_t)(rand_r(&seed) % 255);
}
#endif
