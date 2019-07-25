#ifndef CRYPTONIGHT_H
#define CRYPTONIGHT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void c_cryptonight_hash(const char* input, char* output, uint32_t len, int variant);
void c_cryptonight_fast_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
