#include "volkenborn2.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void derive_inputs(const uint8_t *data, size_t size, uint8_t key[32], uint8_t nonce[16]) {
    for (size_t i = 0; i < 32; ++i) { key[i] = (uint8_t)(0xa5u ^ (uint8_t)i ^ (i < size ? data[i] : 0u)); }
    for (size_t i = 0; i < 16; ++i) { nonce[i] = (uint8_t)(0x5au ^ (uint8_t)i ^ (i + 32u < size ? data[i + 32u] : 0u)); }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t key[32], nonce[16], iv[16], tag[32];
    uint8_t *cipher = NULL;
    uint8_t *plain = NULL;
    uint8_t *recovered = NULL;
    size_t msg_off = size > 48u ? 48u : size;
    size_t msg_len = size - msg_off;
    derive_inputs(data, size, key, nonce);
    v2_derive_message_iv(key, nonce, iv);
    cipher = (uint8_t *)malloc(msg_len == 0u ? 1u : msg_len);
    plain = (uint8_t *)malloc(msg_len == 0u ? 1u : msg_len);
    recovered = (uint8_t *)malloc(msg_len == 0u ? 1u : msg_len);
    if (cipher == NULL || plain == NULL || recovered == NULL) abort();
    if (msg_len != 0u) memcpy(plain, data + msg_off, msg_len);
    v2_seal_poly1305(key, nonce, plain, msg_len, cipher, tag);
    if (!v2_open_poly1305(key, nonce, cipher, msg_len, tag, recovered)) abort();
    if (msg_len != 0u && memcmp(plain, recovered, msg_len) != 0) abort();
    if (msg_len != 0u) {
        cipher[msg_len / 2u] ^= 1u;
        if (v2_open_poly1305(key, nonce, cipher, msg_len, tag, recovered)) abort();
    }
    v2_secure_zero(key, sizeof(key)); v2_secure_zero(nonce, sizeof(nonce)); v2_secure_zero(iv, sizeof(iv));
    v2_secure_zero(tag, sizeof(tag)); v2_secure_zero(cipher, msg_len); v2_secure_zero(plain, msg_len); v2_secure_zero(recovered, msg_len);
    free(cipher); free(plain); free(recovered);
    return 0;
}

#ifndef __AFL_HAVE_MANUAL_CONTROL
int main(void) {
    uint8_t sample[96];
    for (unsigned i = 0; i < sizeof(sample); ++i) sample[i] = (uint8_t)(i * 17u + 3u);
    return LLVMFuzzerTestOneInput(sample, sizeof(sample));
}
#endif
