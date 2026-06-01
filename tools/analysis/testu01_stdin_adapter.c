/*
 * TestU01 stdin adapter skeleton.
 * Build in an environment with TestU01 installed, then feed Volkenborn-2 stream
 * bytes from stdin. This file is intentionally standalone and not built in CI.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "unif01.h"
#include "bbattery.h"

static unsigned long stdin_bits(void) {
    unsigned char b[4];
    if (fread(b, 1, 4, stdin) != 4) exit(0);
    return ((unsigned long)b[0]) | ((unsigned long)b[1] << 8) | ((unsigned long)b[2] << 16) | ((unsigned long)b[3] << 24);
}

int main(void) {
    unif01_Gen *gen = unif01_CreateExternGenBits("volkenborn2-stdin", stdin_bits);
    bbattery_SmallCrush(gen);
    unif01_DeleteExternGenBits(gen);
    return 0;
}
