#include "volkenborn2.h"

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static double now_ticks(void) { return (double)clock(); }

int main(void) {
    uint8_t a[32], b[32];
    enum { N = 20000 };
    double sum0 = 0, sum1 = 0, sumsq0 = 0, sumsq1 = 0;
    int n0 = 0, n1 = 0;
    for (int i = 0; i < 32; ++i) { a[i] = (uint8_t)(i * 7 + 1); b[i] = a[i]; }
    for (int i = 0; i < N; ++i) {
        int cls = i & 1;
        if (cls) b[(i >> 1) & 31] ^= 1u;
        double t0 = now_ticks();
        volatile int ok = v2_tag_equal(a, b);
        double t1 = now_ticks();
        (void)ok;
        double dt = t1 - t0;
        if (cls) { sum1 += dt; sumsq1 += dt * dt; n1++; b[(i >> 1) & 31] ^= 1u; }
        else { sum0 += dt; sumsq0 += dt * dt; n0++; }
    }
    double mean0 = sum0 / n0, mean1 = sum1 / n1;
    double var0 = (sumsq0 / n0) - mean0 * mean0;
    double var1 = (sumsq1 / n1) - mean1 * mean1;
    double denom = sqrt(var0 / n0 + var1 / n1);
    double t = denom > 0.0 ? (mean0 - mean1) / denom : 0.0;
    printf("dudect_smoke tag_equal mean_equal=%.6f mean_diff=%.6f t=%.6f\n", mean0, mean1, t);
    printf("Interpretation: smoke only; use real dudect/perf counters for audit-grade timing. |t| > 10 is suspicious.\n");
    return (t < -10.0 || t > 10.0) ? 2 : 0;
}
