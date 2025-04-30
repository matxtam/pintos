#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <debug.h>
#include <stdint.h>
#include <stdlib.h>

typedef int fp;
#define Q_FP 14

#define INT_2_FP(n) (n << Q_FP)
#define FP_2_INT_CUT(x) (x >> Q_FP)
#define FP_2_INT_NEAREST(x) x > 0 ? (x + (1 << Q_FP) / 2) : (x - (1 << Q_FP) / 2) 

#define FP_ADD(x, y) (x + y)
#define FP_SUB(x, y) (x - y)
#define FP_INT_ADD(x, n) (x + (n << Q_FP))
#define FP_INT_SUB(x, n) (x - (n << Q_FP))

#define FP_MUL(x, y) ((((int64_t)x) * y) >> Q_FP)
#define FP_DIV(x, y) ((((int64_t)x) * (1 << Q_FP)) / y)
#define FP_INT_MUL(x, n) (x * n)
#define FP_INT_DIV(x, n) (x / n)

#endif
