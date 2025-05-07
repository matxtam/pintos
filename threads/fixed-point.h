#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <debug.h>
#include <stdint.h>
#include <stdlib.h>

/* 基本型別與小數位數 */
typedef int fp;
#define Q_FP 14

/* 整數 ↔ 固定點 互轉 */
#define INT_2_FP(n)       ((int64_t)(n) << Q_FP)
#define FP_2_INT_CUT(x)   ((x) >> Q_FP)
/* 最近取整：先加上 half unit，再右移 Q_FP */
#define FP_2_INT_NEAREST(x) \
  ( ((x) >= 0) \
      ? (((x) + (1LL << (Q_FP - 1))) >> Q_FP) \
      : (((x) - (1LL << (Q_FP - 1))) >> Q_FP) )

/* 固定點加減 */
#define FP_ADD(x, y)      ((x) + (y))
#define FP_SUB(x, y)      ((x) - (y))
/* 固定點 與 整數 加減 */
#define FP_INT_ADD(x, n)  ((x) + ((int64_t)(n) << Q_FP))
#define FP_INT_SUB(x, n)  ((x) - ((int64_t)(n) << Q_FP))

/* 固定點 相乘與相除 */
#define FP_MUL(x, y)      ((int)(((int64_t)(x) * (y)) >> Q_FP))
#define FP_DIV(x, y)      ((int)(((int64_t)(x) << Q_FP) / (y)))

/* 固定點 與 整數 相乘／相除 */
#define FP_INT_MUL(x, n)  ((x) * (n))
#define FP_INT_DIV(x, n)  ((x) / (n))

#endif /* FIXED_POINT_H */
