/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef _RTT_TEMPLATE_ALGO_PARAMS_H_
#define _RTT_TEMPLATE_ALGO_PARAMS_H_

/* Configurable algorithm parameters */
/* This parameters are hardcoded and they provide the best set of the parameters for real firmware */
#define UPDATE_FACTOR (((1 << 16) * 10) / 100) /* 0.08 in fxp16 - maximum multiplicative decrease factor */
#define AI (((1 << 20) * 5) / 100)	       /* 0.05 In fxp20 - additive increase value */
#define BASE_RTT (13000)		       /* Base value of rtt - in nanosec */
#define NEW_FLOW_RATE (1 << (20))	       /* Rate format in fixed point 20 */
#define MIN_RATE (1 << (20 - 14))	       /* Rate format in fixed point 20 */
#define MAX_DELAY (150000)		       /* Maximum delay - in nanosec */

#define UPDATE_FACTOR_MAX (10 * (1 << 16)) /* Maximum value of update factor */
#define AI_MAX (1 << (20))		   /* Maximum value of AI */
#define RATE_MAX (1 << (20))		   /* Maximum value of rate */
#define BW_MB_DEFAULT (25000)		   /* Initial value of bandwidth. Units MB/s */

#endif /* _RTT_TEMPLATE_ALGO_PARAMS_H_ */
