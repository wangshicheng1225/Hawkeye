#!/bin/bash

#
# Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

set -e

# This script uses the dpacc tool (located in /opt/mellanox/doca/tools/dpacc) to compile DPA kernels device code (for DPA samples).
# This script takes the following arguments:
# arg1: Absolute paths of PCC device source code directory (our code)
# arg2: The project's build path (for the PCC Device build)
# arg3: DOCA Libraries directories path
# arg4: Name of compiled DPA program
# arg5: Flag to indicate enabling TX counter sampling
# arg6: Flag to indicate enabling updating CC rate from notification point RX bytes

####################
## Configurations ##
####################

PCC_APP_DEVICE_SRC_DIR=$1
APPLICATION_DEVICE_BUILD_DIR=$2
DOCA_LIB_DIR=$3
PCC_APP_NAME=$4
ENABLE_TX_COUNTER_SAMPLING=$5
ENABLE_NP_RX_RATE=$6

# Tools location - DPACC, DPA compiler
DOCA_INSTALL_DIR="/opt/mellanox/doca"
DOCA_TOOLS="${DOCA_INSTALL_DIR}/tools"
DPACC="${DOCA_TOOLS}/dpacc"

# DOCA include list
DOCA_APP_DEVICE_COMMON_DIR="${DOCA_INSTALL_DIR}/applications/common/device/"
DOCA_INC_LIST="-I${DOCA_INSTALL_DIR}/include/ -I${DOCA_APP_DEVICE_COMMON_DIR}"

# Set source file
if [ ${PCC_APP_NAME} = "pcc_rp_app" ]
then
	DOCA_PCC_DEV_LIB_NAME="doca_pcc_dev"
	PCC_APP_DEVICE_SRCS=`ls ${PCC_APP_DEVICE_SRC_DIR}/rp/*.c`
	PCC_DEVICE_ALGO_SRCS=`ls ${PCC_APP_DEVICE_SRC_DIR}/rp/algo/*.c`
	PCC_DEVICE_SRC_FILES="${PCC_APP_DEVICE_SRCS} ${PCC_DEVICE_ALGO_SRCS}"
	APP_INC_LIST="${DOCA_INC_LIST} -I${DOCA_PCC_DIR}/device/include/rp -I${DOCA_PCC_DIR}/device/adb_gen/"
elif [ ${PCC_APP_NAME} = "pcc_np_nic_telemetry_app" ]
then
	DOCA_PCC_DEV_LIB_NAME="doca_pcc_np_dev"
        PCC_APP_DEVICE_SRCS=`ls ${PCC_APP_DEVICE_SRC_DIR}/np_nic_telemetry/*.c`
        PCC_DEVICE_SRC_FILES="${PCC_APP_DEVICE_SRCS}"
        APP_INC_LIST="${DOCA_INC_LIST} -I${DOCA_PCC_DIR}/device/include/np"
fi

# DPA Configurations
HOST_CC_FLAGS="-Wno-deprecated-declarations -Werror -Wall -Wextra"
DEV_CC_EXTRA_FLAGS="-DSIMX_BUILD,-ffreestanding,-mcmodel=medany,-ggdb,-O2,-DE_MODE_LE,-Wdouble-promotion"
DEVICE_CC_FLAGS="-Wno-deprecated-declarations -Werror -Wall -Wextra ${DEV_CC_EXTRA_FLAGS} "

# App flags

DOCA_PCC_SAMPLE_TX_BYTES=""
if [ ${ENABLE_TX_COUNTER_SAMPLING} = "true" ]
then
	DOCA_PCC_SAMPLE_TX_BYTES="-DDOCA_PCC_SAMPLE_TX_BYTES"
fi

DOCA_PCC_NP_RX_RATE=""
if [ ${ENABLE_NP_RX_RATE} = "true" ]
then
	DOCA_PCC_NP_RX_RATE="-DDOCA_PCC_NP_RX_RATE"
fi

APP_FLAGS="${DOCA_PCC_SAMPLE_TX_BYTES}, ${DOCA_PCC_NP_RX_RATE}"

##################
## Script Start ##
##################

mkdir -p $APPLICATION_DEVICE_BUILD_DIR

# Compile the DPA (kernel) device source code using the DPACC
$DPACC \
-flto \
$PCC_DEVICE_SRC_FILES \
-o ${APPLICATION_DEVICE_BUILD_DIR}/${PCC_APP_NAME}.a \
-hostcc=gcc \
-hostcc-options="${HOST_CC_FLAGS}" \
--devicecc-options="${DEVICE_CC_FLAGS}, ${APP_FLAGS}, ${APP_INC_LIST}" \
-disable-asm-checks \
-device-libs="-L${DOCA_LIB_DIR} -l${DOCA_PCC_DEV_LIB_NAME}" \
--app-name="${PCC_APP_NAME}"
