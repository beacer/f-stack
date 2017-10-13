ifeq (${FF_PATH},)
$(error "FF_PATH is not defined")
endif

ifeq (${FF_DPDK},)
$(error "FF_DPDK is not defined")
endif

CFLAGS += -I ${FF_PATH}/tools/compat
CFLAGS += -I ${FF_PATH}/lib

CFLAGS += -I ${FF_DPDK}/include
CFLAGS += -include ${FF_DPDK}/include/rte_config.h

CFLAGS += -march=native \
		  -DRTE_MACHINE_CPUFLAG_SSE \
		  -DRTE_MACHINE_CPUFLAG_SSE2 \
		  -DRTE_MACHINE_CPUFLAG_SSE3 \
		  -DRTE_MACHINE_CPUFLAG_SSSE3 \
		  -DRTE_MACHINE_CPUFLAG_SSE4_1 \
		  -DRTE_MACHINE_CPUFLAG_SSE4_2 \
		  -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2
