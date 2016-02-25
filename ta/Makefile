.PHONY: all clean clean-ta

CFG_TEE_TA_LOG_LEVEL ?= 1
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -DCFG_TRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

TA_DEV_KIT_DIR ?= ../../optee_os/out/arm32-plat-vexpress/export-user_ta
TA_CROSS_COMPILE ?= arm-linux-gnueabihf-
CROSS_COMPILE ?= $(TA_CROSS_COMPILE)

BINARY = 82dbae9c-9ce0-47e0-a1cb4048cfdb847d
# Do not fail if TA_DEV_KIT_DIR does not exist (make clean)
-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

CPPFLAGS += -Iinclude

all: $(BINARY).ta

$(BINARY).ta: $(BINARY).bin faked_armv7_uta_signed_header.bin
	cat faked_armv7_uta_signed_header.bin $< >$@

clean: clean-ta

clean-ta:
	rm -f $(BINARY).ta
