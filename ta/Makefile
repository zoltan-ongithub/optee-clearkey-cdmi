.PHONY: clean clean-ta

CFG_TEE_TA_LOG_LEVEL ?= 1

CPPFLAGS += -Iinclude

BINARY = 82dbae9c-9ce0-47e0-a1cb4048cfdb847d
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk


clean-ta:
	rm -f $(BINARY).ta
