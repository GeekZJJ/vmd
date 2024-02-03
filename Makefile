# Makefile for vmctl

SIGN   = codesign
CC     = clang
CFLAGS = -mtune=native -O2 -Wall
FFLAGS = -framework Foundation -framework Virtualization -framework vmnet

BUILD_DIR = objs
BIN = vmctl

SRCS = main.m compat/reallocarray.m compat/fmt_scaled.m vm.m vmd.m config.m vmnet.m

OBJ = $(SRCS:%.m=$(BUILD_DIR)/%.o)
DEP = $(OBJ:%.o=%.d)

all: $(BIN)

$(BIN) : $(OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(FFLAGS) $^ -o $@
	$(SIGN) --entitlements hypervisor.entitlements --force -s - $@

-include $(DEP)

$(BUILD_DIR)/%.o : %.m
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -c $< -o $@

.PHONY : clean release
clean :
	-rm -fr $(BUILD_DIR)/*
