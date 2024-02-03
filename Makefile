SIGN   = codesign
CC     = clang
CFLAGS = -mtune=native -O2 -Wall
FFLAGS = -framework Foundation -framework Virtualization

BUILD_DIR = objs
BIN = vmctl

SRCS = main.m compat/reallocarray.m compat/fmt_scaled.m vm.m vmd.m config.m

OBJ = $(SRCS:%.m=$(BUILD_DIR)/%.o)
DEP = $(OBJ:%.o=%.d)

all: $(BIN) tap

$(BIN): $(BUILD_DIR)/$(BIN)
	[ -L $(BIN) ] || ln -s $^ $(BIN)

$(BUILD_DIR)/$(BIN) : $(OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(FFLAGS) $^ -o $@
	$(SIGN) --entitlements hypervisor.entitlements --force -s - $@

TAP_LDFLAGS=-framework vmnet  -framework CoreFoundation

tap: $(BUILD_DIR)/tap
	[ -L tap ] || ln -s $^ tap

$(BUILD_DIR)/tap : $(BUILD_DIR)/tap.o
	@mkdir -p $(@D)
	$(CC) $(TAP_LDFLAGS) $^ -o $@

-include $(DEP)

$(BUILD_DIR)/%.o : %.m
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -c $< -o $@

.PHONY : clean
clean :
	-rm -fr $(BUILD_DIR)/*