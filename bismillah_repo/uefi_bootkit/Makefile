# UEFI Bootkit Makefile
# This Makefile compiles the UEFI bootkit payload using EDK2

# Configuration
APP_NAME  := uefi_bootkit
APP_SRCS  := payload_uefi.c
EDK2_DIR  := /opt/edk2
WORKSPACE := $(CURDIR)/edk2-workspace
OUTPUT    := $(CURDIR)/build
ARCH      := X64
PLATFORM  := UefiPayloadPkg/UefiPayloadPkg.dsc
TOOLCHAIN := GCC5

# Default target
all: edk2-setup compile

# Set up EDK2 workspace
edk2-setup:
	@echo "Setting up EDK2 workspace..."
	@mkdir -p $(WORKSPACE)
	@mkdir -p $(OUTPUT)
	@mkdir -p $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)
	@cp $(APP_SRCS) $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/

	@# Create package DSC file
	@echo "[Defines]" > $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  PLATFORM_NAME                  = $(APP_NAME)Pkg" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  PLATFORM_GUID                  = 8f0e5b89-54aa-4319-8fe8-13ec436dd7cf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  PLATFORM_VERSION               = 1.0" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  DSC_SPECIFICATION              = 0x00010005" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  OUTPUT_DIRECTORY               = $(OUTPUT)" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  SUPPORTED_ARCHITECTURES        = $(ARCH)" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  SKUID_IDENTIFIER               = DEFAULT" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "[LibraryClasses]" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  DebugLib|MdePkg/Library/UefiDebugLibStdErr/UefiDebugLibStdErr.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "[Components]" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc
	@echo "  $(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_SRCS)" >> $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc

	@# Create INF file
	@echo "[Defines]" > $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  INF_VERSION                    = 0x00010005" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  BASE_NAME                      = $(APP_NAME)" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  FILE_GUID                      = 8f0e5b89-54aa-4319-8fe8-13ec436dd7ce" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  MODULE_TYPE                    = UEFI_APPLICATION" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  VERSION_STRING                 = 1.0" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  ENTRY_POINT                    = UefiMain" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "[Sources]" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  $(APP_SRCS)" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "[Packages]" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  MdePkg/MdePkg.dec" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "[LibraryClasses]" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  UefiApplicationEntryPoint" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  UefiLib" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  UefiBootServicesTableLib" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf
	@echo "  UefiRuntimeServicesTableLib" >> $(WORKSPACE)/$(APP_NAME)Pkg/Application/$(APP_NAME)/$(APP_NAME).inf

	@echo "EDK2 workspace setup complete"

# Compile the bootkit
compile:
	@echo "Compiling UEFI bootkit..."
	@if [ -d "$(EDK2_DIR)" ]; then \
		cd $(EDK2_DIR) && \
		source edksetup.sh && \
		build -p $(WORKSPACE)/$(APP_NAME)Pkg/$(APP_NAME)Pkg.dsc -a $(ARCH) -b RELEASE -t $(TOOLCHAIN); \
	else \
		echo "Error: EDK2 directory not found at $(EDK2_DIR)"; \
		echo "Please install EDK2 or modify EDK2_DIR in Makefile"; \
		exit 1; \
	fi
	@echo "Compilation complete"

# Copy the EFI binary to output directory
install: compile
	@echo "Installing bootkit..."
	@mkdir -p $(OUTPUT)/efi/boot
	@cp $(OUTPUT)/$(ARCH)/$(APP_NAME).efi $(OUTPUT)/efi/boot/boot$(ARCH).efi
	@echo "Bootkit installed to $(OUTPUT)/efi/boot/boot$(ARCH).efi"

# Clean build files
clean:
	@echo "Cleaning build files..."
	@rm -rf $(WORKSPACE)
	@rm -rf $(OUTPUT)
	@echo "Clean complete"

# Print help
help:
	@echo "UEFI Bootkit Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Set up EDK2 workspace and compile (default)"
	@echo "  edk2-setup - Set up EDK2 workspace"
	@echo "  compile    - Compile the bootkit"
	@echo "  install    - Copy EFI binary to output directory"
	@echo "  clean      - Clean build files"
	@echo "  help       - Print this help message"
	@echo ""
	@echo "Configuration:"
	@echo "  EDK2_DIR   - Path to EDK2 installation (default: /opt/edk2)"
	@echo "  WORKSPACE  - Path to EDK2 workspace (default: ./edk2-workspace)"
	@echo "  OUTPUT     - Path to output directory (default: ./build)"
	@echo "  ARCH       - Target architecture (default: X64)"
	@echo "  TOOLCHAIN  - Toolchain to use (default: GCC5)"

.PHONY: all edk2-setup compile install clean help
